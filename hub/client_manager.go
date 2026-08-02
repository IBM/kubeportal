package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"kubeportal/shared"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/maypok86/otter/v2"
	"golang.org/x/net/http2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	_ http.Handler = (*ClientHandler)(nil)
)

type ClientManager struct {
	s  *http.Server
	tr *http2.Transport
	wg *sync.WaitGroup
}

func NewClientManager(ctx context.Context) (*ClientManager, *http2.Transport, error) {
	tr := &http2.Transport{
		AllowHTTP:                  true,
		StrictMaxConcurrentStreams: false,
		ReadIdleTimeout:            10 * time.Second,
		PingTimeout:                2 * time.Second,
		IdleConnTimeout:            1 * time.Hour,
		CountError: func(errType string) {
			shared.LogHTTP2Error("hub-client", errType)
		},
	}
	rp := &httputil.ReverseProxy{
		Transport: &shared.LoggingTripper{
			RoundTripper: &upgradeTransport{tr},
			LogHeaders:   LogRequest,
		},
		Rewrite:      func(pr *httputil.ProxyRequest) {}, // done in ServeHTTP
		ErrorHandler: shared.ProcessProxyError,
		ErrorLog:     slog.NewLogLogger(slog.Default().With("module", "hub-proxy").Handler(), slog.LevelError),
	}
	wg := &sync.WaitGroup{}
	ch, err := newClientHandler(ctx, rp, wg)
	if err != nil {
		return nil, nil, err
	}
	tlsCert, err := generateTLSCert()
	if err != nil {
		return nil, nil, err
	}
	clientSrv := &http.Server{
		Handler:     ch,
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 90 * time.Second,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	}
	if err := http2.ConfigureServer(clientSrv, &http2.Server{
		CountError: func(errType string) {
			shared.LogHTTP2Error("hub-server", errType)
		},
	}); err != nil {
		return nil, nil, err
	}
	return &ClientManager{
		s:  clientSrv,
		tr: tr,
		wg: wg,
	}, tr, nil
}

func (cm *ClientManager) SetConnPool(cp http2.ClientConnPool) {
	cm.tr.ConnPool = cp
}

func (cm *ClientManager) Run(ln net.Listener, listenerCrt, listenerKey string) {
	if err := cm.s.ServeTLS(ln, listenerCrt, listenerKey); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}

func (cm *ClientManager) Shutdown() {
	cm.s.Shutdown(context.Background())
	cm.wg.Wait()
}

type ClientHandler struct {
	rp            *httputil.ReverseProxy
	ctx           context.Context
	log           *slog.Logger
	tokenParser   *jwt.Parser
	k8sAuthClient kubernetes.Interface
	wg            *sync.WaitGroup
	rbacCache     *otter.Cache[rbacCacheKey, byte]
	cacheLoader   CacheLoader
}

func newClientHandler(ctx context.Context, rp *httputil.ReverseProxy, wg *sync.WaitGroup) (*ClientHandler, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	config = rest.AnonymousClientConfig(config)
	config.Wrap(BearerTokenInjector)
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &ClientHandler{
		rp:          rp,
		ctx:         ctx,
		log:         slog.With("module", "hub-client-handler"),
		tokenParser: jwt.NewParser(jwt.WithoutClaimsValidation()),
		wg:          wg,
		rbacCache: otter.Must(&otter.Options[rbacCacheKey, byte]{
			MaximumSize:       100_000,
			InitialCapacity:   1_000,
			RefreshCalculator: otter.RefreshWriting[rbacCacheKey, byte](1 * time.Minute),
			ExpiryCalculator:  otter.ExpiryWriting[rbacCacheKey, byte](2 * time.Minute),
			Logger:            CacheLogger{slog.With("module", "hub-rbac-allowed-cache")},
		}),
		cacheLoader: CacheLoader{
			K8sAuthClient: k8sClient,
			DeniedCache: otter.Must(&otter.Options[rbacCacheKey, byte]{
				MaximumSize:      1_000,
				InitialCapacity:  100,
				ExpiryCalculator: otter.ExpiryWriting[rbacCacheKey, byte](1 * time.Minute),
				Logger:           CacheLogger{slog.With("module", "hub-rbac-denied-cache")},
			})},
	}, nil
}

func (ch *ClientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// validate the request
	path := r.URL.Path
	if len(path) == 0 || path[0] != '/' {
		ch.respondError(w, r, http.StatusBadRequest, "invalid path, missing leading slash")
		return
	}
	pathParts := strings.SplitN(path, "/", 4)
	if len(pathParts) != 4 {
		ch.respondError(w, r, http.StatusBadRequest, "invalid path, expected /<kube-id>/<virtual-user>/<api-path>")
		return
	}
	kubeIdentifier, virtualUser, requestedPath := pathParts[1], pathParts[2], pathParts[3]
	requestedPath = "/" + requestedPath

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ch.respondError(w, r, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	tokClaims, allowed, err := ch.checkAuth(r.Context(), authHeader[7:], kubeIdentifier, virtualUser)
	if err != nil {
		ch.respondError(w, r, http.StatusInternalServerError, fmt.Sprintf("authorization check failed: %v", err))
		return
	}
	if !allowed {
		ch.respondError(w, r, http.StatusForbidden, "insufficient permissions for virtual user")
		return
	}

	// set up the request for forwarding to agent
	reqType := shared.DetermineRequestType(r)
	r.Header.Set(shared.RequestIDHeaderName, uuid.NewString())
	rCtx := shared.CtxWithStartTime(r.Context())
	rCtx = shared.CtxWithRequestType(rCtx, reqType)
	rCtx = shared.CtxWithResponseLogItems(rCtx)
	rCtx = context.WithValue(rCtx, ctxKeyRequestProps, &RequestProps{
		KubeIdentifier: kubeIdentifier,
		VirtualUser:    virtualUser,
		ApiPath:        requestedPath,
		ClientNS:       tokClaims.K8s.Namespace,
		ClientPod:      tokClaims.K8s.Pod.Name,
		ClientSA:       tokClaims.K8s.ServiceAccount.Name,
	})
	if reqType.IsLongPoll() { // don't wait for watches when terminating
		var cancel context.CancelFunc
		rCtx, cancel = context.WithCancel(rCtx)
		defer cancel()
		stop := context.AfterFunc(ch.ctx, cancel)
		defer stop()
		defer shared.CatchAbortOnShutdown(ch.ctx)
	}
	if reqType.IsUpgrade() {
		ch.wg.Add(1)
		defer ch.wg.Done()
		var cancel context.CancelFunc
		rCtx, cancel = context.WithCancel(rCtx)
		defer cancel()
		stop := context.AfterFunc(ch.ctx, func() {
			time.Sleep(time.Until(shared.StartTimeFromCtx(rCtx).Add(10 * time.Second)))
			cancel()
		})
		defer stop()
	}
	r = r.WithContext(rCtx)
	r.URL.Scheme = "http"
	r.URL.Host = kubeIdentifier
	r.URL.Path = requestedPath
	r.Header.Del("Authorization")
	for k := range r.Header {
		if strings.HasPrefix(k, "X-Remote") || strings.HasPrefix(k, "Impersonate") {
			delete(r.Header, k)
		}
	}
	r.Header.Set("Impersonate-User", shared.VirtualUserPrefix+virtualUser)

	reqInFlightMetric.WithLabelValues(kubeIdentifier, virtualUser, tokClaims.K8s.Namespace, tokClaims.K8s.ServiceAccount.Name, r.Method, reqType.String()).Inc()
	defer reqInFlightMetric.WithLabelValues(kubeIdentifier, virtualUser, tokClaims.K8s.Namespace, tokClaims.K8s.ServiceAccount.Name, r.Method, reqType.String()).Dec()
	defer DecrementReqCnt(r)
	defer shared.LogRequestFinished(r, LogRequest)
	ch.rp.ServeHTTP(w, r)
}

func (ch *ClientHandler) checkAuth(ctx context.Context, bearerToken, kubeIdentifier, virtualUser string) (ServiceAccountClaims, bool, error) {
	var claims ServiceAccountClaims
	if _, _, err := ch.tokenParser.ParseUnverified(bearerToken, &claims); err != nil {
		return claims, false, fmt.Errorf("failed to parse bearer token: %w", err)
	}
	_, err := ch.rbacCache.Get(ctx, rbacCacheKey{
		Namespace:   claims.K8s.Namespace,
		BearerToken: bearerToken,
		VirtualUser: virtualUser,
	}, ch.cacheLoader)
	result := "allowed"
	if err != nil {
		if err == otter.ErrNotFound {
			result = "denied"
		} else {
			result = "error"
		}
	}
	clientAuthMetric.WithLabelValues(claims.K8s.Namespace, claims.K8s.ServiceAccount.Name, virtualUser, result).Inc()
	if err != nil && err != otter.ErrNotFound {
		return claims, false, err
	}
	allowed := err == nil
	ch.log.With(
		"kube_identifier", kubeIdentifier, "virtual_user", virtualUser, "allowed", allowed,
		"client_ns", claims.K8s.Namespace, "client_pod", claims.K8s.Pod.Name, "client_sa", claims.K8s.ServiceAccount.Name,
	).Debug("Authorization check completed")
	return claims, allowed, nil
}

func (ch *ClientHandler) respondError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	http.Error(w, msg, code)
	ch.log.With(
		"client_ip", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.RequestURI(),
	).Warn(fmt.Sprintf("Request error: %d %s", code, msg))
}
