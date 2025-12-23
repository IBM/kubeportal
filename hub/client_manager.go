package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"kubeportal/shared"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	_ http.Handler = (*ClientHandler)(nil)
)

type ClientManager struct {
	s  *http.Server
	tr *http2.Transport
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
			RoundTripper: tr,
			LogRequest:   LogRequest,
		},
		Rewrite:      func(pr *httputil.ProxyRequest) {}, // done in ServeHTTP
		ErrorHandler: shared.ProcessProxyError,
		ErrorLog:     slog.NewLogLogger(slog.Default().With("module", "hub-proxy").Handler(), slog.LevelError),
	}
	ch, err := newClientHandler(ctx, rp)
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
	http2.ConfigureServer(clientSrv, &http2.Server{
		CountError: func(errType string) {
			shared.LogHTTP2Error("hub-server", errType)
		},
	})
	return &ClientManager{
		s:  clientSrv,
		tr: tr,
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
}

type ClientHandler struct {
	rp            *httputil.ReverseProxy
	ctx           context.Context
	log           *slog.Logger
	tokenParser   *jwt.Parser
	k8sAuthClient kubernetes.Interface
}

func newClientHandler(ctx context.Context, rp *httputil.ReverseProxy) (*ClientHandler, error) {
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
		rp:            rp,
		ctx:           ctx,
		log:           slog.With("module", "hub-client-handler"),
		tokenParser:   jwt.NewParser(jwt.WithoutClaimsValidation()),
		k8sAuthClient: k8sClient,
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
	r.Header.Set(shared.RequestIDHeaderName, uuid.NewString())
	rCtx := context.WithValue(shared.CtxWithStartTime(r.Context()), ctxKeyRequestProps, &RequestProps{
		KubeIdentifier: kubeIdentifier,
		VirtualUser:    virtualUser,
		ApiPath:        requestedPath,
		ClientNS:       tokClaims.K8s.Namespace,
		ClientPod:      tokClaims.K8s.Pod.Name,
		ClientSA:       tokClaims.K8s.ServiceAccount.Name,
	})
	if shared.IsLongPollRequest(r) { // don't wait for watches when terminating
		var cancel context.CancelFunc
		rCtx, cancel = shared.CtxWithExistingCancel(rCtx, ch.ctx)
		defer cancel()
		defer shared.NoAbortOnShutdown(ch.ctx)
	}
	r = r.WithContext(rCtx)
	r.URL.Scheme = "http"
	r.URL.Host = kubeIdentifier
	r.URL.Path = requestedPath
	r.Header.Set("Impersonate-User", shared.VirtualUserPrefix+virtualUser)
	r.Header.Del("Authorization")

	defer DecrementReqCnt(r)
	if shared.IsUpgradeRequest(r) {
		ch.serveUpgrade(w, r)
		return
	}
	ch.rp.ServeHTTP(w, r)
}

func (ch *ClientHandler) checkAuth(ctx context.Context, bearerToken, kubeIdentifier, virtualUser string) (ServiceAccountClaims, bool, error) {
	var claims ServiceAccountClaims
	if _, _, err := ch.tokenParser.ParseUnverified(bearerToken, &claims); err != nil {
		return claims, false, fmt.Errorf("failed to parse bearer token: %w", err)
	}

	ctx = ContextWithBearerToken(ctx, bearerToken)

	result, err := ch.k8sAuthClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: claims.K8s.Namespace,
				Verb:      "use",
				Group:     "kubeportal.ibm.com",
				Version:   "v1",
				Resource:  "virtualUsers",
				Name:      virtualUser,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return claims, false, fmt.Errorf("failed to perform SubjectAccessReview: %w", err)
	}

	ch.log.With(
		"kube_identifier", kubeIdentifier, "virtual_user", virtualUser,
		"client_ns", claims.K8s.Namespace, "client_pod", claims.K8s.Pod.Name, "client_sa", claims.K8s.ServiceAccount.Name,
		"allowed", result.Status.Allowed, "denied", result.Status.Denied, "reason", result.Status.Reason,
	).Debug("Authorization check completed")

	return claims, result.Status.Allowed, nil
}

func (ch *ClientHandler) respondError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	http.Error(w, msg, code)
	ch.log.With(
		"client_ip", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.Path,
	).Warn(fmt.Sprintf("Request error: %d %s", code, msg))
}

func (ch *ClientHandler) serveUpgrade(w http.ResponseWriter, r *http.Request) {
	// modify and forward the request
	proto := r.Header.Get("Upgrade")
	r.Header.Set("Kubeportal-Upgrade", proto)
	r.Header.Del("Upgrade")
	r.Header.Del("Connection")
	pr, pw := io.Pipe()
	defer pw.Close()
	r.Body = pr
	resp, err := ch.rp.Transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		LogRequest(r, slog.LevelError, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()

	// proxy resp back to client
	headers := w.Header()
	maps.Copy(headers, resp.Header)
	if resp.StatusCode != http.StatusOK {
		errStr := fmt.Sprintf("unexpected status code from agent: %d", resp.StatusCode)
		ch.log.Error(errStr)
		http.Error(w, errStr, http.StatusBadGateway)
		return
	}
	statusCode, err := strconv.Atoi(headers.Get(shared.StatusCodeHeaderName))
	if err != nil {
		ch.log.Error("Failed to parse response status code from agent", "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	headers.Del(shared.StatusCodeHeaderName)
	if statusCode != http.StatusSwitchingProtocols {
		w.WriteHeader(statusCode)
		LogRequest(r, slog.LevelError, statusCode, errors.New("unexpected status code from k8s"))
		if _, err := io.Copy(w, resp.Body); err != nil {
			ch.log.Error("Upgrade copy error", "error", err)
		}
		return
	}
	headers.Add("Connection", "Upgrade")
	w.WriteHeader(statusCode)
	LogRequest(r, slog.LevelInfo, statusCode, nil)

	// Hijack the request conn
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		ch.log.Error("Failed to flush response", "error", err)
		return
	}
	reqConn, _, err := rc.Hijack()
	if err != nil {
		ch.log.Error("Failed to hijack connection", "error", err)
		return
	}
	defer reqConn.Close()

	// bidirectional data copy
	err = shared.BidirectionalCopy(r.Context(), ch.ctx, reqConn, shared.ReadWriteCloser{
		ReadCloser: resp.Body,
		Writer:     pw,
	})
	shared.LogUpgradeRequest("hub", r, err)
}
