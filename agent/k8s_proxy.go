package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"kubeportal/shared"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

const (
	tokenRefreshInterval = 30 * time.Second
)

type K8sProxy struct {
	ctx              context.Context
	ctxCancel        context.CancelFunc
	rp               *httputil.ReverseProxy
	s                *http2.Server
	wg               sync.WaitGroup
	inShutdown       atomic.Bool
	baseServer       *http.Server
	k8sHost          string
	token            shared.AtomicValue[string]
	log              *slog.Logger
	upgradeTransport http.RoundTripper
}

func NewK8sProxy() (*K8sProxy, error) {
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	k8sURL, err := url.Parse(k8sConfig.Host)
	if err != nil {
		return nil, err
	}
	caPool, err := certutil.NewPool(k8sConfig.TLSClientConfig.CAFile)
	if err != nil {
		return nil, err
	}
	baseServer := &http.Server{ConnState: connStateLogger}
	http2Server := &http2.Server{
		MaxConcurrentStreams: shared.MaxConcurrentStreams,
		IdleTimeout:          2 * time.Hour, // hub is 1h so this is just in case
		CountError: func(errType string) {
			shared.LogHTTP2Error("agent-server", errType)
		},
	}
	if err := http2.ConfigureServer(baseServer, http2Server); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{RootCAs: caPool}
	ctx, ctxCancel := context.WithCancel(context.Background())
	kp := &K8sProxy{
		ctx:        ctx,
		ctxCancel:  ctxCancel,
		s:          http2Server,
		baseServer: baseServer,
		k8sHost:    k8sURL.Host,
		log:        slog.With("module", "k8s-proxy"),
		upgradeTransport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	kp.rp = &httputil.ReverseProxy{
		Transport: &shared.LoggingTripper{
			RoundTripper: &http2.Transport{
				TLSClientConfig:            tlsConfig,
				StrictMaxConcurrentStreams: false,
				CountError: func(errType string) {
					shared.LogHTTP2Error("agent-client", errType)
				},
			},
			LogRequest: LogRequest,
		},
		Rewrite:      func(pr *httputil.ProxyRequest) {}, // done in ServeHTTP
		ErrorHandler: shared.ProcessProxyError,
		ErrorLog:     slog.NewLogLogger(slog.With("module", "agent-proxy").Handler(), slog.LevelError),
	}
	kp.token.Store(k8sConfig.BearerToken)
	return kp, nil
}

func (kp *K8sProxy) Run() {
	kp.watchToken() // start watching token updates
}

func (kp *K8sProxy) Shutdown() {
	kp.inShutdown.Store(true)
	kp.log.Info("Shutting down")
	time.Sleep(2 * time.Second)                  // prevent ServeConn races to ensure each conn is registered to receive a GOAWAY
	kp.baseServer.Shutdown(context.Background()) // send GOAWAY to all conns, returns immediately - todo: verify, regular reqs allowed to finish - todo: verify
	kp.ctxCancel()                               // cancel all streaming requests, watches/longpolls immediately, execs will wait individually a bit
	kp.wg.Wait()
}

func (kp *K8sProxy) ServeConn(c net.Conn) {
	if kp.inShutdown.Load() {
		c.Close()
		return
	}
	kp.wg.Add(1)
	defer kp.wg.Done()
	kp.s.ServeConn(c, &http2.ServeConnOpts{
		Context:    context.WithValue(context.Background(), ctxKeyConnID, c.(tracedConn).ID),
		Handler:    kp,
		BaseConfig: kp.baseServer, // conn state changes not shown without this
	})
}

func (kp *K8sProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rCtx := shared.CtxWithStartTime(r.Context())
	if shared.IsLongPollRequest(r) { // don't wait for watches when terminating
		var cancel context.CancelFunc
		rCtx, cancel = shared.CtxWithExistingCancel(rCtx, kp.ctx)
		defer cancel()
		defer shared.NoAbortOnShutdown(kp.ctx)
	}
	r = r.WithContext(rCtx)
	r.Header.Set("Authorization", "Bearer "+kp.token.Load())
	r.URL.Scheme = "https"
	r.URL.Host = kp.k8sHost
	r.Host = ""
	if shared.IsUpgradeRequest(r) {
		kp.serveUpgrade(w, r)
		return
	}
	kp.rp.ServeHTTP(w, r)
}

func (kp *K8sProxy) serveUpgrade(w http.ResponseWriter, r *http.Request) {
	// modify and forward the request
	proto := r.Header.Get("Kubeportal-Upgrade")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", proto)
	r.Header.Del("Kubeportal-Upgrade")
	reqBody := r.Body
	r.Body = http.NoBody
	resp, err := kp.upgradeTransport.RoundTrip(r)
	if err != nil {
		w.Header().Add(shared.StatusCodeHeaderName, strconv.Itoa(http.StatusBadGateway))
		http.Error(w, err.Error(), http.StatusOK)
		kp.log.Error("Failed to roundtrip upgrade request", "error", err)
		LogRequest(r, slog.LevelError, 0, err)
		return
	}
	defer resp.Body.Close()

	// proxy resp back to hub
	maps.Copy(w.Header(), resp.Header)
	w.Header().Add(shared.StatusCodeHeaderName, strconv.Itoa(resp.StatusCode))
	w.WriteHeader(http.StatusOK)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		LogRequest(r, slog.LevelError, resp.StatusCode, errors.New("expected 101 response"))
		if _, err := io.Copy(w, resp.Body); err != nil {
			kp.log.Error("Upgrade copy error", "error", err)
		}
		return
	}
	LogRequest(r, slog.LevelInfo, resp.StatusCode, nil)

	// bidirectional data copy
	err = shared.BidirectionalCopy(r.Context(), kp.ctx, resp.Body.(io.ReadWriteCloser), shared.ReadWriteCloser{
		ReadCloser: reqBody,
		Writer:     &flushWriter{w},
	})
	shared.LogUpgradeRequest("agent", r, err)
}

func (kp *K8sProxy) watchToken() {
	for range time.NewTicker(tokenRefreshInterval).C {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			kp.log.Error("Failed to refresh k8s token", "error", err)
			continue
		}
		kp.token.Store(cfg.BearerToken)
	}
}
