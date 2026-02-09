package agent

import (
	"context"
	"crypto/tls"
	"kubeportal/shared"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	tr1 := http.DefaultTransport.(*http.Transport).Clone()
	tr1.TLSClientConfig = tlsConfig
	tr2, err := http2.ConfigureTransports(tr1)
	if err != nil {
		return nil, err
	}
	tr2.StrictMaxConcurrentStreams = false
	tr2.CountError = func(errType string) {
		shared.LogHTTP2Error("agent-client", errType)
	}
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
			RoundTripper: tr1,
			LogHeaders:   LogRequest,
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
	rCtx = shared.CtxWithResponseLogItems(rCtx)
	if shared.IsLongPollRequest(r) { // don't wait for watches when terminating
		var cancel context.CancelFunc
		rCtx, cancel = context.WithCancel(rCtx)
		defer cancel()
		stop := context.AfterFunc(kp.ctx, cancel)
		defer stop()
		defer shared.CatchAbortOnShutdown(kp.ctx)
	}
	r = r.WithContext(rCtx)
	r.Header.Set("Authorization", "Bearer "+kp.token.Load())
	r.URL.Scheme = "https"
	r.URL.Host = kp.k8sHost
	r.Host = ""
	if shared.IsUpgradeRequest(r) {
		upgCtx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(kp.ctx, func() {
			time.Sleep(time.Until(shared.StartTimeFromCtx(upgCtx).Add(10 * time.Second)))
			cancel()
		})
		defer stop()
		r = (&http.Request{ // don't use Clone, need an upgrade-friendly request
			Method: r.Method,
			URL:    r.URL,
			Header: r.Header,
			Body:   r.Body,
		}).WithContext(upgCtx)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", r.Header.Get("Kubeportal-Upgrade"))
		r.Header.Del("Kubeportal-Upgrade")
		w = &h2Hijacker{w, r}
	}
	defer shared.LogRequestFinished(r, LogRequest)
	kp.rp.ServeHTTP(w, r)
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
