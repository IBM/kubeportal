package agent

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"k8s.io/client-go/rest"
)

const (
	tokenRefreshInterval  = 30 * time.Second
	proxyIdleConnsPerHost = 50
	proxyIdleConnTimeout  = 50 * time.Second
)

type K8sProxy struct {
	k8sURL   *url.URL
	caPool   *x509.CertPool
	token    atomic.Value
	connChan chan net.Conn
}

func NewK8sProxy(k8sURL *url.URL, caPool *x509.CertPool, k8sConfig *rest.Config) *K8sProxy {
	kp := &K8sProxy{
		k8sURL:   k8sURL,
		caPool:   caPool,
		connChan: make(chan net.Conn),
	}
	kp.token.Store(k8sConfig.BearerToken) // store initial token, will be refreshed later
	return kp
}
func (kp *K8sProxy) Start() {
	go kp.watchToken() // start watching token updates
	go kp.serve()      // proxy requests to k8s api server
}
func (kp *K8sProxy) ProxyConn(c net.Conn)      { kp.connChan <- c }
func (kp *K8sProxy) Accept() (net.Conn, error) { return <-kp.connChan, nil }
func (kp *K8sProxy) Close() error              { return nil }
func (kp *K8sProxy) Addr() net.Addr            { return &net.TCPAddr{} }
func (kp *K8sProxy) serve() {
	err := http.Serve(kp, &httputil.ReverseProxy{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: kp.caPool,
			},
			MaxIdleConnsPerHost: proxyIdleConnsPerHost,
			IdleConnTimeout:     proxyIdleConnTimeout,
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(kp.k8sURL)
			pr.Out.Header.Set("Authorization", "Bearer "+kp.token.Load().(string))
		},
	})
	if err != nil {
		panic(err)
	}
}
func (kp *K8sProxy) watchToken() {
	ticker := time.NewTicker(tokenRefreshInterval)
	defer ticker.Stop()
	for range ticker.C {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			slog.With("module", "k8sProxy", "error", err).Error("Failed to refresh k8s token")
			continue
		}
		kp.token.Store(cfg.BearerToken)
	}
}
