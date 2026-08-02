package hub

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"kubeportal/shared"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/julien040/go-ternary"
	"github.com/maypok86/otter/v2"
	"github.com/prometheus/client_golang/prometheus"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ctxKey int

const (
	ctxKeyBearerToken ctxKey = iota
	ctxKeyRequestProps
)

type rbacCacheKey struct {
	Namespace   string
	BearerToken string
	VirtualUser string
}

type openidResponse struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

type ConnInfo struct {
	Kube    *Kube
	AgentID string
	ConnID  string
}

// struct for reading claims from service account tokens
type ServiceAccountClaims struct {
	jwt.RegisteredClaims
	K8s struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func BearerTokenFromContext(ctx context.Context) string {
	return ctx.Value(ctxKeyBearerToken).(string)
}

func ContextWithBearerToken(ctx context.Context, bearerToken string) context.Context {
	return context.WithValue(ctx, ctxKeyBearerToken, bearerToken)
}

type tokenTripper struct {
	http.RoundTripper
}

func (tt *tokenTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+BearerTokenFromContext(req.Context()))
	return tt.RoundTripper.RoundTrip(req)
}

func BearerTokenInjector(rt http.RoundTripper) http.RoundTripper {
	return &tokenTripper{rt}
}

// download jwks via openid
func getOpenidPrivate(conn net.Conn, path, svcActToken string) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = shared.K8sHostname
	req.Header.Set("Authorization", "Bearer "+svcActToken)
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected status: " + resp.Status)
	}
	return body, nil
}

func getOpenidPublic(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected status: " + resp.Status)
	}
	return body, nil
}

// request logging and metrics
var (
	reqLabels        = []string{"kube_identifier", "virtual_user", "client_ns", "client_sa", "method", "request_type", "status_code"}
	reqCounterMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "hub",
			Name:      "http_requests_total",
			Help:      "HTTP requests",
		},
		reqLabels,
	)
	reqHeadersLatencyMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "hub",
			Name:      "http_request_headers_duration_seconds",
			Help:      "HTTP request duration",
			Buckets:   prometheus.DefBuckets,
		},
		reqLabels,
	)
	reqLatencyMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "hub",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration",
			Buckets:   prometheus.DefBuckets,
		},
		reqLabels,
	)
	reqInFlightMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "hub",
			Name:      "http_requests_in_flight",
			Help:      "HTTP requests in flight",
		},
		[]string{"kube_identifier", "virtual_user", "client_ns", "client_sa", "method", "request_type"},
	)
	agentConnsMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "hub",
			Name:      "agent_connections",
			Help:      "Number of connections per kube and agent",
		},
		[]string{"kube_identifier", "agent_id"},
	)
	agentTokenValidationMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "hub",
			Name:      "agent_token_validations",
			Help:      "Agent token validation results",
		},
		[]string{"kube_identifier", "agent_id", "result"},
	)
	clientAuthMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "hub",
			Name:      "client_auth_results",
			Help:      "RBAC authorization checks",
		},
		[]string{"client_ns", "client_sa", "virtual_user", "result"},
	)
)

type KubeMetricCollector struct {
	sync.Mutex
	Kubes map[string]bool
	Desc  *prometheus.Desc
}

var configuredKubesMetric = &KubeMetricCollector{
	Desc: prometheus.NewDesc("hub_configured_kubes", "Configured Kubes", []string{"kube_identifier", "verified"}, nil),
}

func (c *KubeMetricCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.Desc
}

func (c *KubeMetricCollector) Collect(ch chan<- prometheus.Metric) {
	c.Lock()
	defer c.Unlock()
	for kubeID, verified := range c.Kubes {
		ch <- prometheus.MustNewConstMetric(c.Desc, prometheus.GaugeValue, 1, kubeID, ternary.If(verified, "verified", "unverified"))
	}
}

func (c *KubeMetricCollector) Update(kubes map[string]bool) {
	c.Lock()
	defer c.Unlock()
	c.Kubes = kubes
}
func (c *KubeMetricCollector) UpdateOne(kubeID string, verified bool) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.Kubes[kubeID]; ok {
		c.Kubes[kubeID] = verified
	}
}

func init() {
	prometheus.MustRegister(reqCounterMetric, reqHeadersLatencyMetric, reqLatencyMetric, reqInFlightMetric, agentConnsMetric, agentTokenValidationMetric, configuredKubesMetric, clientAuthMetric)
}

type RequestProps struct {
	KubeIdentifier string
	VirtualUser    string
	ApiPath        string
	ClientNS       string
	ClientPod      string
	ClientSA       string
	ConnInfo       *ConnInfo
}

func RequestPropsFromContext(ctx context.Context) *RequestProps {
	return ctx.Value(ctxKeyRequestProps).(*RequestProps)
}

func DecrementReqCnt(r *http.Request) {
	rp := RequestPropsFromContext(r.Context())
	if rp.ConnInfo != nil {
		rp.ConnInfo.Kube.ReqCntDec(rp.ConnInfo.AgentID)
	}
}

func LogRequest(requestFinished bool, r *http.Request, level slog.Level, statusCode int, err error) {
	ctx := r.Context()
	rp := RequestPropsFromContext(ctx)
	connID, agentID := "", ""
	if rp.ConnInfo != nil {
		connID = rp.ConnInfo.ConnID
		agentID = rp.ConnInfo.AgentID
	}
	duration := time.Since(shared.StartTimeFromCtx(ctx))
	strStatusCode := strconv.Itoa(statusCode)
	msg := "Processed "
	if requestFinished {
		msg += "body"
	} else {
		msg += "headers"
	}
	reqType := shared.RequestTypeFromCtx(ctx).String()
	slog.Log(ctx, level, msg,
		"module", "hub-request-logger",
		"kube_identifier", rp.KubeIdentifier,
		"virtual_user", rp.VirtualUser,
		"client_ns", rp.ClientNS,
		"client_pod", rp.ClientPod,
		"client_sa", rp.ClientSA,
		"conn_id", connID,
		"agent_id", agentID,
		"client_ip", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.RequestURI(),
		"request_id", r.Header.Get(shared.RequestIDHeaderName),
		"request_type", reqType,
		"status_code", strStatusCode,
		"duration", duration.Milliseconds(),
		"error", err,
	)
	if requestFinished {
		reqLatencyMetric.WithLabelValues(rp.KubeIdentifier, rp.VirtualUser, rp.ClientNS, rp.ClientSA, r.Method, reqType, strStatusCode).Observe(duration.Seconds())
	} else {
		reqCounterMetric.WithLabelValues(rp.KubeIdentifier, rp.VirtualUser, rp.ClientNS, rp.ClientSA, r.Method, reqType, strStatusCode).Inc()
		reqHeadersLatencyMetric.WithLabelValues(rp.KubeIdentifier, rp.VirtualUser, rp.ClientNS, rp.ClientSA, r.Method, reqType, strStatusCode).Observe(duration.Seconds())
	}
}

func generateTLSCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(5 * 24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

type CacheLogger struct {
	Log *slog.Logger
}

func (l CacheLogger) Warn(_ context.Context, msg string, err error) {
	l.Log.With("error", err).Warn(msg)
}
func (l CacheLogger) Error(_ context.Context, msg string, err error) {
	l.Log.With("error", err).Error(msg)
}

type CacheLoader struct {
	K8sAuthClient kubernetes.Interface
	DeniedCache   *otter.Cache[rbacCacheKey, byte]
}

func (cl CacheLoader) Load(ctx context.Context, k rbacCacheKey) (byte, error) {
	if _, ok := cl.DeniedCache.GetIfPresent(k); ok {
		return 0, otter.ErrNotFound
	}
	return cl.Reload(ctx, k, 0)
}

func (cl CacheLoader) Reload(ctx context.Context, k rbacCacheKey, _ byte) (byte, error) {
	ctx = ContextWithBearerToken(ctx, k.BearerToken) // auto-injected into the Authorization header
	result, err := cl.K8sAuthClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: k.Namespace,
				Verb:      "use",
				Group:     "kubeportal.ibm.com",
				Version:   "v1",
				Resource:  "virtualUsers",
				Name:      k.VirtualUser,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to perform SubjectAccessReview: %w", err)
	}
	if !result.Status.Allowed {
		cl.DeniedCache.Set(k, 0)
		return 0, otter.ErrNotFound
	}
	return 0, nil
}
