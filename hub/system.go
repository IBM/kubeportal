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
	"io"
	"kubeportal/shared"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
)

type ctxKey int

const (
	ctxKeyBearerToken ctxKey = iota
	ctxKeyRequestProps
)

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
	reqLabels        = []string{"kube_identifier", "virtual_user", "client_ns", "client_sa", "method", "status_code"}
	reqCounterMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "hub",
			Name:      "http_requests_total",
			Help:      "HTTP requests",
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
)

func init() {
	prometheus.MustRegister(reqCounterMetric, reqLatencyMetric)
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

func LogRequest(r *http.Request, level slog.Level, statusCode int, err error) {
	ctx := r.Context()
	rp := RequestPropsFromContext(ctx)
	connID, agentID := "", ""
	if rp.ConnInfo != nil {
		connID = rp.ConnInfo.ConnID
		agentID = rp.ConnInfo.AgentID
	}
	duration := time.Since(shared.StartTimeFromCtx(ctx))
	strStatusCode := strconv.Itoa(statusCode)
	slog.Log(ctx, level, "Request proxied",
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
		"path", r.URL.Path,
		"request_id", r.Header.Get(shared.RequestIDHeaderName),
		"status_code", strStatusCode,
		"duration", duration.Milliseconds(),
		"error", err,
	)
	reqCounterMetric.WithLabelValues(rp.KubeIdentifier, rp.VirtualUser, rp.ClientNS, rp.ClientSA, r.Method, strStatusCode).Inc()
	reqLatencyMetric.WithLabelValues(rp.KubeIdentifier, rp.VirtualUser, rp.ClientNS, rp.ClientSA, r.Method, strStatusCode).Observe(duration.Seconds())
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
