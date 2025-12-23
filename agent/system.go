package agent

import (
	"crypto/tls"
	"errors"
	"io"
	"kubeportal/shared"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type ctxKey int

const (
	ctxKeyConnID ctxKey = iota
)

const currentNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

var (
	tcpDialer = net.Dialer{
		Timeout: 5 * time.Second,
	}
	tlsDialer = tls.Dialer{
		NetDialer: &tcpDialer,
	}
)

type tracedConn struct {
	net.Conn
	ID string
}

func currentNamespace() (string, error) {
	data, err := os.ReadFile(currentNamespacePath)
	if err != nil {
		return "", err
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", errors.New("got empty current namespace?")
	}
	return ns, nil
}

func netCopy(dst, src *net.TCPConn, errChan chan error) {
	_, err := io.Copy(dst, src)
	dst.CloseWrite()
	src.CloseRead()
	errChan <- err
}

type flushWriter struct {
	io.Writer
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.Writer.Write(p)
	fw.Writer.(http.Flusher).Flush()
	return
}

func connStateLogger(c net.Conn, connState http.ConnState) {
	slog.Debug("conn state changed", "module", "agent-conn-tracker", "state", connState.String(), "conn_id", c.(tracedConn).ID)
}

// request logging and metrics
var (
	reqLabels        = []string{"virtual_user", "method", "status_code"}
	reqCounterMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "agent",
			Name:      "http_requests_total",
			Help:      "HTTP requests",
		},
		reqLabels,
	)
	reqLatencyMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "agent",
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

func LogRequest(r *http.Request, level slog.Level, statusCode int, err error) {
	ctx := r.Context()
	duration := time.Since(shared.StartTimeFromCtx(ctx))
	strStatusCode := strconv.Itoa(statusCode)
	virtualUser := strings.TrimPrefix(r.Header.Get("Impersonate-User"), shared.VirtualUserPrefix)
	slog.Log(ctx, level, "Request proxied",
		"module", "agent-request-logger",
		"virtual_user", virtualUser,
		"conn_id", ctx.Value(ctxKeyConnID),
		"method", r.Method,
		"path", r.URL.Path,
		"request_id", r.Header.Get(shared.RequestIDHeaderName),
		"status_code", strStatusCode,
		"duration", duration.Milliseconds(),
		"error", err,
	)
	reqCounterMetric.WithLabelValues(virtualUser, r.Method, strStatusCode).Inc()
	reqLatencyMetric.WithLabelValues(virtualUser, r.Method, strStatusCode).Observe(duration.Seconds())
}
