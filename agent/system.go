package agent

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"kubeportal/shared"
	"log/slog"
	"maps"
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

type closeWriter interface{ CloseWrite() error }

func netCopy(dst, src net.Conn, errChan chan error) {
	_, err := io.Copy(dst, src)
	dst.(closeWriter).CloseWrite()
	errChan <- err
}

type flushWriter struct {
	http.ResponseWriter
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.ResponseWriter.Write(p)
	fw.ResponseWriter.(http.Flusher).Flush()
	return
}

func connStateLogger(c net.Conn, connState http.ConnState) {
	slog.Debug("conn state changed", "module", "agent-conn-tracker", "state", connState.String(), "conn_id", c.(tracedConn).ID)
}

// request logging and metrics
var (
	reqLabels        = []string{"virtual_user", "method", "request_type", "status_code"}
	reqCounterMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "agent",
			Name:      "http_requests_total",
			Help:      "HTTP requests",
		},
		reqLabels,
	)
	reqHeadersLatencyMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "agent",
			Name:      "http_request_headers_duration_seconds",
			Help:      "HTTP request duration",
			Buckets:   prometheus.DefBuckets,
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
	reqInFlightMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "agent",
			Name:      "http_requests_in_flight",
			Help:      "HTTP requests in flight",
		},
		[]string{"virtual_user", "method", "request_type"},
	)
)

func init() {
	prometheus.MustRegister(reqCounterMetric, reqHeadersLatencyMetric, reqLatencyMetric, reqInFlightMetric)
}

func VirtualUserFromRequest(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Impersonate-User"), shared.VirtualUserPrefix)
}

func LogRequest(requestFinished bool, r *http.Request, level slog.Level, statusCode int, err error) {
	ctx := r.Context()
	duration := time.Since(shared.StartTimeFromCtx(ctx))
	strStatusCode := strconv.Itoa(statusCode)
	virtualUser := VirtualUserFromRequest(r)
	msg := "Processed "
	if requestFinished {
		msg += "body"
	} else {
		msg += "headers"
	}
	reqType := shared.RequestTypeFromCtx(ctx).String()
	slog.Log(ctx, level, msg,
		"module", "agent-request-logger",
		"virtual_user", virtualUser,
		"conn_id", ctx.Value(ctxKeyConnID),
		"method", r.Method,
		"path", r.URL.Path,
		"request_id", r.Header.Get(shared.RequestIDHeaderName),
		"request_type", reqType,
		"status_code", strStatusCode,
		"duration", duration.Milliseconds(),
		"error", err,
	)
	if requestFinished {
		reqLatencyMetric.WithLabelValues(virtualUser, r.Method, reqType, strStatusCode).Observe(duration.Seconds())
	} else {
		reqCounterMetric.WithLabelValues(virtualUser, r.Method, reqType, strStatusCode).Inc()
		reqHeadersLatencyMetric.WithLabelValues(virtualUser, r.Method, reqType, strStatusCode).Observe(duration.Seconds())
	}
}

type h2Conn struct {
	io.ReadCloser
	io.Writer
}

func (h2Conn) LocalAddr() net.Addr                { return nil }
func (h2Conn) RemoteAddr() net.Addr               { return nil }
func (h2Conn) SetDeadline(t time.Time) error      { return nil }
func (h2Conn) SetReadDeadline(t time.Time) error  { return nil }
func (h2Conn) SetWriteDeadline(t time.Time) error { return nil }

type h2Hijacker struct {
	http.ResponseWriter
	r *http.Request
}

func (h h2Hijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return &h2Conn{h.r.Body, &flushWriter{h.ResponseWriter}}, bufio.NewReadWriter(nil, bufio.NewWriter(&respInterceptor{
		Buffer: &bytes.Buffer{},
		rw:     h.ResponseWriter,
	})), nil
}

type respInterceptor struct {
	*bytes.Buffer
	rw http.ResponseWriter
}

// this is needed because currently the reverseproxy manually writes the response in http1.1 format
// we capture that here and write it natively
func (ri *respInterceptor) Write(p []byte) (int, error) {
	n, err := ri.Buffer.Write(p)
	b := ri.Buffer.Bytes()
	if len(b) >= 4 && bytes.Equal(b[len(b)-4:], []byte("\r\n\r\n")) {
		resp, err := http.ReadResponse(bufio.NewReader(ri.Buffer), nil)
		if err != nil {
			return n, err
		}
		maps.Copy(ri.rw.Header(), resp.Header)
		ri.rw.Header().Set(shared.StatusCodeHeaderName, strconv.Itoa(resp.StatusCode))
		ri.rw.WriteHeader(http.StatusOK)
		ri.rw.(http.Flusher).Flush()
		ri.Buffer = nil
	}
	return n, err
}
