package shared

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	OpenidReaderSAName   = "kubeportal-openid-reader"
	K8sHostname          = "kubernetes.default.svc.cluster.local"
	VirtualUserPrefix    = "kubeportal:"
	RequestIDHeaderName  = "x-request-id"
	MaxConcurrentStreams = 100
	StatusCodeHeaderName = "Kubeportal-Status-Code"
)

type ctxKey int

const (
	ctxKeyRequestStartTime ctxKey = iota
	ctxKeyResponseLogItems
)

var (
	http2errors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http2_errors_total",
			Help: "HTTP2 errors",
		},
		[]string{"module", "error"},
	)
	upgradeRequestDurationMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_upgrade_request_duration_seconds",
			Help:    "HTTP upgrade request duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"module"},
	)
)

func init() {
	prometheus.MustRegister(http2errors, upgradeRequestDurationMetric)
}

// generic atomic
type AtomicValue[T comparable] struct {
	atomic.Value
}

func (a *AtomicValue[T]) Load() (val T) {
	if v := a.Value.Load(); v != nil {
		return v.(T)
	}
	return val
}

func (a *AtomicValue[T]) Store(s T) {
	a.Value.Store(s)
}

func (a *AtomicValue[T]) Swap(new T) (val T) {
	if old := a.Value.Swap(new); old != nil {
		return old.(T)
	}
	return val
}

func (a *AtomicValue[T]) CompareAndSwap(old, new T) bool {
	var zeroVal T // jit init
	a.Value.CompareAndSwap(nil, zeroVal)
	return a.Value.CompareAndSwap(old, new)
}

// generic sync map
type SyncMap[K, V comparable] struct {
	sync.Map
}

func (sm *SyncMap[K, V]) Load(key K) (val V, ok bool) {
	if v, ok := sm.Map.Load(key); ok && v != nil {
		return v.(V), true
	}
	return val, false
}

func (sm *SyncMap[K, V]) Store(key K, val V) {
	sm.Map.Store(key, val)
}

func (sm *SyncMap[K, V]) Swap(key K, val V) (old V, ok bool) {
	if v, ok := sm.Map.Swap(key, val); ok && v != nil {
		return v.(V), true
	}
	return old, false
}

func (sm *SyncMap[K, V]) LoadOrStore(key K, val V) (V, bool) {
	if v, loaded := sm.Map.LoadOrStore(key, val); loaded && v != nil {
		return v.(V), true
	}
	return val, false
}

func (sm *SyncMap[K, V]) CompareAndSwap(key K, oldVal, newVal V) bool {
	return sm.Map.CompareAndSwap(key, oldVal, newVal)
}

func (sm *SyncMap[K, V]) Delete(key K) {
	sm.Map.Delete(key)
}

func ProcessProxyError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("proxy error", "error", err, "module", "reverse-proxy")
	http.Error(w, "reverse-proxy error: "+err.Error(), http.StatusBadGateway)
}

func LogHTTP2Error(module, errType string) {
	logLevel := slog.LevelError
	if errType == "read_frame_eof" {
		errType = "read_frame_eof-likely_after_goaway"
		logLevel = slog.LevelInfo
	}
	http2errors.WithLabelValues(module, errType).Inc()
	slog.Log(context.Background(), logLevel, "http2 conn", "module", module, "error", errType)
}

func IsLongPollRequest(r *http.Request) bool {
	q := r.URL.Query()
	// may include /proxy/ calls to pods, assume they follow same semantics if so
	return q.Get("watch") == "true" || q.Get("follow") == "true"
}

// Special handling for upgrade requests until golang reverse proxy supports them natively
func IsUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || r.Header.Get("Kubeportal-Upgrade") != ""
}

func CtxWithStartTime(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyRequestStartTime, time.Now())
}

func StartTimeFromCtx(ctx context.Context) time.Time {
	return ctx.Value(ctxKeyRequestStartTime).(time.Time)
}

// During shutdown, we want to let regular requests run to completion
// but long-poll requests like watch and logs -f we want to stop immediately to allow for a quicker shutdown.
// When cancelling a context, the reverse proxy will panic with http.ErrAbortHandler, which the http2 server
// turns into a RST_STREAM INTERNAL_ERROR. But this is not the correct behavior for a proxy that is restarting.
// The correct behavior seems to be a RST_STREAM CANCEL, but there is no way to cause the http2 server to send that.
// The next best option seems to be to just end the stream, usually after GoAway is sent, which we do on shutdown.
func CatchAbortOnShutdown(ctx context.Context) {
	if ctx.Err() != nil {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			panic(err)
		}
	}
}

type ReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (rwc ReadWriteCloser) Close() error {
	var err1, err2 error
	if c, ok := rwc.Reader.(io.Closer); ok {
		err1 = c.Close()
	}
	if c, ok := rwc.Writer.(io.Closer); ok {
		err2 = c.Close()
	}
	return errors.Join(err1, err2)
}

func LogUpgradeRequest(module string, r *http.Request, err error) {
	ctx := r.Context()
	duration := time.Since(StartTimeFromCtx(ctx))
	level := slog.LevelInfo
	if err != nil {
		level = slog.LevelError
	}
	slog.Log(ctx, level, "Upgrade request proxied",
		"module", module,
		"path", r.URL.Path,
		"request_id", r.Header.Get(RequestIDHeaderName),
		"duration", duration.Milliseconds(),
		"error", err,
	)
	upgradeRequestDurationMetric.WithLabelValues(module).Observe(duration.Seconds())
}

type LoggerFunc func(requestFinished bool, r *http.Request, level slog.Level, statusCode int, err error)
type LoggingTripper struct {
	http.RoundTripper
	LogHeaders LoggerFunc
}

func (lt *LoggingTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := lt.RoundTripper.RoundTrip(req)
	statusCode := http.StatusBadGateway
	logLevel := slog.LevelError
	if err == nil {
		statusCode = resp.StatusCode
		logLevel = slog.LevelInfo
	} else if errors.Is(err, context.Canceled) {
		statusCode = 0
		logLevel = slog.LevelWarn
	}
	lt.LogHeaders(false, req, logLevel, statusCode, err)
	respItems := req.Context().Value(ctxKeyResponseLogItems).(*ResponseLogItems)
	respItems.statusCode = statusCode
	respItems.logLevel = logLevel
	respItems.err = err
	return resp, err
}

type ResponseLogItems struct {
	logLevel   slog.Level
	statusCode int
	err        error
}

func CtxWithResponseLogItems(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyResponseLogItems, &ResponseLogItems{})
}

func LogRequestFinished(r *http.Request, l LoggerFunc) {
	respItems := r.Context().Value(ctxKeyResponseLogItems).(*ResponseLogItems)
	l(true, r, respItems.logLevel, respItems.statusCode, respItems.err)
}
