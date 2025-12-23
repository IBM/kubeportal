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

func IsUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || r.Header.Get("Kubeportal-Upgrade") != ""
}

// returns baseCtx that is canceled when existingCancelCtx is canceled
func CtxWithExistingCancel(baseCtx, existingCancelCtx context.Context) (context.Context, context.CancelFunc) {
	newCtx, cancel := context.WithCancel(baseCtx)
	stop := context.AfterFunc(existingCancelCtx, cancel)
	return newCtx, func() {
		cancel()
		stop()
	}
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
// The correct behavior seems to be a RST_STREAM CANCEL, but this there is no way to cause the http2 server to send that.
// The next best option seems to be to just end the stream, usually after GoAway is sent, which we do on shutdown.
func NoAbortOnShutdown(ctx context.Context) {
	if ctx.Err() != nil {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			panic(err)
		}
	}
}

type ReadWriteCloser struct {
	io.ReadCloser
	io.Writer
}

func asyncCopy(dst io.Writer, src io.Reader, errChan chan error) {
	_, err := io.Copy(dst, src)
	errChan <- err
}

func BidirectionalCopy(rCtx context.Context, cancelCtx context.Context, a, b io.ReadWriteCloser) error {
	errChan := make(chan error)
	go asyncCopy(a, b, errChan)
	go asyncCopy(b, a, errChan)
	select {
	case <-rCtx.Done():
		a.Close()
		b.Close()
		<-errChan
		<-errChan
		return nil
	case <-cancelCtx.Done():
		time.Sleep(time.Until(StartTimeFromCtx(rCtx).Add(10 * time.Second))) // let it run for at least 10s
		a.Close()
		b.Close()
		<-errChan
		<-errChan
		return nil
	case err := <-errChan:
		a.Close()
		b.Close()
		return errors.Join(err, <-errChan)
	}
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

type LoggingTripper struct {
	http.RoundTripper
	LogRequest func(r *http.Request, level slog.Level, statusCode int, err error)
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
	lt.LogRequest(req, logLevel, statusCode, err)
	return resp, err
}
