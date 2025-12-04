package hub

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
)

type TracedConn struct {
	net.Conn
	ID string
}

type clientTracer struct {
	connID string
}

func (ct *clientTracer) recordConnID(info httptrace.GotConnInfo) {
	ct.connID = info.Conn.(*TracedConn).ID
}

type responseStatusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseStatusRecorder) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

type ctxKey int

const ctxKeyBearerToken ctxKey = iota

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
