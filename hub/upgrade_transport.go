package hub

import (
	"fmt"
	"io"
	"kubeportal/shared"
	"net/http"
	"strconv"
)

// upgradeTransport wraps an http.RoundTripper to special-case UPGRADE requests
type upgradeTransport struct {
	rt http.RoundTripper
}

func (t *upgradeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !shared.IsUpgradeRequest(req) {
		return t.rt.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	proto := req.Header.Get("Upgrade")
	req.Header.Set("Kubeportal-Upgrade", proto)
	req.Header.Del("Upgrade")
	req.Header.Del("Connection")
	pr, pw := io.Pipe()
	req.Body = pr
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		pw.CloseWithError(err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected upgrade status code from agent: %d", resp.StatusCode)
		pw.CloseWithError(err)
		resp.Body.Close()
		return nil, err
	}
	statusCode, err := strconv.Atoi(resp.Header.Get(shared.StatusCodeHeaderName))
	if err != nil {
		err = fmt.Errorf("failed to parse response status code from agent: %w", err)
		pw.CloseWithError(err)
		resp.Body.Close()
		return nil, err
	}
	resp = &http.Response{
		StatusCode: statusCode,
		Header:     resp.Header,
		Body:       resp.Body,
		Request:    resp.Request,
	}
	resp.Header.Del(shared.StatusCodeHeaderName)
	if statusCode == http.StatusSwitchingProtocols {
		resp.Header.Set("Connection", "Upgrade")
		resp.Body = &shared.ReadWriteCloser{
			Reader: resp.Body,
			Writer: pw,
		}
	}
	return resp, nil
}
