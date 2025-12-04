package agent

import (
	"context"
	"crypto/tls"
	"kubeportal/messaging"
	"log/slog"
	"net"
	"net/url"
	"time"
)

const (
	maxConsecutiveRejections = 10
	maxSleepTime             = 5 * time.Second
	unitOfSleep              = maxSleepTime / maxConsecutiveRejections
)

type Agent struct {
	hubURL         url.URL
	kubeIdentifier string
	k8sProxy       *K8sProxy
	log            *slog.Logger
	ctx            context.Context
}

func NewAgent(ctx context.Context, k8sProxy *K8sProxy, kubeIdentifier string, hubURL url.URL) *Agent {
	return &Agent{
		k8sProxy:       k8sProxy,
		hubURL:         hubURL,
		kubeIdentifier: kubeIdentifier,
		log:            slog.With("module", "Agent"),
		ctx:            ctx,
	}
}

func (a *Agent) Run() {
	consecutiveRejections := 0
	for a.ctx.Err() == nil {
		if consecutiveRejections > 0 {
			time.Sleep(unitOfSleep * time.Duration(min(consecutiveRejections, maxConsecutiveRejections)))
		}
		c, err := a.dialHub()
		if err != nil {
			a.log.With("error", err).Error("couldn't connect to hub")
			consecutiveRejections++
			continue
		}
		msg, err := a.initConn(c)
		if err != nil {
			c.Close()
			a.log.With("error", err).Error("Error during conn init")
			continue
		}
		switch msg {
		case messaging.MsgConnAccepted:
			consecutiveRejections = 0
			go a.standbyConn(c)
		case messaging.MsgConnRejected:
			c.Close()
			consecutiveRejections++
		case messaging.MsgVerifyConn:
			consecutiveRejections = 0
			c.Close()
		}
	}
}

func (a *Agent) initConn(c net.Conn) (messaging.Message, error) {
	if err := messaging.Write(c, messaging.ConnInfo{
		KubeIdentifier: a.kubeIdentifier,
		SvcActToken:    "todo", // use aud
		ConnectionID:   "todo",
	}); err != nil {
		return messaging.MsgNone, err
	}
	msg, err := messaging.Expect(c, messaging.MsgConnAccepted, messaging.MsgConnRejected, messaging.MsgVerifyConn)
	if err != nil {
		return messaging.MsgNone, err
	}
	if msg == messaging.MsgVerifyConn {
		if err := messaging.Write(c, messaging.MsgConnVerificationReady); err != nil {
			return msg, err
		}
	}
	return msg, nil
}

func (a *Agent) standbyConn(c net.Conn) {
	a.log.Debug("Conn to hub established, entering standby")
	for a.ctx.Err() == nil {
		msg, err := messaging.Expect(c, messaging.MsgActivateConn, messaging.MsgPing)
		if err != nil {
			a.log.With("error", err).Error("Error while waiting for conn activation")
			c.Close()
			return
		}
		if a.ctx.Err() != nil {
			c.Close()
			return
		}
		switch msg {
		case messaging.MsgActivateConn:
			a.log.Debug("activate")
			if err := messaging.Write(c, messaging.MsgConnActivated); err != nil {
				a.log.With("error", err).Error("Error confirming conn activation")
				c.Close()
				return
			}
			a.k8sProxy.ProxyConn(c)
			return
		case messaging.MsgPing:
			a.log.Debug("ping")
			if err := messaging.Write(c, messaging.MsgPong); err != nil {
				a.log.With("error", err).Error("Error while ponging hub")
				c.Close()
				return
			}
		}
	}
}

var tcpDialer = net.Dialer{
	Timeout:   5 * time.Second,
	KeepAlive: 30 * time.Second,
}

var tlsDialer = tls.Dialer{
	NetDialer: &tcpDialer,
}

func (a *Agent) dialHub() (net.Conn, error) {
	u := a.hubURL
	useTLS := u.Scheme == "https" || u.Scheme == "tls"
	hostPort := u.Host
	if u.Port() == "" {
		if useTLS {
			hostPort = u.Hostname() + ":443"
		} else {
			hostPort = u.Hostname() + ":80"
		}
	}
	if useTLS {
		return tlsDialer.DialContext(a.ctx, "tcp", hostPort)
	}
	return tcpDialer.DialContext(a.ctx, "tcp", hostPort)
}
