package agent

import (
	"context"
	"errors"
	"kubeportal/messaging"
	"kubeportal/shared"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const (
	maxConsecutiveRejections = 10
	maxSleepTime             = 5 * time.Second
	unitOfSleep              = maxSleepTime / maxConsecutiveRejections
	openidTokenTTL           = 10 * time.Minute
)

type Agent struct {
	id                 string
	hubAddress         string
	insecureHub        bool
	kubeIdentifier     string
	k8sProxy           *K8sProxy
	log                *slog.Logger
	ctx                context.Context
	openidToken        shared.AtomicValue[string]
	openidTokenFetcher v1.ServiceAccountInterface
	openidTokenRequest *authv1.TokenRequest
}

func NewAgent(ctx context.Context, k8sProxy *K8sProxy, kubeIdentifier string, hubAddress string, insecureHub bool) (*Agent, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	ns, err := currentNamespace()
	if err != nil {
		return nil, err
	}
	podName, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	ttl := int64(openidTokenTTL.Seconds())
	a := &Agent{
		id:                 podName,
		k8sProxy:           k8sProxy,
		hubAddress:         hubAddress,
		insecureHub:        insecureHub,
		kubeIdentifier:     kubeIdentifier,
		log:                slog.With("module", "agent"),
		ctx:                ctx,
		openidTokenFetcher: clientset.CoreV1().ServiceAccounts(ns),
		openidTokenRequest: &authv1.TokenRequest{
			Spec: authv1.TokenRequestSpec{
				ExpirationSeconds: &ttl,
			},
		},
	}
	if err := a.refreshOpenidToken(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Agent) Run() {
	// refresh openid token periodically
	go func() {
		for range time.NewTicker(time.Minute).C {
			if err := a.refreshOpenidToken(); err != nil {
				a.log.Error("Failed to refresh openid token, will try again soon", "error", err)
			}
		}
	}()
	consecutiveRejections := 0
	for {
		select {
		case <-a.ctx.Done():
			a.log.Info("Shutting down")
			return
		case <-time.After(unitOfSleep * time.Duration(min(consecutiveRejections, maxConsecutiveRejections))):
			c, err := a.dialHub()
			if err != nil {
				a.log.Error("couldn't connect to hub", "error", err)
				consecutiveRejections++
				continue
			}
			connID := uuid.NewString()
			log := a.log.With("conn_id", connID)
			tcpConn := c.(*net.TCPConn)
			c = tracedConn{Conn: c, ID: connID}
			msg, err := messaging.WriteAndExpect(c, messaging.MsgConnInfo{
				KubeIdentifier: a.kubeIdentifier,
				AgentID:        a.id,
				SvcActToken:    a.openidToken.Load(),
				ConnectionID:   connID,
			}, messaging.MsgConnAccepted, messaging.MsgConnRejected, messaging.MsgVerifyConn)
			if err != nil {
				c.Close()
				log.Error("Error during conn init", "error", err)
				consecutiveRejections++
				continue
			}
			switch msg {
			case messaging.MsgConnAccepted:
				consecutiveRejections = 0
				log.Info("Serving conn")
				go a.k8sProxy.ServeConn(c)
			case messaging.MsgConnRejected:
				c.Close()
				consecutiveRejections++
			case messaging.MsgVerifyConn:
				if err := a.doConnVerification(tcpConn); err != nil {
					log.Error("Error during conn verification", "error", err)
					consecutiveRejections++
				} else {
					consecutiveRejections = 0
				}
				c.Close()
			}
		}
	}
}

func (a *Agent) doConnVerification(c *net.TCPConn) error {
	k8sConn, err := tcpDialer.DialContext(a.ctx, "tcp", shared.K8sHostname+":443")
	if err != nil {
		return err
	}
	defer k8sConn.Close()
	if err := messaging.Write(c, messaging.MsgConnVerificationReady); err != nil {
		return err
	}
	errChan := make(chan error)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go netCopy(k8sConn.(*net.TCPConn), c, errChan)
	go netCopy(c, k8sConn.(*net.TCPConn), errChan)
	return errors.Join(<-errChan, <-errChan)
}

func (a *Agent) dialHub() (net.Conn, error) {
	if a.insecureHub {
		return tcpDialer.DialContext(a.ctx, "tcp", a.hubAddress)
	}
	return tlsDialer.DialContext(a.ctx, "tcp", a.hubAddress)
}

func (a *Agent) refreshOpenidToken() error {
	resp, err := a.openidTokenFetcher.CreateToken(a.ctx, shared.OpenidReaderSAName, a.openidTokenRequest, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	a.openidToken.Store(resp.Status.Token)
	return nil
}
