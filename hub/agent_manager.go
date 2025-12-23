package hub

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"kubeportal/messaging"
	"kubeportal/shared"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	openidConfigPath = "/.well-known/openid-configuration"
)

type AgentManager struct {
	log         *slog.Logger
	ln          net.Listener
	kubeManager *KubeManager
}

func NewAgentManager(ln net.Listener, km *KubeManager) *AgentManager {
	am := &AgentManager{
		log:         slog.With("module", "hub-agent-manager"),
		ln:          ln,
		kubeManager: km,
	}
	return am
}

func (am *AgentManager) Run() {
	am.log.Info("Agent manager listening")
	for {
		conn, err := am.ln.Accept()
		if err != nil {
			am.log.Error("accept error", "error", err)
			continue
		}
		go am.HandleIncomingConn(conn)
	}
}

func (am *AgentManager) HandleIncomingConn(c net.Conn) {
	log := am.log.With("addr", c.RemoteAddr().String())
	connInfo, err := messaging.ReadConnInfo(c)
	if err != nil {
		log.Error("Failed reading conn info from agent", "error", err)
		c.Close()
		return
	}
	log = log.With("kube_identifier", connInfo.KubeIdentifier, "conn_id", connInfo.ConnectionID, "agent_id", connInfo.AgentID)

	kube, err := am.kubeManager.GetKube(connInfo.KubeIdentifier)
	if err != nil {
		log.Error("Unknown kube", "error", err)
		c.Close()
		return
	}

	if err := kube.ValidateToken(connInfo.SvcActToken); err != nil {
		if !errors.Is(err, ErrNoJWKS) {
			log.Warn("Failed to validate agent token, will try fetching new jwks", "error", err)
		}
		if !kube.CanFetchJWKS() {
			log.Debug("Can't fetch jwks due to rate limiting, probably fetched by another agent conn in parallel")
			c.Close()
			return
		}
		log.Info("Fetching new jwks for kube")
		jwksBytes, err := am.fetchJWKS(c, kube, connInfo.SvcActToken)
		if err != nil {
			log.Error("Failed to fetch jwks for kube", "error", err)
			c.Close()
			return
		}
		if err := am.kubeManager.SetJWKS(kube, jwksBytes); err != nil {
			log.Error("Failed to set jwks for kube", "error", err)
			c.Close()
			return
		}
		c.Close()
		return
	}
	if !kube.ShouldAddAgentConn(connInfo.AgentID) { // each agent sends one conn request at a time
		if err := messaging.Write(c, messaging.MsgConnRejected); err != nil {
			log.Error("Failed to send conn rejection to agent", "error", err)
		}
		c.Close()
		return
	}
	if err := messaging.Write(c, messaging.MsgConnAccepted); err != nil {
		log.Error("Failed to accept new conn from agent", "error", err)
		c.Close()
		return
	}
	log.Info("Accepted new conn from agent, adding it to pool")
	if err := kube.AddAgentConn(c, connInfo.AgentID, connInfo.ConnectionID); err != nil {
		log.Error("Failed to add agent conn to pool", "error", err)
		c.Close()
		return
	}
}

func (am *AgentManager) fetchJWKS(conn net.Conn, kube *Kube, svcActToken string) ([]byte, error) {
	if _, err := messaging.WriteAndExpect(conn, messaging.MsgVerifyConn, messaging.MsgConnVerificationReady); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    kube.CaPool,
		ServerName: shared.K8sHostname,
	})
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	defer tlsConn.Close()
	body, err := getOpenidPrivate(tlsConn, openidConfigPath, svcActToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch private openid configuration: %w", err)
	}
	var openidResp openidResponse
	if err := json.Unmarshal(body, &openidResp); err != nil {
		return nil, fmt.Errorf("failed to parse private openid configuration: %w", err)
	}
	issuerUrl, err := url.Parse(openidResp.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer url: %w", err)
	}
	if issuerUrl.Hostname() == shared.K8sHostname { // the kube is itself the issuer
		jwksUri, err := url.Parse(openidResp.JwksUri)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private jwks uri: %w", err)
		}
		return getOpenidPrivate(tlsConn, jwksUri.Path, svcActToken)
	}
	// external issuer
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: kube.CaPoolWithRoots,
			},
		},
	}
	body, err = getOpenidPublic(client, openidResp.Issuer+openidConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public openid configuration: %w", err)
	}
	var pubOpenidResp openidResponse
	if err := json.Unmarshal(body, &pubOpenidResp); err != nil {
		return nil, fmt.Errorf("failed to parse public openid configuration: %w", err)
	}
	body, err = getOpenidPublic(client, pubOpenidResp.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to get public jwks: %w", err)
	}
	return body, nil
}
