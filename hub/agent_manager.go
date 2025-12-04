package hub

import (
	"context"
	"errors"
	"kubeportal/messaging"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const timeToWaitForConnSlot = 50 * time.Millisecond

type AgentManager struct {
	ctx                 context.Context
	log                 *slog.Logger
	ln                  net.Listener
	agentConns          sync.Map
	tokenParser         *jwt.Parser
	standbyConnsPerKube int
}

func NewAgentManager(ctx context.Context, ln net.Listener, standbyConnsPerKube int) *AgentManager {
	am := &AgentManager{
		ctx:                 ctx,
		log:                 slog.With("module", "HubAgentManager"),
		ln:                  ln,
		agentConns:          sync.Map{},
		tokenParser:         jwt.NewParser(jwt.WithoutClaimsValidation()),
		standbyConnsPerKube: standbyConnsPerKube,
	}
	return am
}

func (am *AgentManager) Serve() {
	am.log.Info("Agent manager listening")
	for {
		conn, err := am.ln.Accept()
		if err != nil {
			am.log.With("error", err).Error("accept error")
			continue
		}
		go am.HandleIncomingConn(conn)
	}
}

func (am *AgentManager) HandleIncomingConn(c net.Conn) {
	log := am.log.With("addr", c.RemoteAddr().String())
	connInfo, err := messaging.ReadConnInfo(c)
	if err != nil {
		log.With("error", err).Error("Failed reading conn info from agent")
		c.Close()
		return
	}
	log = log.With("kubeIdentifier", connInfo.KubeIdentifier).With("connID", connInfo.ConnectionID)
	log.Info("New conn from agent")
	sc := am.getKubeStandbyConns(connInfo.KubeIdentifier)
	deadlineCtx, cancel := context.WithTimeout(context.Background(), timeToWaitForConnSlot) // survive a few sc loops
	defer cancel()
	select {
	case <-sc.ReserveSlot:
		if err := setupConn(c); err != nil {
			<-sc.ReleaseSlot
			log.With("error", err).Error("Failed to setup new conn from agent")
		} else {
			sc.FillSlot <- &TracedConn{Conn: c, ID: connInfo.ConnectionID}
			log.Info("Added agent conn for kube")
		}
	case <-deadlineCtx.Done():
		log.Debug("Standby conns full, closing conn")
		if err := messaging.Write(c, messaging.MsgConnRejected); err != nil {
			log.With("error", err).Error("Failed to send conn rejection to agent")
		}
		c.Close()
	}
}

func (am *AgentManager) GetConnForHost(ctx context.Context, network string, kubeIdentifier string) (net.Conn, error) {
	kubeIdentifier, _, _ = strings.Cut(kubeIdentifier, ":") // remove port if present
	log := am.log.With("kubeIdentifier", kubeIdentifier)
	log.Debug("Connection requested")

	sc := am.getKubeStandbyConns(kubeIdentifier)

	// Try to get a valid connection, with retries for dead connections
	deadlineCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second) // kubectl seems to have ~30s default t/o
	start := time.Now()
	defer cancel()
	for {
		select {
		case <-deadlineCtx.Done():
			err := errors.New("hit deadline while waiting for a connection for the kube")
			log.Warn(err.Error())
			return nil, err
		case <-ctx.Done():
			err := errors.New("context cancelled while waiting for a connection for the kube")
			log.With("error", ctx.Err()).Warn(err.Error())
			return nil, err
		case conn := <-sc.GetConn:
			log := log.With("connID", conn.(*TracedConn).ID)
			if err := messaging.Write(conn, messaging.MsgActivateConn); err != nil {
				log.With("error", err).Warn("Failed while requesting to activate agent connection, discarding")
				conn.Close()
				continue
			}
			if _, err := messaging.Expect(conn, messaging.MsgConnActivated); err != nil {
				log.With("error", err).Warn("Failed while confirming agent connection activation, discarding")
				conn.Close()
				continue
			}
			elapsed := time.Since(start)
			durationLog := log.With("duration", elapsed.Milliseconds())
			if elapsed > (time.Second * 5) {
				durationLog.Warn("Took a long time to get a connection for a kube")
			} else if elapsed > time.Second {
				durationLog.Info("Took a while to get a connection for a kube")
			}
			durationLog.Debug("Successfully activated a connection for kube")
			return conn, nil
		}
	}
}

func (am *AgentManager) getKubeStandbyConns(kubeIdentifier string) *StandbyConnStore {
	conns, loaded := am.agentConns.Load(kubeIdentifier)
	if !loaded {
		conns, loaded = am.agentConns.LoadOrStore(kubeIdentifier, NewStandbyConnStore(am.standbyConnsPerKube))
		if !loaded {
			am.log.With("kubeIdentifier", kubeIdentifier).Info("New kube")
			conns.(*StandbyConnStore).Run(kubeIdentifier)
		}
	}
	return conns.(*StandbyConnStore)
}

func setupConn(c net.Conn) error {
	if err := messaging.Write(c, messaging.MsgConnAccepted); err != nil {
		return err
	}
	if c, ok := c.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return err
		}
		if err := c.SetKeepAlivePeriod(time.Second * 30); err != nil {
			return err
		}
	}
	return nil
}
