package hub

import (
	"context"
	"crypto/x509"
	"errors"
	"kubeportal/shared"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/http2"
)

const (
	jwksFetchCooldown = time.Minute
	kubeWarmupTime    = 5 * time.Minute
)

var (
	ErrNoJWKS   = errors.New("no jwks for kube yet")
	tokenParser = jwt.NewParser()
)

type Kube struct {
	id                string
	km                *KubeManager
	mu                sync.Mutex
	certBytes         []byte
	verified          bool
	CaPool            *x509.CertPool
	CaPoolWithRoots   *x509.CertPool
	jwksFetchTime     shared.AtomicValue[time.Time]
	jwtKeyFunc        jwt.Keyfunc
	conns             shared.SyncMap[string, *[]*http2.ClientConn]
	inflightReqCounts *shared.SyncMap[string, *atomic.Int32]
	agents            atomic.Pointer[[]string]
	getConnCounter    atomic.Uint32
	CreationTime      time.Time
	Ctx               context.Context
	CtxCancel         context.CancelFunc
	Prev              *Kube
}

func (k *Kube) ValidateToken(token string) error {
	if k.jwtKeyFunc == nil {
		return ErrNoJWKS
	}
	var claims ServiceAccountClaims
	parsedToken, err := tokenParser.ParseWithClaims(token, &claims, k.jwtKeyFunc)
	if err != nil {
		return err
	}
	if !parsedToken.Valid {
		return errors.New("invalid token")
	}
	if claims.K8s.ServiceAccount.Name != shared.OpenidReaderSAName {
		return errors.New("unexpected service account name for agent token: " + claims.K8s.ServiceAccount.Name)
	}
	return nil
}

func (k *Kube) CanFetchJWKS() bool {
	lastFetch := k.jwksFetchTime.Load()
	if time.Since(lastFetch) < jwksFetchCooldown {
		return false
	}
	return k.jwksFetchTime.CompareAndSwap(lastFetch, time.Now())
}

func (k *Kube) AddAgentConn(conn net.Conn, agentID, connID string) error {
	cc, err := k.km.transport.NewClientConn(conn)
	if err != nil {
		return err
	}
	k.km.connLookup.Store(cc, &ConnInfo{
		Kube:    k,
		AgentID: agentID,
		ConnID:  connID,
	})
	k.mu.Lock()
	defer k.mu.Unlock()
	connsPtr, loaded := k.conns.LoadOrStore(agentID, &[]*http2.ClientConn{cc})
	if loaded {
		newConns := append(slices.Clone(*connsPtr), cc)
		k.conns.Store(agentID, &newConns)
	}
	agents := *k.agents.Load()
	if !slices.Contains(agents, agentID) {
		agents = append(slices.Clone(agents), agentID)
		k.agents.Store(&agents)
	}
	return nil
}

func (k *Kube) RemoveAgentConn(conn *http2.ClientConn, info *ConnInfo) {
	agentID := info.AgentID
	k.km.log.Info("Removing agent conn from kube", "kube_identifier", k.id, "agent_id", agentID, "conn_id", info.ConnID)
	k.mu.Lock()
	defer k.mu.Unlock()
	connsPtr, loaded := k.conns.Load(agentID)
	if !loaded {
		return
	}
	conns := slices.Clone(*connsPtr)
	numConns := len(conns)
	for i, c := range conns {
		if c == conn {
			if numConns == 1 {
				k.conns.Delete(agentID)
			} else {
				conns[i] = conns[numConns-1]
				conns[numConns-1] = nil
				conns = conns[:numConns-1]
				k.conns.Store(agentID, &conns)
				return // skip agent cleanup below
			}
			break
		}
	}
	agents := slices.Clone(*k.agents.Load())
	numAgents := len(agents)
	for i, a := range agents {
		if a == agentID {
			agents[i] = agents[numAgents-1]
			agents = agents[:numAgents-1]
			k.agents.Store(&agents)
			break
		}
	}
}

// Returns true if current utilization over 50%
func (k *Kube) ShouldAddAgentConn(agentID string) bool {
	conns, loaded := k.conns.Load(agentID)
	if !loaded || len(*conns) < 2 {
		return true
	}
	return k.ReqCnt(agentID)*2 > len(*conns)*shared.MaxConcurrentStreams
}

func (k *Kube) GetKubeConn() *http2.ClientConn {
	if k.verified {
		cnt := k.getConnCounter.Add(1)
		agents := *k.agents.Load()
		agentCnt := uint32(len(agents))
		if agentCnt > 0 {
			agentsToTryFirst := []string{agents[cnt%agentCnt], agents[(cnt+1)%agentCnt]}
			if k.ReqCnt(agentsToTryFirst[0]) > k.ReqCnt(agentsToTryFirst[1]) {
				agentsToTryFirst[0], agentsToTryFirst[1] = agentsToTryFirst[1], agentsToTryFirst[0]
			}
			// first try the two selected agents
			for _, agentID := range agentsToTryFirst {
				if conn := k.GetAgentConn(agentID, cnt); conn != nil {
					return conn
				}
			}
			// fall back to any agent
			for _, agentID := range agents {
				if agentID == agentsToTryFirst[0] || agentID == agentsToTryFirst[1] {
					continue
				}
				if conn := k.GetAgentConn(agentID, cnt); conn != nil {
					return conn
				}
			}
		}
	}
	// fall back to prev Kube
	if time.Since(k.CreationTime) < kubeWarmupTime {
		if k.Prev != nil { // prevent races via time segregated access
			return k.Prev.GetKubeConn()
		}
	}
	return nil
}

func (k *Kube) GetAgentConn(agentID string, cnt uint32) *http2.ClientConn {
	if connsPtr, loaded := k.conns.Load(agentID); loaded {
		conns := *connsPtr
		connLen := uint32(len(conns))
		for i := uint32(0); i < connLen; i++ {
			j := (cnt + i) % connLen
			if conns[j].ReserveNewRequest() {
				return conns[j]
			}
		}
	}
	return nil
}

func (k *Kube) ReqCnt(agentID string) int {
	if ctr, loaded := k.inflightReqCounts.Load(agentID); loaded {
		return int(ctr.Load())
	}
	return 0
}
func (k *Kube) ReqCntInc(agentID string) {
	k.reqCntChangeBy(agentID, 1)
}
func (k *Kube) ReqCntDec(agentID string) {
	k.reqCntChangeBy(agentID, -1)
}
func (k *Kube) reqCntChangeBy(agentID string, n int32) {
	ctr, _ := k.inflightReqCounts.LoadOrStore(agentID, &atomic.Int32{})
	if ctr.Add(n) == 0 {
		k.reqCntCleanup(agentID, ctr)
	}
}
func (k *Kube) reqCntCleanup(agentID string, ctr *atomic.Int32) {
	if k.inflightReqCounts.CompareAndDelete(agentID, ctr) {
		go func() {
			for _, d := range []time.Duration{time.Second, 5 * time.Second, time.Minute} {
				time.Sleep(d)
				if racers := ctr.Load(); racers != 0 {
					ctr.Add(-racers)
					k.reqCntChangeBy(agentID, racers)
				}
			}
		}()
	}
}
