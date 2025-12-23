package hub

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"kubeportal/shared"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"golang.org/x/net/http2"
	"k8s.io/client-go/util/cert"
)

var (
	_ http2.ClientConnPool = (*KubeManager)(nil)
)

var ErrUnknownKube = errors.New("unknown kube")

type KubeManager struct {
	kubes        shared.SyncMap[string, *Kube]
	connLookup   shared.SyncMap[*http2.ClientConn, *ConnInfo]
	mutationLock sync.Mutex
	transport    *http2.Transport
	caCertsPath  string
	rootCAs      *x509.CertPool
	log          *slog.Logger
}

func NewKubeManager(caCertsPath string, tr *http2.Transport) (*KubeManager, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	km := &KubeManager{
		caCertsPath: caCertsPath,
		rootCAs:     rootCAs,
		log:         slog.With("module", "kube-manager"),
		transport:   tr,
	}
	if err := km.loadKubes(); err != nil {
		return nil, err
	}
	return km, nil
}

func (km *KubeManager) GetKube(kubeIdentifier string) (*Kube, error) {
	kube, loaded := km.kubes.Load(kubeIdentifier)
	if !loaded {
		return nil, ErrUnknownKube
	}
	return kube, nil
}

func (km *KubeManager) Run() {
	var lastMountVersion string
	for range time.NewTicker(time.Minute).C {
		// todo: cleanup old kubes here

		// reload certs
		mountVersion, err := os.Readlink(filepath.Join(km.caCertsPath, "..data"))
		if err != nil {
			if os.IsNotExist(err) {
				km.log.Info("Skipping kube ca cert reloading, assume static certs", "error", err)
				continue
			}
			km.log.Error("Error reading kube ca certs", "error", err)
			continue
		}
		if mountVersion != lastMountVersion {
			if err := km.loadKubes(); err != nil {
				km.log.Error("Error reloading kube certs", "error", err)
				continue
			}
			lastMountVersion = mountVersion
		}
	}
}

func (km *KubeManager) loadKubes() error {
	km.log.Info("Reloading ca certs")
	entries, err := os.ReadDir(km.caCertsPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fileName := entry.Name()
		if entry.IsDir() || fileName == "..data" {
			continue
		}
		log := km.log.With("kube_identifier", fileName)
		certBytes, err := os.ReadFile(filepath.Join(km.caCertsPath, fileName))
		if err != nil {
			log.Error("Error reading ca cert", "error", err)
			continue
		}
		oldKube, loaded := km.kubes.Load(fileName)
		if loaded && bytes.Equal(oldKube.certBytes, certBytes) {
			log.Info("Not adding new kube, ca certs unchanged")
			continue
		}
		certs, err := cert.ParseCertsPEM(certBytes)
		if err != nil {
			log.Error("Error parsing ca cert", "error", err)
			continue
		}
		caPool := x509.NewCertPool()
		rootCAs := km.rootCAs.Clone()
		for _, cert := range certs {
			caPool.AddCert(cert)
			rootCAs.AddCert(cert)
		}
		newKube := &Kube{
			id:              fileName,
			certBytes:       certBytes,
			CaPool:          caPool,
			CaPoolWithRoots: rootCAs,
			CreationTime:    time.Now(),
		}
		km.mutationLock.Lock()
		oldKube, loaded = km.kubes.Load(fileName)
		if loaded && oldKube != nil {
			newKube.inflightReqCounts = oldKube.inflightReqCounts
			newKube.Prev = oldKube
		} else {
			newKube.inflightReqCounts = &shared.SyncMap[string, *atomic.Int32]{}
		}
		km.kubes.Store(fileName, newKube)
		km.mutationLock.Unlock()
		log.Info("Added kube")
	}
	return nil
}

func (km *KubeManager) SetJWKS(oldKube *Kube, jwksBytes []byte) error {
	kf, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksBytes))
	if err != nil {
		return err
	}
	km.log.Info("Setting new jwks for kube", "kube_identifier", oldKube.id)
	ctx, cancel := context.WithCancel(context.Background())
	newKube := &Kube{
		id:                oldKube.id,
		km:                km,
		verified:          true,
		certBytes:         oldKube.certBytes,
		CaPool:            oldKube.CaPool,
		CaPoolWithRoots:   oldKube.CaPoolWithRoots,
		jwtKeyFunc:        kf.Keyfunc,
		inflightReqCounts: oldKube.inflightReqCounts,
		CreationTime:      time.Now(),
		Ctx:               ctx,
		CtxCancel:         cancel,
		Prev:              oldKube,
	}
	newKube.agents.Store(&[]string{})
	km.mutationLock.Lock()
	defer km.mutationLock.Unlock()
	if !km.kubes.CompareAndSwap(oldKube.id, oldKube, newKube) {
		return errors.New("kube changed while fetching jwks, didn't set jwks")
	}
	return nil
}

// called by the reverse proxy Transport
func (km *KubeManager) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	kubeIdentifier, _, _ := strings.Cut(addr, ":") // remove port if present
	kube, err := km.GetKube(kubeIdentifier)
	if err != nil {
		return nil, err
	}
	conn := kube.GetKubeConn()
	if conn == nil {
		return nil, errors.New("no conn available")
	}
	connInfo, loaded := km.connLookup.Load(conn)
	if !loaded {
		return nil, errors.New("conn info unavailable?")
	}
	rp := RequestPropsFromContext(req.Context())
	if rp.ConnInfo != nil {
		kube.ReqCntDec(rp.ConnInfo.AgentID)
	}
	kube.ReqCntInc(connInfo.AgentID)
	rp.ConnInfo = connInfo
	return conn, nil
}

// this is called after conn has been marked closed, to notify pool to remove it from list
func (km *KubeManager) MarkDead(c *http2.ClientConn) {
	info, loaded := km.connLookup.Load(c)
	if !loaded {
		return
	}
	info.Kube.RemoveAgentConn(c, info)
	km.connLookup.Delete(c)
}
