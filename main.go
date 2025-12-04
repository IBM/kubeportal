package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"kubeportal/agent"
	"kubeportal/hub"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/itzg/go-flagsfiller"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

var loggingLevel = new(slog.LevelVar)

type baseConfig struct {
	LogLevel string `default:"debug" validate:"oneof=debug info warn error" usage:"log level (debug, info, warn, error)"`
}

func (bc baseConfig) BaseConfig() baseConfig {
	return bc
}

type BaseConfig interface {
	BaseConfig() baseConfig
}

type hubConfig struct {
	baseConfig          `flatten:"true"`
	ClientListenPort    uint   `required:"true" validate:"port" usage:"port for client connections"`
	AgentListenPort     uint   `required:"true" validate:"port" usage:"port for agent connections"`
	StandbyConnsPerKube int    `default:"20" validate:"min=5" usage:"number of standby connections per kube"`
	ClientListenerCrt   string `usage:"path to TLS certificate file (uses self-signed if not provided)"`
	ClientListenerKey   string `usage:"path to TLS key file (uses self-signed if not provided)"`
}

type agentConfig struct {
	baseConfig     `flatten:"true"`
	HubURL         string `validate:"url" usage:"url of the hub server"`
	KubeIdentifier string `default:"kube.id" validate:"required" usage:"kubernetes cluster identifier"`
}

func parseConfig(subCommand string, cfg BaseConfig) error {
	filler := flagsfiller.New(flagsfiller.WithEnv(""))
	if err := filler.Fill(flag.CommandLine, cfg); err != nil {
		return err
	}
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Commands: kubeportal <hub|agent>\nUsage: kubeportal %s [options]\n", subCommand)
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := validator.New().Struct(cfg); err != nil {
		return err
	}

	switch cfg.BaseConfig().LogLevel {
	case "debug":
		loggingLevel.Set(slog.LevelDebug)
	case "info":
		loggingLevel.Set(slog.LevelInfo)
	case "warn":
		loggingLevel.Set(slog.LevelWarn)
	case "error":
		loggingLevel.Set(slog.LevelError)
	}
	slog.Debug("Config: " + fmt.Sprintf("%+v", cfg))
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: loggingLevel})))
	if len(os.Args) < 2 || (os.Args[1] != "hub" && os.Args[1] != "agent") {
		slog.Error("Usage: kubeportal <hub|agent>")
		os.Exit(1)
	}
	subCommand := os.Args[1]
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...) // Remove the subcommand from args before parsing

	switch subCommand {
	case "hub":
		var cfg hubConfig
		exitIfErr(parseConfig(subCommand, &cfg), "Failed to parse config")

		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.AgentListenPort))
		exitIfErr(err, "Failed to listen on agent mgr port")

		agentManager := hub.NewAgentManager(ctx, ln, cfg.StandbyConnsPerKube)
		rp := &httputil.ReverseProxy{
			Transport: &http.Transport{
				DialContext:         agentManager.GetConnForHost,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     50 * time.Second,
			},
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "http"
			},
		}
		clientLn, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ClientListenPort))
		exitIfErr(err, "Failed to listen on client port")
		tlsCert, err := generateTLSCert()
		exitIfErr(err, "Failed to generate TLS certificate")
		clientHandler, err := hub.NewClientHandler(rp)
		exitIfErr(err, "Failed to create client handler")
		clientSrv := &http.Server{
			Handler:     clientHandler,
			ReadTimeout: 15 * time.Second,
			IdleTimeout: 90 * time.Second,
			TLSConfig:   &tls.Config{Certificates: []tls.Certificate{tlsCert}},
		}
		go agentManager.Serve()
		exitIfErr(clientSrv.ServeTLS(clientLn, cfg.ClientListenerCrt, cfg.ClientListenerKey), "Failed to start client server")
	case "agent":
		var cfg agentConfig
		exitIfErr(parseConfig(subCommand, &cfg), "Failed to parse config")

		hubURL, err := url.Parse(cfg.HubURL)
		exitIfErr(err, "Failed to parse hub url")

		k8sConfig, err := rest.InClusterConfig()
		exitIfErr(err, "Failed to create in-cluster Kubernetes config")

		k8sURL, err := url.Parse(k8sConfig.Host)
		exitIfErr(err, "Failed to parse k8s url")

		k8sCaPool, err := certutil.NewPool(k8sConfig.TLSClientConfig.CAFile)
		exitIfErr(err, "Failed to create in-cluster k8s cert pool")

		k8sProxy := agent.NewK8sProxy(k8sURL, k8sCaPool, k8sConfig)
		k8sProxy.Start()
		agent.NewAgent(ctx, k8sProxy, cfg.KubeIdentifier, *hubURL).Run()
	}
}

func exitIfErr(err error, msg string) {
	if err != nil && err != http.ErrServerClosed {
		slog.With("error", err).Error(msg)
		os.Exit(1)
	}
}

func generateTLSCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(5 * 24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
