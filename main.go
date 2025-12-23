package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"kubeportal/agent"
	"kubeportal/hub"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-playground/validator/v10"
	"github.com/itzg/go-flagsfiller"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	baseConfig        `flatten:"true"`
	ClientListenPort  uint   `required:"true" validate:"port" usage:"port for client connections"`
	AgentListenPort   uint   `required:"true" validate:"port" usage:"port for agent connections"`
	OpenidCACertsPath string `default:"/tmp/certs" usage:"path to directory containing CA certs for loading jwks, can be multiple per file"`
	ClientListenerCrt string `usage:"path to TLS certificate file (uses self-signed if not provided)"`
	ClientListenerKey string `usage:"path to TLS key file (uses self-signed if not provided)"`
}

type agentConfig struct {
	baseConfig     `flatten:"true"`
	HubAddress     string `validate:"hostname_port" usage:"address of the hub server"`
	InsecureHub    bool   `usage:"connect to hub server without tls, mainly for debugging"`
	KubeIdentifier string `default:"kube.id" validate:"required" usage:"kubernetes cluster identifier"`
}

func parseConfig(cfg BaseConfig) error {
	fs := &flag.FlagSet{}
	fs.SetOutput(io.Discard)
	filler := flagsfiller.New(flagsfiller.WithEnv(""))
	if err := filler.Fill(fs, cfg); err != nil {
		fs = &flag.FlagSet{} // need to do this as otherwise only a partial usage is printed
		flagsfiller.New(flagsfiller.NoSetFromEnv()).Fill(fs, cfg)
		return err
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
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

func printUsageAndExit(cfg BaseConfig, subCommand string, err error) {
	if err != nil {
		fmt.Println("Config validation errors:")
		fmt.Println(err)
	}
	fmt.Printf("\nCommands: kubeportal <hub|agent>\n\nUsage: kubeportal %s [options]\n", subCommand)
	// recreate flagset because flagsfiller exits early on env parse errors
	os.Clearenv()
	fs := &flag.FlagSet{}
	flagsfiller.New(flagsfiller.WithEnv("")).Fill(fs, cfg)
	fs.PrintDefaults()
	os.Exit(2)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: loggingLevel})))
	exitWithError := slog.NewLogLogger(slog.Default().Handler(), slog.LevelError).Fatal
	if len(os.Args) < 2 || (os.Args[1] != "hub" && os.Args[1] != "agent") {
		fmt.Println("Usage: kubeportal <hub|agent>")
		os.Exit(2)
	}
	subCommand := os.Args[1]
	os.Args = append([]string{"kubeportal"}, os.Args[2:]...) // Remove the subcommand from args before parsing

	// serve metrics
	metricsLn, err := net.Listen("tcp", ":9090")
	if err != nil {
		exitWithError("Failed to listen on metrics port: ", err)
	}
	go http.Serve(metricsLn, promhttp.Handler())

	switch subCommand {
	case "hub":
		var cfg hubConfig
		if err := parseConfig(&cfg); err != nil {
			printUsageAndExit(&hubConfig{}, subCommand, err)
		}
		if err := runHub(ctx, cfg); err != nil {
			exitWithError("Error starting hub: ", err)
		}
	case "agent":
		var cfg agentConfig
		if err := parseConfig(&cfg); err != nil {
			printUsageAndExit(&agentConfig{}, subCommand, err)
		}
		if err := runAgent(ctx, cfg); err != nil {
			exitWithError("Error starting agent: ", err)
		}
	}
}

func runHub(ctx context.Context, cfg hubConfig) error {
	agentLn, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.AgentListenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on agent mgr port: %w", err)
	}
	clientLn, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ClientListenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on client port: %w", err)
	}
	clientManager, tr, err := hub.NewClientManager(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client manager: %w", err)
	}
	kubeManager, err := hub.NewKubeManager(cfg.OpenidCACertsPath, tr)
	if err != nil {
		return fmt.Errorf("failed to initialize kube manager: %w", err)
	}
	clientManager.SetConnPool(kubeManager)
	agentManager := hub.NewAgentManager(agentLn, kubeManager)

	go kubeManager.Run()
	go agentManager.Run()
	// if the crt and key below are "", a default self signed cert is used
	go clientManager.Run(clientLn, cfg.ClientListenerCrt, cfg.ClientListenerKey)
	<-ctx.Done()
	clientManager.Shutdown()
	return nil
}

func runAgent(ctx context.Context, cfg agentConfig) error {
	k8sProxy, err := agent.NewK8sProxy()
	if err != nil {
		return fmt.Errorf("failed to create k8s proxy: %w", err)
	}
	a, err := agent.NewAgent(ctx, k8sProxy, cfg.KubeIdentifier, cfg.HubAddress, cfg.InsecureHub)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}
	go k8sProxy.Run()
	go a.Run()
	<-ctx.Done()
	k8sProxy.Shutdown()
	return nil
}
