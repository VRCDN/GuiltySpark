package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/VRCDN/guiltyspark/internal/agent"
	"github.com/VRCDN/guiltyspark/internal/common/logger"
)

func main() {
	var (
		configFile   = flag.String("config", "configs/agent.yaml", "path to agent config file")
		printVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *printVersion {
		fmt.Println("guiltyspark-agent version dev")
		os.Exit(0)
	}

	cfg, err := agent.LoadConfig(*configFile)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	log := logger.New(cfg.LogFormat, cfg.LogLevel)
	log.Info("starting guiltyspark-agent", "config", *configFile)

	a, err := agent.New(cfg, log.Logger)
	if err != nil {
		log.Error("initialise agent", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := a.Run(ctx); err != nil {
		log.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("guiltyspark-agent stopped")
}
