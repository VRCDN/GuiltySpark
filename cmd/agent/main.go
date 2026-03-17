package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
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

	// tee logs to stdout (journal via systemd) and an on-disk file.
	var logWriter io.Writer = os.Stdout
	if cfg.LogFile != "" {
		if mkErr := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o750); mkErr != nil {
			slog.Warn("could not create log directory", "path", filepath.Dir(cfg.LogFile), "error", mkErr)
		} else if f, openErr := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); openErr != nil {
			slog.Warn("could not open log file", "path", cfg.LogFile, "error", openErr)
		} else {
			defer f.Close()
			logWriter = io.MultiWriter(os.Stdout, f)
		}
	}
	log := logger.NewWithWriter(logWriter, cfg.LogFormat, cfg.LogLevel)
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
