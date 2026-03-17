package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/VRCDN/guiltyspark/internal/collector"
	"github.com/VRCDN/guiltyspark/internal/common/logger"
)

func main() {
	var (
		configFile   = flag.String("config", "configs/collector.yaml", "path to collector config file")
		rulesFile    = flag.String("rules", "configs/default_rules.yaml", "path to default rules YAML")
		printVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *printVersion {
		fmt.Println("guiltyspark-collector version dev")
		os.Exit(0)
	}

	// load config
	cfg, err := collector.LoadConfig(*configFile)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}
	if *rulesFile != "" {
		cfg.DefaultRulesFile = *rulesFile
	}

	// set up the logger
	log := logger.New(cfg.LogFormat, cfg.LogLevel)
	log.Info("starting guiltyspark-collector", "config", *configFile)

	// make sure the database directory exists
	if err := os.MkdirAll(dirOf(cfg.Database.Path), 0o750); err != nil {
		log.Error("create data directory", "error", err)
		os.Exit(1)
	}

	// build and wire up the collector
	col, err := collector.New(cfg, log.Logger)
	if err != nil {
		log.Error("initialise collector", "error", err)
		os.Exit(1)
	}
	defer col.Close()

	// seed default rules on first start
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := col.SeedRules(ctx, cfg.DefaultRulesFile); err != nil {
		log.Error("seed default rules", "error", err)
		// non-fatal — log and carry on
	}

	// listen for ctrl-c and SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := col.Run(ctx); err != nil {
		log.Error("collector exited", "error", err)
		os.Exit(1)
	}
	log.Info("guiltyspark-collector stopped")
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
