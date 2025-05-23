package main

import (
	"auth_service/internal/config"
	"flag"
	"log"
	"log/slog"
	"os"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	//PARSE ARGS
	var configPath string
	flag.StringVar(&configPath, "config", "", "")

	flag.Parse()
	if configPath == "" {
		log.Fatal("failed get config path from flags")
	}

	cfg := config.MustLoadConfig(configPath)

	lgr := setupLogger(cfg.Env)
	lgr.Info("started auth service")

	//INIT LOGGER

	//INIT DB

	//INIT SERVER
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}
