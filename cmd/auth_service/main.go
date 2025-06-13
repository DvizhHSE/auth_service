package main

import (
	"auth_service/internal/config"
	"auth_service/internal/handler"
	"auth_service/internal/service"
	"auth_service/internal/storage"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/joho/godotenv"
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

	err := godotenv.Load()
	if err != nil {
		log.Println("failed to load .env file %v", err)
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("db url can't be empty string")
	}

	cfg := config.MustLoadConfig(configPath)

	lgr := setupLogger(cfg.Env)

	lgr.Info("started auth service")

	conn, err := storage.NewPostgresStorage(dbURL)
	if err != nil {
		log.Fatalf("failed to connect to db, err: %w", err)
	}

	serviceLayer := service.NewService(conn)

	hand := handler.NewHandler(serviceLayer, lgr)

	router := hand.InitRoutes()

	if err := http.ListenAndServe(cfg.Address, router); err != nil {
		log.Fatalf("error while running server %s", err.Error())
	}
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
