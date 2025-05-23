package config

import (
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env        string `yaml:"env" env-default:"local"`
	DB         `yaml:"db"`
	HTTPServer `yaml:"http_server"`
}

type DB struct {
	DbURL string `yaml:"db_url" env-default:"postgres://postgres:postgres@localhost:5432/auth?sslmode=disable"`
}

type HTTPServer struct {
	Address      string        `yaml:"address" env-required:"true"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" env-default:"60s"`
	ReadTimeout  time.Duration `yaml:"read_timeout" env-default:"10s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env-default:"10s"`
}

func MustLoadConfig(configPath string) *Config {
	if _, err := os.Stat(configPath); err != nil {
		panic("config file not found")
	}

	config, err := loadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}

	return config
}

func loadConfig(path string) (*Config, error) {
	var config Config

	if err := cleanenv.ReadConfig(path, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
