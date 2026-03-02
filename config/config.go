package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Security SecurityConfig `mapstructure:"security"`
}

type ServerConfig struct {
	Port int `mapstructure:"port"`
}

type StorageConfig struct {
	Path string `mapstructure:"path"`
}

type SecurityConfig struct {
	APIKey string `mapstructure:"api_key"`
}

var cfg *Config

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	viper.SetDefault("server.port", 8080)
	viper.SetDefault("storage.path", "./tokens")
	viper.SetDefault("security.api_key", "")

	viper.SetEnvPrefix("WEBAUTHN_MCP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	cfg = &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func Get() *Config {
	return cfg
}
