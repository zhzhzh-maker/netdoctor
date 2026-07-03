package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen     string   `yaml:"listen" json:"listen"`
	Object     string   `yaml:"object" json:"object"`
	Protocols  []string `yaml:"protocols" json:"protocols"`
	Interface  string   `yaml:"interface" json:"interface"`
	EventLimit int      `yaml:"event_limit" json:"event_limit"`
	Web        bool     `yaml:"web" json:"web"`
}

func Default() Config {
	return Config{
		Listen:     "0.0.0.0:56789",
		Object:     "bin/netdoctor_bpfel.o",
		Protocols:  []string{"tcp", "udp"},
		EventLimit: 4096,
		Web:        true,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:56789"
	}
	if cfg.Object == "" {
		cfg.Object = "bin/netdoctor_bpfel.o"
	}
	if cfg.EventLimit <= 0 {
		cfg.EventLimit = 4096
	}
	return cfg, nil
}
