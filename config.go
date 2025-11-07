package main

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const defaultBytebeat = "t*(((t>>12)|(t>>8))&(63&(t>>4)))"

type BoopConfig struct {
	Bytebeat string  `toml:"bytebeat"`
	Duration int     `toml:"duration_ms"`
	Volume   float64 `toml:"volume"`
}

func getConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "boop", "config.toml")
}

func loadConfig() BoopConfig {
	config := BoopConfig{
		Bytebeat: defaultBytebeat,
		Duration: 150,
		Volume:   0.5,
	}

	configPath := getConfigPath()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		saveDefaultConfig()
		return config
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return config
	}

	toml.Unmarshal(data, &config)
	return config
}

func saveDefaultConfig() error {
	config := BoopConfig{
		Bytebeat: defaultBytebeat,
		Duration: 150,
		Volume:   0.5,
	}

	configPath := getConfigPath()
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return toml.NewEncoder(f).Encode(config)
}
