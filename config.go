package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const defaultBytebeat = "t*(((t>>12)|(t>>8))&(63&(t>>4)))"

type BoopConfig struct {
	Bytebeat string  `json:"bytebeat"`
	Duration int     `json:"duration_ms"` // Duration in milliseconds
	Volume   float64 `json:"volume"`      // 0.0 to 1.0
}

func getConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "boop", "config.json")
}

func loadConfig() BoopConfig {
	config := BoopConfig{
		Bytebeat: defaultBytebeat,
		Duration: 150,
		Volume:   0.5,
	}

	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Config doesn't exist, create default
		saveDefaultConfig()
		return config
	}

	json.Unmarshal(data, &config)
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

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}
