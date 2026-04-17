package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Interface     string        // PACKET_INTERFACE, e.g. "eth1"
	BPFFilter     string        // PACKET_BPF_FILTER, default ""
	BackendURL    string        // BACKEND_URL, e.g. "http://backend:8000"
	BackendToken  string        // BACKEND_TOKEN — JWT token for API auth
	BatchSize     int           // PACKET_BATCH_SIZE, default 100
	FlushInterval time.Duration // PACKET_FLUSH_INTERVAL, default 1s
	FlowTimeout   time.Duration // PACKET_FLOW_TIMEOUT, default 60s
	SnapLen       int32         // PACKET_SNAPLEN, default 65535
	Promiscuous   bool          // PACKET_PROMISCUOUS, default true
	WorkerCount   int           // PACKET_WORKERS, default 4
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Interface:     envStr("PACKET_INTERFACE", "eth1"),
		BPFFilter:     envStr("PACKET_BPF_FILTER", ""),
		BackendURL:    envStr("BACKEND_URL", "http://backend:8000"),
		BackendToken:  envStr("BACKEND_TOKEN", ""),
		BatchSize:     envInt("PACKET_BATCH_SIZE", 100),
		FlushInterval: envDuration("PACKET_FLUSH_INTERVAL", time.Second),
		FlowTimeout:   envDuration("PACKET_FLOW_TIMEOUT", 60*time.Second),
		SnapLen:       int32(envInt("PACKET_SNAPLEN", 65535)),
		Promiscuous:   envBool("PACKET_PROMISCUOUS", true),
		WorkerCount:   envInt("PACKET_WORKERS", 4),
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
