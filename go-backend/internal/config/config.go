package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all application settings loaded from environment variables.
type Config struct {
	// Server
	Port int    // PORT, default 8000
	Env  string // ENV, default "development"

	// Database
	DatabaseURL string // DATABASE_URL
	DBPath      string // DB_PATH, default "/data/pcap.db"

	// Auth
	JWTSecret      string // JWT_SECRET
	JWTAlgorithm   string // always HS256
	JWTExpireHours int    // JWT_EXPIRE_HOURS, default 24
	DefaultUser    string // DEFAULT_USER, default "admin"
	DefaultPass    string // DEFAULT_PASS, default "admin123"

	// Upload
	UploadDir   string // UPLOAD_DIR, default "/data/uploads"
	MaxUploadMB int    // MAX_UPLOAD_MB, default 100

	// Analysis
	AnalysisTimeoutSec int    // ANALYSIS_TIMEOUT_SEC, default 300
	MaxAnalysesPerUser int    // MAX_ANALYSES_PER_USER, default 0
	TsharkPath         string // TSHARK_PATH, default "/usr/bin/tshark"

	// Collector
	CollectorEnabled       bool    // COLLECTOR_ENABLED, default false
	SyslogHost             string  // SYSLOG_HOST, default "0.0.0.0"
	SyslogPort             int     // SYSLOG_PORT, default 5514
	CollectorFlushInterval float64 // COLLECTOR_FLUSH_INTERVAL, default 1.0
	CollectorBatchSize     int     // COLLECTOR_BATCH_SIZE, default 100
	CollectorSourceID      string  // COLLECTOR_SOURCE_ID
	CollectorDeviceRole    string  // COLLECTOR_DEVICE_ROLE, default "unknown"
	SyslogMaxEPS           int     // SYSLOG_MAX_EPS, default 5000
	SyslogPerIPMaxEPS      int     // SYSLOG_PER_IP_MAX_EPS, default 500
	NetflowEnabled         bool    // NETFLOW_ENABLED, default false
	NetflowHost            string  // NETFLOW_HOST, default "0.0.0.0"
	NetflowPort            int     // NETFLOW_PORT, default 2055
	RetentionDays          int     // RETENTION_DAYS, default 7

	// GeoIP
	GeoIPCityDB           string // GEOIP_CITY_DB
	GeoIPASNDB            string // GEOIP_ASN_DB
	GeoIPEnabled          bool   // GEOIP_ENABLED, default true
	GeoIPUseIPAPIFallback bool   // GEOIP_USE_IPAPI_FALLBACK, default true

	// PCAP Trigger
	PcapTriggerEnabled       bool   // PCAP_TRIGGER_ENABLED, default false
	PcapTriggerInterface     string // PCAP_TRIGGER_INTERFACE
	PcapTriggerDuration      int    // PCAP_TRIGGER_DURATION, default 30
	PcapTriggerMaxConcurrent int    // PCAP_TRIGGER_MAX_CONCURRENT, default 5
	PcapTriggerDir           string // PCAP_TRIGGER_DIR, default "/data/triggered"

	// Packet Engine
	PacketEngineToken string // PACKET_ENGINE_TOKEN
	PacketEngineURL   string // PACKET_ENGINE_URL, default "http://packet-engine:8080"

	// Threat Feed
	ThreatFeedTimeout   int    // THREAT_FEED_TIMEOUT, default 30 (seconds)
	ThreatFeedUserAgent string // THREAT_FEED_USER_AGENT, default "pcap-analyzer/1.0"

	// GeoIP Rate Limiting
	GeoIPRateLimit    int // GEOIP_RATE_LIMIT, default 45 (requests per minute)
	GeoIPCacheTTLDays int // GEOIP_CACHE_TTL_DAYS, default 7

	// CORS
	AllowedOrigins string // ALLOWED_ORIGINS, default "*"

	// Feature Flags (migration)
	FeatureCollector  bool // FEATURE_COLLECTOR, default false
	FeatureCausalPath bool // FEATURE_CAUSAL_PATH, default false
	FeatureMonitorRun bool // FEATURE_MONITOR_RUN, default false
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		// Server
		Port: envInt("PORT", 8000),
		Env:  envStr("ENV", "development"),

		// Database
		DatabaseURL: envStr("DATABASE_URL", ""),
		DBPath:      envStr("DB_PATH", "/data/pcap.db"),

		// Auth
		JWTSecret:      envStr("JWT_SECRET", "pcap-analyzer-secret-change-in-production"),
		JWTAlgorithm:   "HS256",
		JWTExpireHours: envInt("JWT_EXPIRE_HOURS", 24),
		DefaultUser:    envStr("DEFAULT_USER", "admin"),
		DefaultPass:    envStr("DEFAULT_PASS", "admin123"),

		// Upload
		UploadDir:   envStr("UPLOAD_DIR", "/data/uploads"),
		MaxUploadMB: envInt("MAX_UPLOAD_MB", 100),

		// Analysis
		AnalysisTimeoutSec: envInt("ANALYSIS_TIMEOUT_SEC", 300),
		MaxAnalysesPerUser: envInt("MAX_ANALYSES_PER_USER", 0),
		TsharkPath:         envStr("TSHARK_PATH", "/usr/bin/tshark"),

		// Collector
		CollectorEnabled:       envBool("COLLECTOR_ENABLED", false),
		SyslogHost:             envStr("SYSLOG_HOST", "0.0.0.0"),
		SyslogPort:             envInt("SYSLOG_PORT", 5514),
		CollectorFlushInterval: envFloat("COLLECTOR_FLUSH_INTERVAL", 1.0),
		CollectorBatchSize:     envInt("COLLECTOR_BATCH_SIZE", 100),
		CollectorSourceID:      envStr("COLLECTOR_SOURCE_ID", ""),
		CollectorDeviceRole:    envStr("COLLECTOR_DEVICE_ROLE", "unknown"),
		SyslogMaxEPS:           envInt("SYSLOG_MAX_EPS", 5000),
		SyslogPerIPMaxEPS:      envInt("SYSLOG_PER_IP_MAX_EPS", 500),
		NetflowEnabled:         envBool("NETFLOW_ENABLED", false),
		NetflowHost:            envStr("NETFLOW_HOST", "0.0.0.0"),
		NetflowPort:            envInt("NETFLOW_PORT", 2055),
		RetentionDays:          envInt("RETENTION_DAYS", 7),

		// GeoIP
		GeoIPCityDB:           envStr("GEOIP_CITY_DB", ""),
		GeoIPASNDB:            envStr("GEOIP_ASN_DB", ""),
		GeoIPEnabled:          envBool("GEOIP_ENABLED", true),
		GeoIPUseIPAPIFallback: envBool("GEOIP_USE_IPAPI_FALLBACK", true),

		// PCAP Trigger
		PcapTriggerEnabled:       envBool("PCAP_TRIGGER_ENABLED", false),
		PcapTriggerInterface:     envStr("PCAP_TRIGGER_INTERFACE", ""),
		PcapTriggerDuration:      envInt("PCAP_TRIGGER_DURATION", 30),
		PcapTriggerMaxConcurrent: envInt("PCAP_TRIGGER_MAX_CONCURRENT", 5),
		PcapTriggerDir:           envStr("PCAP_TRIGGER_DIR", "/data/triggered"),

		// Packet Engine
		PacketEngineToken: envStr("PACKET_ENGINE_TOKEN", ""),
		PacketEngineURL:   envStr("PACKET_ENGINE_URL", "http://packet-engine:8080"),

		// Threat Feed
		ThreatFeedTimeout:   envInt("THREAT_FEED_TIMEOUT", 30),
		ThreatFeedUserAgent: envStr("THREAT_FEED_USER_AGENT", "pcap-analyzer/1.0"),

		// GeoIP Rate Limiting
		GeoIPRateLimit:    envInt("GEOIP_RATE_LIMIT", 45),
		GeoIPCacheTTLDays: envInt("GEOIP_CACHE_TTL_DAYS", 7),

		// CORS
		AllowedOrigins: envStr("ALLOWED_ORIGINS", "*"),

		// Feature Flags
		FeatureCollector:  envBool("FEATURE_COLLECTOR", false),
		FeatureCausalPath: envBool("FEATURE_CAUSAL_PATH", false),
		FeatureMonitorRun: envBool("FEATURE_MONITOR_RUN", false),
	}
}

// EffectiveDBURL returns the resolved database URL, falling back to SQLite.
func (c *Config) EffectiveDBURL() string {
	if c.DatabaseURL != "" {
		return c.DatabaseURL
	}
	return "sqlite:///" + c.DBPath
}

// ---------- helper functions ----------

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
