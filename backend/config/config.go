package config

import (
	"os"
)

type Config struct {
	JWTSecret   string
	DBPath      string
	UploadDir   string
	Port        string
	DefaultUser string
	DefaultPass string
}

func Load() *Config {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "pcap-analyzer-secret-key-change-in-production"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/data/pcap_analyzer.db"
	}

	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "/data/uploads"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	defaultUser := os.Getenv("DEFAULT_USER")
	if defaultUser == "" {
		defaultUser = "admin"
	}

	defaultPass := os.Getenv("DEFAULT_PASS")
	if defaultPass == "" {
		defaultPass = "admin123"
	}

	return &Config{
		JWTSecret:   jwtSecret,
		DBPath:      dbPath,
		UploadDir:   uploadDir,
		Port:        port,
		DefaultUser: defaultUser,
		DefaultPass: defaultPass,
	}
}
