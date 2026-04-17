package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB is the package-level database handle shared across the application.
var DB *gorm.DB

// Connect initialises the GORM database connection from the supplied config.
// It supports both SQLite and PostgreSQL based on the effective database URL.
func Connect(cfg *config.Config) error {
	url := cfg.EffectiveDBURL()

	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}

	var err error

	if strings.HasPrefix(url, "sqlite") {
		// sqlite:///path -> extract path
		dsn := strings.TrimPrefix(url, "sqlite:///")
		if dsn == "" {
			dsn = "pcap.db"
		}
		DB, err = gorm.Open(sqlite.Open(dsn), gormCfg)
		if err != nil {
			return fmt.Errorf("failed to open sqlite database: %w", err)
		}
		log.Info().Str("path", dsn).Msg("connected to SQLite database")
	} else {
		DB, err = gorm.Open(postgres.Open(url), gormCfg)
		if err != nil {
			return fmt.Errorf("failed to open postgres database: %w", err)
		}
		log.Info().Msg("connected to PostgreSQL database")
	}

	// Configure connection pool
	var sqlDB *sql.DB
	sqlDB, err = DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return nil
}

// AutoMigrate runs GORM auto-migration for all registered models.
func AutoMigrate() error {
	if DB == nil {
		return fmt.Errorf("database not connected; call Connect first")
	}
	log.Info().Msg("running database auto-migration")
	return DB.AutoMigrate(models.AllModels()...)
}

// SeedAdmin creates a default admin user if the users table is empty.
func SeedAdmin(cfg *config.Config) error {
	if DB == nil {
		return fmt.Errorf("database not connected; call Connect first")
	}

	var count int64
	if err := DB.Model(&models.User{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}
	if count > 0 {
		return nil // users already exist
	}

	hashed, err := bcrypt.GenerateFromPassword(
		[]byte(cfg.DefaultPass),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("failed to hash default password: %w", err)
	}

	admin := models.User{
		Username:       cfg.DefaultUser,
		HashedPassword: string(hashed),
		IsAdmin:        true,
	}
	if err := DB.Create(&admin).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.Info().
		Str("username", cfg.DefaultUser).
		Msg("seeded default admin user")

	return nil
}
