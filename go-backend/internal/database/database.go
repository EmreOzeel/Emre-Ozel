package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB is the package-level database handle shared across the application.
var DB *gorm.DB

// Connect initialises the GORM database connection from the supplied config.
func Connect(cfg *config.Config) error {
	url := cfg.EffectiveDBURL()

	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}

	var err error
	DB, err = gorm.Open(postgres.Open(url), gormCfg)
	if err != nil {
		return fmt.Errorf("failed to open postgres database: %w", err)
	}
	log.Info().Msg("connected to PostgreSQL database")

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

// ConnectWithDB allows injecting a pre-configured *gorm.DB (used by tests).
func ConnectWithDB(db *gorm.DB) {
	DB = db
}

// AutoMigrate runs GORM auto-migration for all registered models.
// Errors from constraint management on existing tables are logged but
// not fatal — the Python backend may have created tables with different
// constraint naming conventions.
func AutoMigrate() error {
	if DB == nil {
		return fmt.Errorf("database not connected; call Connect first")
	}
	log.Info().Msg("running database auto-migration")
	for _, model := range models.AllModels() {
		if err := DB.AutoMigrate(model); err != nil {
			log.Warn().Err(err).Msgf("auto-migrate warning for %T (continuing)", model)
		}
	}
	return nil
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
