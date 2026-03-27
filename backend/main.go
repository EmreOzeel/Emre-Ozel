package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"pcap-analyzer/config"
	"pcap-analyzer/handlers"
	"pcap-analyzer/middleware"
	"pcap-analyzer/models"
)

func main() {
	cfg := config.Load()

	// Ensure data directory exists
	if err := os.MkdirAll("/data", 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize DB
	db, err := gorm.Open(sqlite.Open(cfg.DBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto-migrate
	if err := db.AutoMigrate(&models.User{}, &models.Analysis{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Seed default admin user if no users exist
	var count int64
	db.Model(&models.User{}).Count(&count)
	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte(cfg.DefaultPass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to hash default password: %v", err)
		}
		db.Create(&models.User{
			Username:     cfg.DefaultUser,
			PasswordHash: string(hash),
		})
		log.Printf("Created default user: %s / %s", cfg.DefaultUser, cfg.DefaultPass)
	}

	// Setup Gin
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
	}))

	// Handlers
	authHandler := handlers.NewAuthHandler(db, cfg.JWTSecret)
	analysisHandler := handlers.NewAnalysisHandler(db, cfg.UploadDir)

	// Public routes
	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
		}
	}

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.AuthRequired(cfg.JWTSecret))
	{
		// Auth
		protected.GET("/auth/me", authHandler.Me)

		// Analyses
		analyses := protected.Group("/analyses")
		{
			analyses.POST("", analysisHandler.Upload)
			analyses.GET("", analysisHandler.List)
			analyses.GET("/:id", analysisHandler.Get)
			analyses.DELETE("/:id", analysisHandler.Delete)
		}
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	log.Printf("PCAP Analyzer backend starting on port %s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
