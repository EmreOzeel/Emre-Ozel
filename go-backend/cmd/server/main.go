package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/api/handlers"
	"github.com/emreozeel/pcap-analyzer/backend/internal/api/router"
	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/database"
)

func main() {
	// 1. Load config
	cfg := config.Load()

	// 2. Connect database + AutoMigrate
	if err := database.Connect(cfg); err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	if err := database.AutoMigrate(); err != nil {
		log.Fatalf("auto-migrate failed: %v", err)
	}

	// 3. Init auth
	auth.Init(cfg)

	// 4. Seed admin user
	if err := database.SeedAdmin(cfg); err != nil {
		log.Printf("warning: seed admin failed: %v", err)
	}

	// 4. Create handler
	h := handlers.New(database.DB, cfg)

	// 5. Setup router
	r := router.Setup(database.DB, cfg, h)

	// 6. Start HTTP server with graceful shutdown
	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{Addr: addr, Handler: r}

	go func() {
		log.Printf("go-backend listening on %s (env=%s)", addr, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// 7. Handle SIGINT/SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
	log.Println("shutdown complete")
}
