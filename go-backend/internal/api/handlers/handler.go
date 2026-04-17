package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"gorm.io/gorm"
)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	DB  *gorm.DB
	Cfg *config.Config
}

// New creates a Handler with database and config references.
func New(db *gorm.DB, cfg *config.Config) *Handler {
	return &Handler{DB: db, Cfg: cfg}
}

// Health returns a simple health check response.
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "3.0.0"})
}

// NotImplemented returns a 501 Not Implemented response.
// Used as a placeholder for routes that are not yet built.
func (h *Handler) NotImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "this endpoint is not yet available in the Go backend",
	})
}
