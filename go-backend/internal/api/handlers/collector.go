package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CollectorStatus handles GET /api/collector/status.
func (h *Handler) CollectorStatus(c *gin.Context) {
	if h.CollectorSvc == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false, "running": false})
		return
	}
	c.JSON(http.StatusOK, h.CollectorSvc.Stats())
}
