package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListBaselines returns all IP baselines ordered by source_ip.
func (h *Handler) ListBaselines(c *gin.Context) {
	var baselines []models.IPBaseline
	h.DB.Order("source_ip").Find(&baselines)
	c.JSON(http.StatusOK, baselines)
}

// GetIPBaseline returns a single baseline by source_ip.
func (h *Handler) GetIPBaseline(c *gin.Context) {
	sourceIP := c.Param("source_ip")

	var baseline models.IPBaseline
	if err := h.DB.Where("source_ip = ?", sourceIP).First(&baseline).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "baseline not found"})
		return
	}

	c.JSON(http.StatusOK, baseline)
}
