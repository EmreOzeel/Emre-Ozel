package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListAttackSessions returns attack sessions with optional filters.
func (h *Handler) ListAttackSessions(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	query := h.DB.Model(&models.AttackSession{})

	if v := c.Query("status"); v != "" {
		query = query.Where("status = ?", v)
	}
	if v := c.Query("source_ip"); v != "" {
		query = query.Where("source_ip = ?", v)
	}

	var sessions []models.AttackSession
	query.Order("last_activity desc").Limit(limit).Offset(offset).Find(&sessions)

	c.JSON(http.StatusOK, sessions)
}

// GetAttackSession returns a single attack session by ID.
func (h *Handler) GetAttackSession(c *gin.Context) {
	var session models.AttackSession
	if err := h.DB.First(&session, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "attack session not found"})
		return
	}

	c.JSON(http.StatusOK, session)
}
