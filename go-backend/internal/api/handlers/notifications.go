package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListNotifications handles GET /api/notifications.
func (h *Handler) ListNotifications(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	unreadOnly := c.DefaultQuery("unread_only", "false")

	q := h.DB.Model(&models.Notification{}).Where("user_id = ?", user.ID)

	if unreadOnly == "true" || unreadOnly == "1" {
		q = q.Where("read_at IS NULL")
	}

	var notifications []models.Notification
	q.Order("created_at DESC").Limit(limit).Find(&notifications)

	c.JSON(http.StatusOK, notifications)
}

// UnreadNotificationCount handles GET /api/notifications/unread-count.
func (h *Handler) UnreadNotificationCount(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var count int64
	h.DB.Model(&models.Notification{}).
		Where("user_id = ? AND read_at IS NULL", user.ID).
		Count(&count)

	c.JSON(http.StatusOK, gin.H{"unread": count})
}

// MarkNotificationsRead handles POST /api/notifications/mark-read.
func (h *Handler) MarkNotificationsRead(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var req struct {
		IDs []uint `json:"ids"`
	}
	// Bind JSON; empty body or {} is valid (marks all as read).
	c.ShouldBindJSON(&req)

	now := time.Now().UTC()
	q := h.DB.Model(&models.Notification{}).
		Where("user_id = ? AND read_at IS NULL", user.ID)

	if len(req.IDs) > 0 {
		q = q.Where("id IN ?", req.IDs)
	}

	result := q.Update("read_at", now)

	c.JSON(http.StatusOK, gin.H{"marked": result.RowsAffected})
}
