package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListSuppressions handles GET /api/suppressions.
func (h *Handler) ListSuppressions(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var suppressions []models.SuppressionRule

	// Return the user's own rules plus all global rules.
	h.DB.Where(
		"is_active = ? AND (scope = ? OR created_by = ?)",
		true, "global", user.ID,
	).Order("created_at DESC").Find(&suppressions)

	c.JSON(http.StatusOK, suppressions)
}

// CreateSuppression handles POST /api/suppressions.
func (h *Handler) CreateSuppression(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var req struct {
		RuleID    *string    `json:"rule_id"`
		SrcIP     *string    `json:"src_ip"`
		DstIP     *string    `json:"dst_ip"`
		Scope     string     `json:"scope"`
		Reason    string     `json:"reason"`
		Note      *string    `json:"note"`
		ExpiresAt *time.Time `json:"expires_at"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	// Default scope to "user" if not provided.
	if req.Scope == "" {
		req.Scope = "user"
	}

	// Only admins can create global suppressions.
	if req.Scope == "global" && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only admins can create global suppressions"})
		return
	}

	suppression := models.SuppressionRule{
		Scope:     req.Scope,
		RuleID:    req.RuleID,
		SrcIP:     req.SrcIP,
		DstIP:     req.DstIP,
		Reason:    req.Reason,
		Note:      req.Note,
		IsActive:  true,
		ExpiresAt: req.ExpiresAt,
		CreatedBy: &user.ID,
	}

	if err := h.DB.Create(&suppression).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create suppression"})
		return
	}

	c.JSON(http.StatusCreated, suppression)
}

// UpdateSuppression handles PATCH /api/suppressions/:id.
func (h *Handler) UpdateSuppression(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var suppression models.SuppressionRule
	if err := h.DB.First(&suppression, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Suppression not found"})
		return
	}

	var req struct {
		IsActive  *bool      `json:"is_active"`
		Reason    *string    `json:"reason"`
		Note      *string    `json:"note"`
		ExpiresAt *time.Time `json:"expires_at"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	updates := map[string]interface{}{}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}
	if req.Reason != nil {
		updates["reason"] = *req.Reason
	}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if req.ExpiresAt != nil {
		updates["expires_at"] = *req.ExpiresAt
	}

	if len(updates) > 0 {
		h.DB.Model(&suppression).Updates(updates)
	}

	// Reload to return the updated record.
	h.DB.First(&suppression, uint(id))
	c.JSON(http.StatusOK, suppression)
}

// DeleteSuppression handles DELETE /api/suppressions/:id.
func (h *Handler) DeleteSuppression(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var suppression models.SuppressionRule
	if err := h.DB.First(&suppression, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Suppression not found"})
		return
	}

	h.DB.Delete(&suppression)
	c.Status(http.StatusNoContent)
}
