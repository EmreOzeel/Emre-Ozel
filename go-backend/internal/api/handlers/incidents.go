package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListLiveIncidents handles GET /api/live-incidents.
func (h *Handler) ListLiveIncidents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := h.DB.Model(&models.LiveIncident{})

	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.Query("severity"); v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	if v := c.Query("behavior_type"); v != "" {
		q = q.Where("behavior_type = ?", v)
	}

	var total int64
	q.Count(&total)

	var incidents []models.LiveIncident
	q.Order("last_seen DESC").Limit(limit).Offset(offset).Find(&incidents)

	c.JSON(http.StatusOK, gin.H{
		"incidents": incidents,
		"total":     total,
	})
}

// GetLiveIncident handles GET /api/live-incidents/:id.
func (h *Handler) GetLiveIncident(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var incident models.LiveIncident
	if err := h.DB.First(&incident, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Incident not found"})
		return
	}

	c.JSON(http.StatusOK, incident)
}

// UpdateLiveIncidentStatus handles PUT /api/live-incidents/:id/status.
func (h *Handler) UpdateLiveIncidentStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var incident models.LiveIncident
	if err := h.DB.First(&incident, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Incident not found"})
		return
	}

	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "status is required"})
		return
	}

	validStatuses := map[string]bool{
		"open":          true,
		"investigating": true,
		"resolved":      true,
		"dismissed":     true,
	}
	if !validStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid status. Must be one of: open, investigating, resolved, dismissed"})
		return
	}

	h.DB.Model(&incident).Update("status", req.Status)
	h.DB.First(&incident, uint(id))

	c.JSON(http.StatusOK, incident)
}

// GetLiveIncidentPcaps handles GET /api/live-incidents/:id/pcaps.
func (h *Handler) GetLiveIncidentPcaps(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var incident models.LiveIncident
	if err := h.DB.First(&incident, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Incident not found"})
		return
	}

	// Parse linked_pcap_analysis_ids JSON field.
	var pcapIDs []string
	if incident.LinkedPcapAnalysisIDs != nil && *incident.LinkedPcapAnalysisIDs != "" {
		if err := json.Unmarshal([]byte(*incident.LinkedPcapAnalysisIDs), &pcapIDs); err != nil {
			pcapIDs = []string{}
		}
	} else {
		pcapIDs = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"incident_id":        incident.ID,
		"pcap_analysis_ids":  pcapIDs,
		"pcap_trigger_count": incident.PcapTriggerCount,
	})
}
