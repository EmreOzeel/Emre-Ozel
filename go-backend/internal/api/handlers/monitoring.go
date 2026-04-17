package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ---------- Monitor CRUD ----------

// ListMonitors handles GET /api/path-monitors.
func (h *Handler) ListMonitors(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var monitors []models.MonitoredPath
	h.DB.Where("owner_user_id = ?", user.ID).
		Order("updated_at DESC").
		Find(&monitors)

	c.JSON(http.StatusOK, monitors)
}

// CreateMonitor handles POST /api/path-monitors.
func (h *Handler) CreateMonitor(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var m models.MonitoredPath
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	m.OwnerUserID = user.ID

	if err := h.DB.Create(&m).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create monitor"})
		return
	}

	c.JSON(http.StatusCreated, m)
}

// GetMonitor handles GET /api/path-monitors/:id.
func (h *Handler) GetMonitor(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var m models.MonitoredPath
	if err := h.DB.First(&m, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Monitor not found"})
		return
	}

	if m.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Monitor not found"})
		return
	}

	c.JSON(http.StatusOK, m)
}

// UpdateMonitor handles PUT /api/path-monitors/:id.
func (h *Handler) UpdateMonitor(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var m models.MonitoredPath
	if err := h.DB.First(&m, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Monitor not found"})
		return
	}

	if m.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only the owner or an admin can update this monitor"})
		return
	}

	var req struct {
		ScheduleIntervalMinutes *int  `json:"schedule_interval_minutes"`
		Enabled                 *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	updates := map[string]interface{}{}
	if req.ScheduleIntervalMinutes != nil {
		updates["schedule_interval_minutes"] = *req.ScheduleIntervalMinutes
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if len(updates) > 0 {
		h.DB.Model(&m).Updates(updates)
	}

	h.DB.First(&m, uint(id))
	c.JSON(http.StatusOK, m)
}

// DeleteMonitor handles DELETE /api/path-monitors/:id.
func (h *Handler) DeleteMonitor(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var m models.MonitoredPath
	if err := h.DB.First(&m, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Monitor not found"})
		return
	}

	if m.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only the owner or an admin can delete this monitor"})
		return
	}

	h.DB.Delete(&m)
	c.Status(http.StatusNoContent)
}

// ---------- RunMonitor ----------

// RunMonitor handles POST /api/path-monitors/:id/run.
func (h *Handler) RunMonitor(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "Monitor execution engine not yet ported",
	})
}

// ---------- MonitorTick ----------

// MonitorTick handles POST /api/path-monitors/tick.
func (h *Handler) MonitorTick(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Admin only"})
		return
	}

	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "Monitor execution engine not yet ported",
	})
}

// ---------- Monitor History ----------

// ListMonitorHistory handles GET /api/path-monitors/:id/history.
func (h *Handler) ListMonitorHistory(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	var runs []models.MonitoredPathRun
	h.DB.Where("monitored_path_id = ?", uint(id)).
		Order("run_at DESC").
		Limit(limit).
		Find(&runs)

	c.JSON(http.StatusOK, runs)
}

// ---------- MonitorTrend ----------

// MonitorTrend handles GET /api/path-monitors/:id/trend.
func (h *Handler) MonitorTrend(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	monitorID := uint(id)

	// Total runs.
	var totalRuns int64
	h.DB.Model(&models.MonitoredPathRun{}).Where("monitored_path_id = ?", monitorID).Count(&totalRuns)

	// Severity distribution.
	type sevCount struct {
		DriftSeverity string `json:"drift_severity"`
		Count         int    `json:"count"`
	}
	var sevCounts []sevCount
	h.DB.Model(&models.MonitoredPathRun{}).
		Select("drift_severity, COUNT(*) as count").
		Where("monitored_path_id = ?", monitorID).
		Group("drift_severity").
		Scan(&sevCounts)

	severityDist := map[string]int{}
	for _, sc := range sevCounts {
		severityDist[sc.DriftSeverity] = sc.Count
	}

	// Outcome distribution.
	type outcomeCount struct {
		Outcome string `json:"outcome"`
		Count   int    `json:"count"`
	}
	var outCounts []outcomeCount
	h.DB.Model(&models.MonitorOutcome{}).
		Select("outcome, COUNT(*) as count").
		Where("monitored_path_id = ?", monitorID).
		Group("outcome").
		Scan(&outCounts)

	outcomeDist := map[string]int{}
	for _, oc := range outCounts {
		outcomeDist[oc.Outcome] = oc.Count
	}

	// Average confidence.
	var avgConfidence float64
	h.DB.Model(&models.MonitoredPathRun{}).
		Select("COALESCE(AVG(path_confidence_score), 0)").
		Where("monitored_path_id = ?", monitorID).
		Scan(&avgConfidence)

	// Confidence trend: last 10 runs.
	var recentRuns []models.MonitoredPathRun
	h.DB.Where("monitored_path_id = ?", monitorID).
		Order("run_at DESC").
		Limit(10).
		Find(&recentRuns)

	confidenceTrend := make([]int, 0, len(recentRuns))
	for i := len(recentRuns) - 1; i >= 0; i-- {
		confidenceTrend = append(confidenceTrend, recentRuns[i].PathConfidenceScore)
	}

	// Last drift severity from most recent run.
	var lastDriftSeverity *string
	if len(recentRuns) > 0 {
		lastDriftSeverity = &recentRuns[0].DriftSeverity
	}

	c.JSON(http.StatusOK, gin.H{
		"total_runs":           totalRuns,
		"severity_distribution": severityDist,
		"outcome_distribution": outcomeDist,
		"avg_confidence":       avgConfidence,
		"confidence_trend":     confidenceTrend,
		"last_drift_severity":  lastDriftSeverity,
	})
}

// ---------- Monitor Outcomes ----------

// CreateOutcome handles POST /api/path-monitors/:id/outcomes.
func (h *Handler) CreateOutcome(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var req struct {
		Outcome           string  `json:"outcome"`
		RootCauseType     *string `json:"root_cause_type"`
		Note              *string `json:"note"`
		SignalDriversJSON *string `json:"signal_drivers_json"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	validOutcomes := map[string]bool{
		"issue_confirmed":     true,
		"false_positive":      true,
		"transient_issue":     true,
		"root_cause_identified": true,
	}
	if !validOutcomes[req.Outcome] {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid outcome. Must be one of: issue_confirmed, false_positive, transient_issue, root_cause_identified"})
		return
	}

	outcome := models.MonitorOutcome{
		MonitoredPathID:   uint(id),
		Outcome:           req.Outcome,
		RootCauseType:     req.RootCauseType,
		Note:              req.Note,
		SignalDriversJSON: req.SignalDriversJSON,
		AnalystID:         &user.ID,
	}

	if err := h.DB.Create(&outcome).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create outcome"})
		return
	}

	c.JSON(http.StatusCreated, outcome)
}

// ListOutcomes handles GET /api/path-monitors/:id/outcomes.
func (h *Handler) ListOutcomes(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var outcomes []models.MonitorOutcome
	h.DB.Where("monitored_path_id = ?", uint(id)).
		Order("created_at DESC").
		Find(&outcomes)

	c.JSON(http.StatusOK, outcomes)
}

// GetLearnings handles GET /api/path-monitors/:id/learnings.
func (h *Handler) GetLearnings(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "Learnings engine not yet ported",
	})
}

// ---------- Monitor Suppressions ----------

// CreateMonitorSuppression handles POST /api/path-monitors/:id/suppressions.
func (h *Handler) CreateMonitorSuppression(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var req struct {
		Kind   string     `json:"kind"`
		Value  *string    `json:"value"`
		Reason *string    `json:"reason"`
		Until  *time.Time `json:"until"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	validKinds := map[string]bool{
		"mute": true, "snooze": true, "impairment": true, "severity": true,
	}
	if !validKinds[req.Kind] {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid kind. Must be one of: mute, snooze, impairment, severity"})
		return
	}

	suppression := models.MonitorSuppression{
		MonitoredPathID: uint(id),
		Kind:            req.Kind,
		Value:           req.Value,
		Reason:          req.Reason,
		Enabled:         true,
		Until:           req.Until,
		CreatedBy:       &user.ID,
	}

	if err := h.DB.Create(&suppression).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create suppression"})
		return
	}

	c.JSON(http.StatusCreated, suppression)
}

// ListMonitorSuppressions handles GET /api/path-monitors/:id/suppressions.
func (h *Handler) ListMonitorSuppressions(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var suppressions []models.MonitorSuppression
	h.DB.Where("monitored_path_id = ? AND enabled = ?", uint(id), true).
		Order("created_at DESC").
		Find(&suppressions)

	c.JSON(http.StatusOK, suppressions)
}

// DeleteMonitorSuppression handles DELETE /api/path-monitors/:id/suppressions/:sid.
func (h *Handler) DeleteMonitorSuppression(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	sid, err := strconv.ParseUint(c.Param("sid"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid suppression ID"})
		return
	}

	var suppression models.MonitorSuppression
	if err := h.DB.First(&suppression, uint(sid)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Suppression not found"})
		return
	}

	h.DB.Delete(&suppression)
	c.Status(http.StatusNoContent)
}

// ---------- Monitor Baseline ----------

// GetMonitorBaseline handles GET /api/path-monitors/:id/baseline.
func (h *Handler) GetMonitorBaseline(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var m models.MonitoredPath
	if err := h.DB.First(&m, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Monitor not found"})
		return
	}

	if m.BaselineJSON != nil && *m.BaselineJSON != "" {
		var parsed interface{}
		if err := json.Unmarshal([]byte(*m.BaselineJSON), &parsed); err == nil {
			c.JSON(http.StatusOK, parsed)
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{})
}

// UpdateMonitorBaseline handles PUT /api/path-monitors/:id/baseline.
func (h *Handler) UpdateMonitorBaseline(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var m models.MonitoredPath
	if err := h.DB.First(&m, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Monitor not found"})
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Failed to read request body"})
		return
	}

	// Validate it is valid JSON.
	var check interface{}
	if err := json.Unmarshal(body, &check); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Request body must be valid JSON"})
		return
	}

	raw := string(body)
	h.DB.Model(&m).Update("baseline_json", raw)

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ---------- SystemInsights ----------

// SystemInsights handles GET /api/system-insights.
func (h *Handler) SystemInsights(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "System insights not yet ported",
	})
}
