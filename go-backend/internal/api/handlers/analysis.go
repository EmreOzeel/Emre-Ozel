package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// allowedExtensions returns the set of valid PCAP file extensions.
var allowedExtensions = map[string]bool{
	".pcap":   true,
	".pcapng": true,
	".cap":    true,
}

// CreateAnalysis handles POST /api/analyses.
func (h *Handler) CreateAnalysis(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "File upload required (field name: file)"})
		return
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !allowedExtensions[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid file extension. Allowed: .pcap, .pcapng, .cap"})
		return
	}

	// Ensure upload directory exists.
	if err := os.MkdirAll(h.Cfg.UploadDir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create upload directory"})
		return
	}

	id := uuid.New().String()
	savedName := id + ext
	savedPath := filepath.Join(h.Cfg.UploadDir, savedName)

	if err := c.SaveUploadedFile(file, savedPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to save uploaded file"})
		return
	}

	analysis := models.Analysis{
		ID:       id,
		UserID:   user.ID,
		Filename: file.Filename,
		FilePath: &savedPath,
		Status:   "pending",
	}

	if err := h.DB.Create(&analysis).Error; err != nil {
		// Clean up the saved file on DB failure.
		os.Remove(savedPath)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create analysis record"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"id":     analysis.ID,
		"status": analysis.Status,
	})
}

// ListAnalyses handles GET /api/analyses.
func (h *Handler) ListAnalyses(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	status := c.Query("status")

	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := h.DB.Model(&models.Analysis{})
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if v := c.Query("workflow_state"); v != "" {
		q = q.Where("workflow_state = ?", v)
	}

	user := auth.CurrentUser(c)
	if c.Query("assigned_to_me") == "true" && user != nil {
		q = q.Where("assigned_user_id = ?", user.ID)
	}

	var analyses []models.Analysis
	q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&analyses)

	// Build summaries without result_json.
	type AnalysisSummary struct {
		ID            string  `json:"id"`
		UserID        uint    `json:"user_id"`
		Filename      string  `json:"filename"`
		Status        string  `json:"status"`
		CurrentStage  *string `json:"current_stage,omitempty"`
		ProgressPct   int     `json:"progress_pct"`
		PacketCount   int     `json:"packet_count"`
		IssueCount    int     `json:"issue_count"`
		CriticalCount int     `json:"critical_count"`
		CreatedAt     string  `json:"created_at"`
	}

	summaries := make([]AnalysisSummary, 0, len(analyses))
	for _, a := range analyses {
		summaries = append(summaries, AnalysisSummary{
			ID:            a.ID,
			UserID:        a.UserID,
			Filename:      a.Filename,
			Status:        a.Status,
			CurrentStage:  a.CurrentStage,
			ProgressPct:   a.ProgressPct,
			PacketCount:   a.PacketCount,
			IssueCount:    a.IssueCount,
			CriticalCount: a.CriticalCount,
			CreatedAt:     a.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	c.JSON(http.StatusOK, summaries)
}

// GetAnalysis handles GET /api/analyses/:id.
func (h *Handler) GetAnalysis(c *gin.Context) {
	id := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Analysis not found"})
		return
	}

	resp := gin.H{
		"id":             analysis.ID,
		"user_id":        analysis.UserID,
		"filename":       analysis.Filename,
		"status":         analysis.Status,
		"current_stage":  analysis.CurrentStage,
		"progress_pct":   analysis.ProgressPct,
		"packet_count":   analysis.PacketCount,
		"issue_count":    analysis.IssueCount,
		"critical_count": analysis.CriticalCount,
		"error":          analysis.Error,
		"created_at":     analysis.CreatedAt,
		"started_at":     analysis.StartedAt,
		"finished_at":    analysis.FinishedAt,
		"workflow_state": analysis.WorkflowState,
		"assigned_user_id": analysis.AssignedUserID,
	}

	// Parse result_json into a proper JSON object if present.
	if analysis.ResultJSON != nil && *analysis.ResultJSON != "" {
		var parsed interface{}
		if err := json.Unmarshal([]byte(*analysis.ResultJSON), &parsed); err == nil {
			resp["result"] = parsed
		} else {
			resp["result_json"] = analysis.ResultJSON
		}
	}

	c.JSON(http.StatusOK, resp)
}

// GetAnalysisStatus handles GET /api/analyses/:id/status.
func (h *Handler) GetAnalysisStatus(c *gin.Context) {
	id := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Analysis not found"})
		return
	}

	errStr := ""
	if analysis.Error != nil {
		errStr = *analysis.Error
	}
	stageStr := ""
	if analysis.CurrentStage != nil {
		stageStr = *analysis.CurrentStage
	}

	c.JSON(http.StatusOK, gin.H{
		"id":            analysis.ID,
		"status":        analysis.Status,
		"current_stage": stageStr,
		"progress_pct":  analysis.ProgressPct,
		"error":         errStr,
	})
}

// DeleteAnalysis handles DELETE /api/analyses/:id.
func (h *Handler) DeleteAnalysis(c *gin.Context) {
	id := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Analysis not found"})
		return
	}

	// Delete the file if it exists.
	if analysis.FilePath != nil && *analysis.FilePath != "" {
		os.Remove(*analysis.FilePath)
	}

	h.DB.Delete(&analysis)
	c.Status(http.StatusNoContent)
}

// CompareAnalyses handles GET /api/analyses/compare.
func (h *Handler) CompareAnalyses(c *gin.Context) {
	idsParam := c.Query("ids")
	if idsParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "ids query parameter is required"})
		return
	}

	ids := strings.Split(idsParam, ",")
	var analyses []models.Analysis
	h.DB.Where("id IN ?", ids).Find(&analyses)

	c.JSON(http.StatusOK, analyses)
}

// GetAnalysisReport handles GET /api/analyses/:id/report.
func (h *Handler) GetAnalysisReport(c *gin.Context) {
	id := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Analysis not found"})
		return
	}

	if analysis.ResultJSON == nil || *analysis.ResultJSON == "" {
		c.JSON(http.StatusNotFound, gin.H{"detail": "No results available for this analysis"})
		return
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(*analysis.ResultJSON), &parsed); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to parse result JSON"})
		return
	}

	c.JSON(http.StatusOK, parsed)
}

// ExportAnalysis handles GET /api/analyses/:id/export.
func (h *Handler) ExportAnalysis(c *gin.Context) {
	id := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Analysis not found"})
		return
	}

	if analysis.ResultJSON == nil || *analysis.ResultJSON == "" {
		c.JSON(http.StatusNotFound, gin.H{"detail": "No results available for this analysis"})
		return
	}

	filename := fmt.Sprintf("analysis-%s.json", id)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, *analysis.ResultJSON)
}
