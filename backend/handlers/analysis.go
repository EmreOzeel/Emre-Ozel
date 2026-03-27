package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"pcap-analyzer/analyzer"
	"pcap-analyzer/models"
)

type AnalysisHandler struct {
	DB        *gorm.DB
	UploadDir string
}

func NewAnalysisHandler(db *gorm.DB, uploadDir string) *AnalysisHandler {
	return &AnalysisHandler{DB: db, UploadDir: uploadDir}
}

// Upload and analyze a PCAP file
func (h *AnalysisHandler) Upload(c *gin.Context) {
	userID := c.GetUint("userID")

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
		return
	}
	defer file.Close()

	ext := filepath.Ext(header.Filename)
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only .pcap, .pcapng, .cap files are supported"})
		return
	}

	if err := os.MkdirAll(h.UploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
		return
	}

	filename := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), sanitizeFilename(header.Filename[:len(header.Filename)-len(ext)]), ext)
	filePath := filepath.Join(h.UploadDir, filename)

	dst, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}
	defer dst.Close()

	written, err := dst.ReadFrom(file)
	if err != nil {
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file"})
		return
	}

	analysis := models.Analysis{
		UserID:   userID,
		Filename: header.Filename,
		FileSize: written,
		Status:   "running",
	}

	if err := h.DB.Create(&analysis).Error; err != nil {
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create analysis record"})
		return
	}

	// Run analysis synchronously (for files up to ~100MB this is fine)
	result, err := analyzer.Analyze(filePath)
	if err != nil {
		h.DB.Model(&analysis).Updates(map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		})
		os.Remove(filePath)
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": fmt.Sprintf("Analysis failed: %s", err.Error())})
		return
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		h.DB.Model(&analysis).Updates(map[string]interface{}{
			"status": "failed",
			"error":  "Failed to serialize result",
		})
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize result"})
		return
	}

	h.DB.Model(&analysis).Updates(map[string]interface{}{
		"status":      "completed",
		"result_json": string(resultJSON),
	})

	// Remove the uploaded file after analysis to save space
	os.Remove(filePath)

	c.JSON(http.StatusOK, gin.H{
		"analysis_id": analysis.ID,
		"filename":    analysis.Filename,
		"status":      "completed",
		"result":      result,
	})
}

// List all analyses for the current user
func (h *AnalysisHandler) List(c *gin.Context) {
	userID := c.GetUint("userID")

	var analyses []models.Analysis
	if err := h.DB.Where("user_id = ?", userID).Order("created_at DESC").Find(&analyses).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch analyses"})
		return
	}

	type ListItem struct {
		ID            uint      `json:"id"`
		Filename      string    `json:"filename"`
		FileSize      int64     `json:"file_size"`
		Status        string    `json:"status"`
		Error         string    `json:"error,omitempty"`
		CreatedAt     time.Time `json:"created_at"`
		CriticalCount int       `json:"critical_count"`
		WarningCount  int       `json:"warning_count"`
		InfoCount     int       `json:"info_count"`
		TotalPackets  int       `json:"total_packets"`
	}

	items := make([]ListItem, 0, len(analyses))
	for _, a := range analyses {
		item := ListItem{
			ID:        a.ID,
			Filename:  a.Filename,
			FileSize:  a.FileSize,
			Status:    a.Status,
			Error:     a.Error,
			CreatedAt: a.CreatedAt,
		}

		if a.ResultJSON != "" {
			var result models.AnalysisResult
			if err := json.Unmarshal([]byte(a.ResultJSON), &result); err == nil {
				item.CriticalCount = result.Summary.CriticalCount
				item.WarningCount = result.Summary.WarningCount
				item.InfoCount = result.Summary.InfoCount
				item.TotalPackets = result.Summary.TotalPackets
			}
		}

		items = append(items, item)
	}

	c.JSON(http.StatusOK, items)
}

// Get a single analysis by ID
func (h *AnalysisHandler) Get(c *gin.Context) {
	userID := c.GetUint("userID")
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var analysis models.Analysis
	if err := h.DB.Where("id = ? AND user_id = ?", id, userID).First(&analysis).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}

	if analysis.ResultJSON == "" {
		c.JSON(http.StatusOK, gin.H{
			"id":         analysis.ID,
			"filename":   analysis.Filename,
			"file_size":  analysis.FileSize,
			"status":     analysis.Status,
			"error":      analysis.Error,
			"created_at": analysis.CreatedAt,
		})
		return
	}

	var result models.AnalysisResult
	if err := json.Unmarshal([]byte(analysis.ResultJSON), &result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse result"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         analysis.ID,
		"filename":   analysis.Filename,
		"file_size":  analysis.FileSize,
		"status":     analysis.Status,
		"created_at": analysis.CreatedAt,
		"result":     result,
	})
}

// Delete an analysis
func (h *AnalysisHandler) Delete(c *gin.Context) {
	userID := c.GetUint("userID")
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	result := h.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.Analysis{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Deleted successfully"})
}

func sanitizeFilename(name string) string {
	safe := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe += string(r)
		} else {
			safe += "_"
		}
	}
	if len(safe) > 50 {
		safe = safe[:50]
	}
	if safe == "" {
		safe = "file"
	}
	return safe
}
