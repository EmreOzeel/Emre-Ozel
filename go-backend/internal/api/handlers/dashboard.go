package handlers

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// DashboardSummary returns an aggregated overview for the authenticated user.
func (h *Handler) DashboardSummary(c *gin.Context) {
	user := auth.CurrentUser(c)
	now := time.Now().UTC()
	fiveMinAgo := now.Add(-5 * time.Minute)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Collector status (static for now)
	collector := gin.H{
		"running":   h.Cfg.CollectorEnabled,
		"syslog_port": h.Cfg.SyslogPort,
		"source_id":   h.Cfg.CollectorSourceID,
	}

	// Live events last 5 min
	var leTotal, leAllow, leDeny, leDrop int64
	h.DB.Model(&models.LiveEvent{}).Where("event_time >= ?", fiveMinAgo).Count(&leTotal)
	h.DB.Model(&models.LiveEvent{}).Where("event_time >= ? AND action = ?", fiveMinAgo, "allow").Count(&leAllow)
	h.DB.Model(&models.LiveEvent{}).Where("event_time >= ? AND action = ?", fiveMinAgo, "deny").Count(&leDeny)
	h.DB.Model(&models.LiveEvent{}).Where("event_time >= ? AND action = ?", fiveMinAgo, "drop").Count(&leDrop)

	liveEvents := gin.H{
		"total_last_5min": leTotal,
		"allow_last_5min": leAllow,
		"deny_last_5min":  leDeny,
		"drop_last_5min":  leDrop,
	}

	// Risk scores: empty for now (complex computation deferred)
	riskScores := []gin.H{}

	// Auto-detections: last 5 notifications with [AUTO] prefix
	var autoNotifs []models.Notification
	h.DB.Where("user_id = ? AND message LIKE ?", user.ID, "[AUTO]%").
		Order("created_at desc").Limit(5).Find(&autoNotifs)
	autoDetections := make([]gin.H, 0, len(autoNotifs))
	for _, n := range autoNotifs {
		autoDetections = append(autoDetections, gin.H{
			"id":          n.ID,
			"message":     n.Message,
			"type":        n.Type,
			"analysis_id": n.AnalysisID,
			"created_at":  n.CreatedAt,
		})
	}

	// Work queue summary
	var totalOpen, needsReview, newAnalyses int64
	h.DB.Model(&models.Analysis{}).
		Where("user_id = ? AND workflow_state NOT IN ?", user.ID, []string{"resolved", "dismissed"}).
		Count(&totalOpen)
	h.DB.Model(&models.Analysis{}).
		Where("(user_id = ? OR assigned_user_id = ?) AND workflow_state = ?", user.ID, user.ID, "needs_review").
		Count(&needsReview)
	h.DB.Model(&models.Analysis{}).
		Where("user_id = ? AND workflow_state = ?", user.ID, "new").
		Count(&newAnalyses)

	workQueue := gin.H{
		"total_open":   totalOpen,
		"needs_review": needsReview,
		"new_analyses": newAnalyses,
	}

	// Analyses summary
	var totalAnalyses, completedToday, failedToday, pending int64
	h.DB.Model(&models.Analysis{}).Count(&totalAnalyses)
	h.DB.Model(&models.Analysis{}).Where("status = ? AND finished_at >= ?", "completed", midnight).Count(&completedToday)
	h.DB.Model(&models.Analysis{}).Where("status = ? AND finished_at >= ?", "failed", midnight).Count(&failedToday)
	h.DB.Model(&models.Analysis{}).Where("status = ?", "pending").Count(&pending)

	analyses := gin.H{
		"total":           totalAnalyses,
		"completed_today": completedToday,
		"failed_today":    failedToday,
		"pending":         pending,
	}

	c.JSON(200, gin.H{
		"collector":       collector,
		"live_events":     liveEvents,
		"risk_scores":     riskScores,
		"auto_detections": autoDetections,
		"work_queue":      workQueue,
		"analyses":        analyses,
	})
}
