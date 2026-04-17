package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListLiveFlows handles GET /api/live-flows.
func (h *Handler) ListLiveFlows(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 5000 {
		limit = 100
	}

	q := h.DB.Model(&models.LiveFlow{})

	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	if v := c.Query("destination_ip"); v != "" {
		q = q.Where("destination_ip = ?", v)
	}
	if v := c.Query("protocol"); v != "" {
		q = q.Where("protocol = ?", v)
	}
	if v := c.Query("state"); v != "" {
		q = q.Where("state = ?", v)
	}
	if v := c.Query("flow_type"); v != "" {
		q = q.Where("flow_type = ?", v)
	}
	if v := c.Query("device_type"); v != "" {
		q = q.Where("device_type = ?", v)
	}
	if v := c.Query("parser_id"); v != "" {
		q = q.Where("parser_id = ?", v)
	}
	if v := c.Query("application"); v != "" {
		q = q.Where("application = ?", v)
	}
	if v := c.Query("action_summary"); v != "" {
		q = q.Where("action_summary = ?", v)
	}
	if v := c.Query("suppressed"); v != "" {
		q = q.Where("suppressed = ?", v == "true" || v == "1")
	}

	var total int64
	q.Count(&total)

	var flows []models.LiveFlow
	q.Order("last_seen DESC").Limit(limit).Offset(offset).Find(&flows)

	c.JSON(http.StatusOK, gin.H{
		"total":  total,
		"offset": offset,
		"limit":  limit,
		"flows":  flows,
	})
}

// LiveFlowStats handles GET /api/live-flows/stats.
func (h *Handler) LiveFlowStats(c *gin.Context) {
	var totalFlows int64
	h.DB.Model(&models.LiveFlow{}).Count(&totalFlows)

	var activeFlows int64
	h.DB.Model(&models.LiveFlow{}).Where("state = ?", "active").Count(&activeFlows)

	var completedFlows int64
	h.DB.Model(&models.LiveFlow{}).Where("state = ?", "completed").Count(&completedFlows)

	var deniedFlows int64
	h.DB.Model(&models.LiveFlow{}).Where("state = ?", "denied").Count(&deniedFlows)

	var resetFlows int64
	h.DB.Model(&models.LiveFlow{}).Where("state = ?", "reset").Count(&resetFlows)

	var droppedFlows int64
	h.DB.Model(&models.LiveFlow{}).Where("state = ?", "dropped").Count(&droppedFlows)

	// Flow type counts.
	type TypeCount struct {
		FlowType string `json:"flow_type"`
		Count    int64  `json:"count"`
	}
	var typeCounts []TypeCount
	h.DB.Model(&models.LiveFlow{}).
		Select("flow_type, count(*) as count").
		Where("flow_type IS NOT NULL").
		Group("flow_type").
		Scan(&typeCounts)

	flowTypeMap := make(map[string]int64)
	for _, tc := range typeCounts {
		flowTypeMap[tc.FlowType] = tc.Count
	}

	// Top talkers (top 5 by flow count).
	type Talker struct {
		SourceIP string `json:"source_ip"`
		Count    int64  `json:"count"`
	}
	var topTalkers []Talker
	h.DB.Model(&models.LiveFlow{}).
		Select("source_ip, count(*) as count").
		Group("source_ip").
		Order("count DESC").
		Limit(5).
		Scan(&topTalkers)

	c.JSON(http.StatusOK, gin.H{
		"total_flows":      totalFlows,
		"active_flows":     activeFlows,
		"completed_flows":  completedFlows,
		"denied_flows":     deniedFlows,
		"reset_flows":      resetFlows,
		"dropped_flows":    droppedFlows,
		"flow_type_counts": flowTypeMap,
		"top_talkers":      topTalkers,
	})
}

// LiveFlowTimeline handles GET /api/live-flows/timeline.
func (h *Handler) LiveFlowTimeline(c *gin.Context) {
	minutes, _ := strconv.Atoi(c.DefaultQuery("minutes", "60"))
	if minutes <= 0 {
		minutes = 60
	}

	cutoff := time.Now().UTC().Add(-time.Duration(minutes) * time.Minute)
	truncExpr := h.timeBucketExpr("first_seen", "minute")

	type Bucket struct {
		Bucket string `json:"bucket"`
		Count  int64  `json:"count"`
	}

	var buckets []Bucket
	h.DB.Model(&models.LiveFlow{}).
		Select(fmt.Sprintf("%s as bucket, count(*) as count", truncExpr)).
		Where("first_seen >= ?", cutoff).
		Group("bucket").
		Order("bucket ASC").
		Scan(&buckets)

	c.JSON(http.StatusOK, buckets)
}

// LiveFlowBehaviors handles GET /api/live-flows/behaviors.
func (h *Handler) LiveFlowBehaviors(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := h.DB.Model(&models.LiveFlow{}).
		Where("flow_type IN ?", []string{"suspicious", "scanning", "unstable"})

	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}

	var flows []models.LiveFlow
	q.Order("last_seen DESC").Limit(limit).Find(&flows)

	c.JSON(http.StatusOK, flows)
}
