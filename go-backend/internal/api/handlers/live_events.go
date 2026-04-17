package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListLiveEvents handles GET /api/live-events.
func (h *Handler) ListLiveEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 5000 {
		limit = 100
	}

	q := h.DB.Model(&models.LiveEvent{})

	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	if v := c.Query("destination_ip"); v != "" {
		q = q.Where("destination_ip = ?", v)
	}
	if v := c.Query("action"); v != "" {
		q = q.Where("action = ?", v)
	}
	if v := c.Query("source_id"); v != "" {
		q = q.Where("source_id = ?", v)
	}
	if v := c.Query("device_type"); v != "" {
		q = q.Where("device_type = ?", v)
	}
	if v := c.Query("protocol"); v != "" {
		q = q.Where("protocol = ?", v)
	}
	if v := c.Query("application"); v != "" {
		q = q.Where("application = ?", v)
	}
	if v := c.Query("suppressed"); v != "" {
		q = q.Where("suppressed = ?", v == "true" || v == "1")
	}

	var total int64
	q.Count(&total)

	var events []models.LiveEvent
	q.Order("event_time DESC, id DESC").Limit(limit).Offset(offset).Find(&events)

	c.JSON(http.StatusOK, gin.H{
		"total":  total,
		"offset": offset,
		"limit":  limit,
		"events": events,
	})
}

// LiveEventStats handles GET /api/live-events/stats.
func (h *Handler) LiveEventStats(c *gin.Context) {
	var total int64
	h.DB.Model(&models.LiveEvent{}).Count(&total)

	// Action counts.
	type ActionCount struct {
		Action string `json:"action"`
		Count  int64  `json:"count"`
	}
	var actionCounts []ActionCount
	h.DB.Model(&models.LiveEvent{}).
		Select("action, count(*) as count").
		Group("action").
		Scan(&actionCounts)

	actionMap := make(map[string]int64)
	for _, ac := range actionCounts {
		actionMap[ac.Action] = ac.Count
	}

	// Device type counts.
	type DeviceCount struct {
		DeviceType string `json:"device_type"`
		Count      int64  `json:"count"`
	}
	var deviceCounts []DeviceCount
	h.DB.Model(&models.LiveEvent{}).
		Select("device_type, count(*) as count").
		Group("device_type").
		Scan(&deviceCounts)

	deviceMap := make(map[string]int64)
	for _, dc := range deviceCounts {
		deviceMap[dc.DeviceType] = dc.Count
	}

	// Parser ID counts.
	type ParserCount struct {
		ParserID string `json:"parser_id"`
		Count    int64  `json:"count"`
	}
	var parserCounts []ParserCount
	h.DB.Model(&models.LiveEvent{}).
		Select("parser_id, count(*) as count").
		Group("parser_id").
		Scan(&parserCounts)

	parserMap := make(map[string]int64)
	for _, pc := range parserCounts {
		parserMap[pc.ParserID] = pc.Count
	}

	// Top source IPs (top 10).
	type IPCount struct {
		IP    string `json:"ip"`
		Count int64  `json:"count"`
	}
	var topSrcIPs []IPCount
	h.DB.Model(&models.LiveEvent{}).
		Select("source_ip as ip, count(*) as count").
		Group("source_ip").
		Order("count DESC").
		Limit(10).
		Scan(&topSrcIPs)

	// Top destination IPs (top 10).
	var topDstIPs []IPCount
	h.DB.Model(&models.LiveEvent{}).
		Select("destination_ip as ip, count(*) as count").
		Group("destination_ip").
		Order("count DESC").
		Limit(10).
		Scan(&topDstIPs)

	// Top denied sources (top 10).
	var topDeniedSrc []IPCount
	h.DB.Model(&models.LiveEvent{}).
		Select("source_ip as ip, count(*) as count").
		Where("action IN ?", []string{"deny", "drop"}).
		Group("source_ip").
		Order("count DESC").
		Limit(10).
		Scan(&topDeniedSrc)

	c.JSON(http.StatusOK, gin.H{
		"total":               total,
		"action_counts":       actionMap,
		"device_type_counts":  deviceMap,
		"parser_id_counts":    parserMap,
		"top_source_ips":      topSrcIPs,
		"top_destination_ips": topDstIPs,
		"top_denied_sources":  topDeniedSrc,
	})
}

// LiveEventTimeline handles GET /api/live-events/timeline.
func (h *Handler) LiveEventTimeline(c *gin.Context) {
	minutes, _ := strconv.Atoi(c.DefaultQuery("minutes", "60"))
	if minutes <= 0 {
		minutes = 60
	}

	cutoff := time.Now().UTC().Add(-time.Duration(minutes) * time.Minute)
	truncExpr := h.timeBucketExpr("event_time", "minute")

	q := h.DB.Model(&models.LiveEvent{}).
		Select(fmt.Sprintf(`%s as bucket,
			count(*) as total,
			sum(case when action = 'allow' then 1 else 0 end) as allow_count,
			sum(case when action = 'deny' then 1 else 0 end) as deny_count,
			sum(case when action = 'drop' then 1 else 0 end) as drop_count`, truncExpr)).
		Where("event_time >= ?", cutoff)

	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	if v := c.Query("destination_ip"); v != "" {
		q = q.Where("destination_ip = ?", v)
	}

	type Bucket struct {
		Bucket     string `json:"bucket"`
		Total      int64  `json:"total"`
		AllowCount int64  `json:"allow_count"`
		DenyCount  int64  `json:"deny_count"`
		DropCount  int64  `json:"drop_count"`
	}

	var buckets []Bucket
	q.Group("bucket").Order("bucket ASC").Scan(&buckets)

	c.JSON(http.StatusOK, buckets)
}

// LiveEventRiskScores handles GET /api/live-events/risk-scores.
// Complex risk scoring logic is deferred; returns an empty array.
func (h *Handler) LiveEventRiskScores(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{})
}

// timeBucketExpr returns a SQL expression to truncate a datetime column
// to the specified interval, compatible with both PostgreSQL and SQLite.
func (h *Handler) timeBucketExpr(column, interval string) string {
	dialector := h.DB.Dialector.Name()
	if strings.Contains(dialector, "postgres") {
		return fmt.Sprintf("date_trunc('%s', %s)", interval, column)
	}
	// SQLite fallback: truncate to minute.
	return fmt.Sprintf("strftime('%%Y-%%m-%%dT%%H:%%M:00', %s)", column)
}
