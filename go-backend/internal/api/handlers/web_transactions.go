package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListWebTransactions handles GET /api/web-transactions.
func (h *Handler) ListWebTransactions(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 5000 {
		limit = 100
	}

	q := h.DB.Model(&models.WebTransaction{})

	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	if v := c.Query("destination_ip"); v != "" {
		q = q.Where("destination_ip = ?", v)
	}
	if v := c.Query("host"); v != "" {
		q = q.Where("host = ?", v)
	}
	if v := c.Query("method"); v != "" {
		q = q.Where("method = ?", v)
	}
	if v := c.Query("status_code"); v != "" {
		if code, err := strconv.Atoi(v); err == nil {
			q = q.Where("status_code = ?", code)
		}
	}
	if v := c.Query("action"); v != "" {
		q = q.Where("action = ?", v)
	}
	if v := c.Query("category"); v != "" {
		q = q.Where("category = ?", v)
	}
	if v := c.Query("suppressed"); v != "" {
		q = q.Where("suppressed = ?", v == "true" || v == "1")
	}
	if v := c.Query("start_time"); v != "" {
		if t, ok := parseTimeParam(v); ok {
			q = q.Where("transaction_time >= ?", t)
		}
	}
	if v := c.Query("end_time"); v != "" {
		if t, ok := parseTimeParam(v); ok {
			q = q.Where("transaction_time <= ?", t)
		}
	}
	if v := c.Query("search"); v != "" {
		// Case-insensitive URL substring match, compatible with both
		// PostgreSQL and SQLite (ILIKE is Postgres-only).
		q = q.Where("LOWER(url) LIKE ?", "%"+strings.ToLower(v)+"%")
	}

	var total int64
	q.Count(&total)

	var transactions []models.WebTransaction
	q.Order("transaction_time DESC, id DESC").Limit(limit).Offset(offset).Find(&transactions)

	c.JSON(http.StatusOK, gin.H{
		"total":        total,
		"offset":       offset,
		"limit":        limit,
		"transactions": transactions,
	})
}

// GetWebTransaction handles GET /api/web-transactions/:id.
func (h *Handler) GetWebTransaction(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var tx models.WebTransaction
	if err := h.DB.First(&tx, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Web transaction not found"})
		return
	}

	c.JSON(http.StatusOK, tx)
}

// WebTransactionStats handles GET /api/web-transactions/stats.
func (h *Handler) WebTransactionStats(c *gin.Context) {
	var total int64
	h.DB.Model(&models.WebTransaction{}).Count(&total)

	// Top hosts (top 10).
	type HostCount struct {
		Host  string `json:"host"`
		Count int64  `json:"count"`
	}
	var topHosts []HostCount
	h.DB.Model(&models.WebTransaction{}).
		Select("host, count(*) as count").
		Where("host IS NOT NULL").
		Group("host").
		Order("count DESC").
		Limit(10).
		Scan(&topHosts)

	// Status code distribution.
	type StatusCount struct {
		StatusCode int   `json:"status_code"`
		Count      int64 `json:"count"`
	}
	var statusCounts []StatusCount
	h.DB.Model(&models.WebTransaction{}).
		Select("status_code, count(*) as count").
		Where("status_code IS NOT NULL").
		Group("status_code").
		Scan(&statusCounts)

	statusMap := make(map[string]int64)
	for _, sc := range statusCounts {
		statusMap[strconv.Itoa(sc.StatusCode)] = sc.Count
	}

	// Top source IPs (top 10).
	type IPTxCount struct {
		SourceIP string `json:"source_ip"`
		Count    int64  `json:"count"`
	}
	var topSourceIPs []IPTxCount
	h.DB.Model(&models.WebTransaction{}).
		Select("source_ip, count(*) as count").
		Group("source_ip").
		Order("count DESC").
		Limit(10).
		Scan(&topSourceIPs)

	// Average duration in milliseconds.
	var avgDuration sql.NullFloat64
	h.DB.Model(&models.WebTransaction{}).
		Select("avg(duration_ms)").
		Where("duration_ms IS NOT NULL").
		Scan(&avgDuration)

	avg := 0.0
	if avgDuration.Valid {
		avg = avgDuration.Float64
	}

	c.JSON(http.StatusOK, gin.H{
		"total":              total,
		"top_hosts":          topHosts,
		"status_code_counts": statusMap,
		"top_source_ips":     topSourceIPs,
		"avg_duration_ms":    avg,
	})
}

// parseTimeParam parses a query time value in RFC3339 or common
// "YYYY-MM-DD HH:MM:SS" / "YYYY-MM-DD" formats.
func parseTimeParam(v string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
