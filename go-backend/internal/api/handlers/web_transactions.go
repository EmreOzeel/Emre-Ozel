package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

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

// timeseriesIntervals maps supported interval query values to their bucket size.
var timeseriesIntervals = map[string]time.Duration{
	"5m":  5 * time.Minute,
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"1d":  24 * time.Hour,
}

// maxTimeseriesBuckets caps the number of buckets a single timeseries
// request may produce.
const maxTimeseriesBuckets = 1000

// deniedActionSQL is a SQL condition matching the deny/block/drop family of
// actions, compatible with both PostgreSQL and SQLite.
const deniedActionSQL = "(LOWER(action) IN ('deny', 'drop', 'block') OR " +
	"LOWER(action) LIKE 'deny-%' OR LOWER(action) LIKE 'drop-%' OR " +
	"LOWER(action) LIKE 'block-%' OR LOWER(action) LIKE 'reset-%')"

// isDeniedWebAction reports whether an action value belongs to the
// deny/block/drop family (e.g. deny, drop, block-url, reset-both).
func isDeniedWebAction(action string) bool {
	a := strings.ToLower(action)
	switch a {
	case "deny", "drop", "block":
		return true
	}
	return strings.HasPrefix(a, "deny-") || strings.HasPrefix(a, "drop-") ||
		strings.HasPrefix(a, "block-") || strings.HasPrefix(a, "reset-")
}

// applyWebTransactionAnalyticsFilters applies the shared optional filters for
// the analytics endpoints (source_ip, host, category, action).
func applyWebTransactionAnalyticsFilters(q *gorm.DB, c *gin.Context) *gorm.DB {
	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	if v := c.Query("host"); v != "" {
		q = q.Where("host = ?", v)
	}
	if v := c.Query("category"); v != "" {
		q = q.Where("category = ?", v)
	}
	if v := c.Query("action"); v != "" {
		q = q.Where("action = ?", v)
	}
	return q
}

// parseAnalyticsTimeRange resolves start_time/end_time query params with the
// given default window. It writes a 400 response and returns ok=false on
// invalid input.
func parseAnalyticsTimeRange(c *gin.Context, defaultWindow time.Duration) (start, end time.Time, ok bool) {
	end = time.Now().UTC()
	if v := c.Query("end_time"); v != "" {
		t, valid := parseTimeParam(v)
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid end_time"})
			return start, end, false
		}
		end = t
	}
	start = end.Add(-defaultWindow)
	if v := c.Query("start_time"); v != "" {
		t, valid := parseTimeParam(v)
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid start_time"})
			return start, end, false
		}
		start = t
	}
	if !start.Before(end) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "start_time must be before end_time"})
		return start, end, false
	}
	return start, end, true
}

// WebTransactionTimeseries handles GET /api/web-transactions/timeseries.
// It returns a continuous time series (empty buckets zero-filled) of
// transaction counts, denied counts, average duration and byte totals.
// Bucketing is done in Go so the query stays portable across
// PostgreSQL and SQLite.
func (h *Handler) WebTransactionTimeseries(c *gin.Context) {
	interval := c.DefaultQuery("interval", "5m")
	step, valid := timeseriesIntervals[interval]
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid interval; must be one of 5m, 15m, 1h, 1d"})
		return
	}

	start, end, ok := parseAnalyticsTimeRange(c, time.Hour)
	if !ok {
		return
	}

	// Align the first bucket to the interval boundary.
	alignedStart := start.Truncate(step)
	numBuckets := int((end.Sub(alignedStart) + step - 1) / step)
	if numBuckets > maxTimeseriesBuckets {
		c.JSON(http.StatusBadRequest, gin.H{
			"detail": fmt.Sprintf("Time range too large for interval %s: %d buckets exceeds maximum of %d", interval, numBuckets, maxTimeseriesBuckets),
		})
		return
	}

	q := h.DB.Model(&models.WebTransaction{}).
		Select("transaction_time, action, duration_ms, bytes_in, bytes_out").
		Where("transaction_time >= ? AND transaction_time < ?", start, end)
	q = applyWebTransactionAnalyticsFilters(q, c)

	type txRow struct {
		TransactionTime time.Time
		Action          *string
		DurationMs      *int
		BytesIn         int64
		BytesOut        int64
	}
	var rows []txRow
	q.Scan(&rows)

	type timeseriesBucket struct {
		Bucket        string   `json:"bucket"`
		Count         int64    `json:"count"`
		DeniedCount   int64    `json:"denied_count"`
		AvgDurationMs *float64 `json:"avg_duration_ms"`
		BytesIn       int64    `json:"bytes_in"`
		BytesOut      int64    `json:"bytes_out"`
	}

	series := make([]timeseriesBucket, numBuckets)
	durationSums := make([]float64, numBuckets)
	durationCounts := make([]int64, numBuckets)
	for i := range series {
		series[i].Bucket = alignedStart.Add(time.Duration(i) * step).Format(time.RFC3339)
	}

	for _, r := range rows {
		idx := int(r.TransactionTime.UTC().Sub(alignedStart) / step)
		if idx < 0 || idx >= numBuckets {
			continue
		}
		b := &series[idx]
		b.Count++
		if r.Action != nil && isDeniedWebAction(*r.Action) {
			b.DeniedCount++
		}
		b.BytesIn += r.BytesIn
		b.BytesOut += r.BytesOut
		if r.DurationMs != nil {
			durationSums[idx] += float64(*r.DurationMs)
			durationCounts[idx]++
		}
	}
	for i := range series {
		if durationCounts[i] > 0 {
			avg := durationSums[i] / float64(durationCounts[i])
			series[i].AvgDurationMs = &avg
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"interval":   interval,
		"start_time": alignedStart.Format(time.RFC3339),
		"end_time":   end.Format(time.RFC3339),
		"series":     series,
	})
}

// topDimensionColumns maps supported top dimensions to their column names.
var topDimensionColumns = map[string]string{
	"host":      "host",
	"category":  "category",
	"source_ip": "source_ip",
}

// WebTransactionTop handles GET /api/web-transactions/top.
// It returns the top N values for a dimension (host, category or source_ip)
// by transaction count within a time range.
func (h *Handler) WebTransactionTop(c *gin.Context) {
	dimension := c.DefaultQuery("dimension", "host")
	column, valid := topDimensionColumns[dimension]
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid dimension; must be one of host, category, source_ip"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	start, end, ok := parseAnalyticsTimeRange(c, 24*time.Hour)
	if !ok {
		return
	}

	q := h.DB.Model(&models.WebTransaction{}).
		Select(fmt.Sprintf(
			"%s as dim_key, count(*) as count, sum(case when %s then 1 else 0 end) as denied_count, sum(bytes_in + bytes_out) as bytes_total",
			column, deniedActionSQL)).
		Where("transaction_time >= ? AND transaction_time <= ?", start, end).
		Where(fmt.Sprintf("%s IS NOT NULL AND %s <> ''", column, column))
	q = applyWebTransactionAnalyticsFilters(q, c)

	type topItem struct {
		Key         string `gorm:"column:dim_key" json:"key"`
		Count       int64  `json:"count"`
		DeniedCount int64  `json:"denied_count"`
		BytesTotal  int64  `json:"bytes_total"`
	}
	var items []topItem
	q.Group(column).Order("count DESC").Limit(limit).Scan(&items)
	if items == nil {
		items = []topItem{}
	}

	c.JSON(http.StatusOK, gin.H{
		"dimension": dimension,
		"items":     items,
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
