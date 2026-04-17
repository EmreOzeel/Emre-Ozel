package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/threat_feeds"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// ListThreatFeeds returns all threat feeds ordered by name.
func (h *Handler) ListThreatFeeds(c *gin.Context) {
	var feeds []models.ThreatFeed
	h.DB.Order("name").Find(&feeds)
	c.JSON(http.StatusOK, feeds)
}

// FetchThreatFeed triggers a fetch for a single feed (admin only).
func (h *Handler) FetchThreatFeed(c *gin.Context) {
	user := auth.CurrentUser(c)
	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "admin only"})
		return
	}

	var feed models.ThreatFeed
	if err := h.DB.First(&feed, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "feed not found"})
		return
	}

	count, err := threat_feeds.FetchFeed(h.DB, &feed, h.Cfg.ThreatFeedTimeout, h.Cfg.ThreatFeedUserAgent)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": fmt.Sprintf("fetch failed: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"fetched": count,
		"feed":    feed.Name,
	})
}

// RefreshAllFeeds fetches all enabled feeds that are due for refresh (admin only).
func (h *Handler) RefreshAllFeeds(c *gin.Context) {
	user := auth.CurrentUser(c)
	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "admin only"})
		return
	}

	now := time.Now().UTC()
	var feeds []models.ThreatFeed
	h.DB.Where("enabled = ?", true).Find(&feeds)

	results := make(map[string]interface{})
	for i := range feeds {
		feed := &feeds[i]
		// Skip if not due
		if feed.LastFetchedAt != nil {
			nextDue := feed.LastFetchedAt.Add(time.Duration(feed.FetchIntervalHours) * time.Hour)
			if now.Before(nextDue) {
				continue
			}
		}
		count, err := threat_feeds.FetchFeed(h.DB, feed, h.Cfg.ThreatFeedTimeout, h.Cfg.ThreatFeedUserAgent)
		if err != nil {
			results[feed.Name] = fmt.Sprintf("error: %v", err)
		} else {
			results[feed.Name] = count
		}
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// ListThreatIndicators returns indicators with optional filters.
func (h *Handler) ListThreatIndicators(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := h.DB.Model(&models.ThreatIndicator{})

	if v := c.Query("indicator_type"); v != "" {
		query = query.Where("indicator_type = ?", v)
	}
	if v := c.Query("threat_type"); v != "" {
		query = query.Where("threat_type = ?", v)
	}
	if v := c.Query("source_feed"); v != "" {
		query = query.Where("source_feed = ?", v)
	}

	var total int64
	query.Count(&total)

	var indicators []models.ThreatIndicator
	query.Limit(limit).Offset(offset).Find(&indicators)

	c.JSON(http.StatusOK, gin.H{
		"total": total,
		"items": indicators,
	})
}

// LookupThreatIP checks whether a given IP appears in threat indicators.
func (h *Handler) LookupThreatIP(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip parameter required"})
		return
	}

	var indicators []models.ThreatIndicator
	h.DB.Where("indicator_type = ? AND indicator_value = ?", "ip", ip).Find(&indicators)

	c.JSON(http.StatusOK, gin.H{
		"ip":         ip,
		"is_threat":  len(indicators) > 0,
		"indicators": indicators,
	})
}

// DeleteThreatIndicator removes an indicator (admin only).
func (h *Handler) DeleteThreatIndicator(c *gin.Context) {
	user := auth.CurrentUser(c)
	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin only"})
		return
	}

	var indicator models.ThreatIndicator
	if err := h.DB.First(&indicator, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "indicator not found"})
		return
	}

	h.DB.Delete(&indicator)
	c.Status(http.StatusNoContent)
}
