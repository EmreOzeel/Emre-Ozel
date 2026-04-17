package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/collector/geoip"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

var geoRateLimiter *geoip.RateLimiter

func initGeoRateLimiter(maxPerMin int) {
	if geoRateLimiter == nil {
		geoRateLimiter = geoip.NewRateLimiter(maxPerMin)
	}
}

// isPrivateIP returns true if the IP belongs to a private/reserved range.
func isPrivateIP(ip string) bool {
	return geoip.IsPrivate(ip)
}

// privateIPResult returns a minimal GeoIP result for a private/bogon IP.
func privateIPResult(ip string) gin.H {
	return gin.H{
		"ip":           ip,
		"is_private":   true,
		"is_bogon":     false,
		"country_code": nil,
		"country_name": nil,
		"city":         nil,
		"latitude":     nil,
		"longitude":    nil,
		"asn":          nil,
		"asn_org":      nil,
		"source":       "private",
	}
}

func (h *Handler) lookupAndCache(ip string) *models.GeoIPCache {
	initGeoRateLimiter(h.Cfg.GeoIPRateLimit)

	// Check cache (with TTL)
	var cached models.GeoIPCache
	ttlCutoff := time.Now().UTC().AddDate(0, 0, -h.Cfg.GeoIPCacheTTLDays)
	if err := h.DB.Where("ip = ? AND created_at >= ?", ip, ttlCutoff).First(&cached).Error; err == nil {
		return &cached
	}

	// Private check
	if isPrivateIP(ip) {
		now := time.Now().UTC()
		entry := models.GeoIPCache{
			IP: ip, IsPrivate: true, Source: "private", LookedUpAt: now,
		}
		h.DB.Create(&entry)
		return &entry
	}

	// External lookup if rate limiter allows
	if h.Cfg.GeoIPUseIPAPIFallback && geoRateLimiter.Allow() {
		result, err := geoip.LookupExternal(ip)
		if err == nil && result != nil {
			now := time.Now().UTC()
			cc := result.CountryCode
			cn := result.CountryName
			city := result.City
			lat := result.Latitude
			lon := result.Longitude
			asn := result.ASN
			asnOrg := result.ASNOrg
			entry := models.GeoIPCache{
				IP:          ip,
				CountryCode: &cc,
				CountryName: &cn,
				City:        &city,
				Latitude:    &lat,
				Longitude:   &lon,
				ASN:         &asn,
				ASNOrg:      &asnOrg,
				IsPrivate:   false,
				Source:       result.Source,
				LookedUpAt:  now,
			}
			h.DB.Create(&entry)
			return &entry
		}
	}

	return nil
}

// GeoLookup handles GET /api/geo/lookup?ip=X.
func (h *Handler) GeoLookup(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "ip parameter required"})
		return
	}

	if isPrivateIP(ip) {
		c.JSON(http.StatusOK, privateIPResult(ip))
		return
	}

	result := h.lookupAndCache(ip)
	if result != nil {
		c.JSON(http.StatusOK, result)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ip":         ip,
		"is_private": false,
		"error":      "lookup unavailable (rate limited or external API error)",
	})
}

type geoBatchInput struct {
	IPs []string `json:"ips" binding:"required"`
}

// GeoBatchLookup handles POST /api/geo/batch-lookup.
func (h *Handler) GeoBatchLookup(c *gin.Context) {
	var input geoBatchInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	initGeoRateLimiter(h.Cfg.GeoIPRateLimit)

	// Batch load from cache
	var cached []models.GeoIPCache
	if len(input.IPs) > 0 {
		h.DB.Where("ip IN ?", input.IPs).Find(&cached)
	}
	cacheMap := make(map[string]*models.GeoIPCache, len(cached))
	for i := range cached {
		cacheMap[cached[i].IP] = &cached[i]
	}

	results := make(map[string]interface{}, len(input.IPs))
	for _, ip := range input.IPs {
		if entry, ok := cacheMap[ip]; ok {
			results[ip] = entry
		} else if isPrivateIP(ip) {
			results[ip] = privateIPResult(ip)
		} else {
			// Try external
			entry := h.lookupAndCache(ip)
			if entry != nil {
				results[ip] = entry
			} else {
				results[ip] = gin.H{"ip": ip, "is_private": false, "error": "not available"}
			}
		}
	}

	c.JSON(http.StatusOK, results)
}

// GeoCacheStats handles GET /api/geo/cache-stats.
func (h *Handler) GeoCacheStats(c *gin.Context) {
	var total int64
	h.DB.Model(&models.GeoIPCache{}).Count(&total)

	type sourceCount struct {
		Source string `json:"source"`
		Count  int64  `json:"count"`
	}
	var bySrc []sourceCount
	h.DB.Model(&models.GeoIPCache{}).
		Select("source, count(*) as count").
		Group("source").
		Scan(&bySrc)

	var oldest time.Time
	row := h.DB.Model(&models.GeoIPCache{}).Select("MIN(created_at)").Row()
	_ = row.Scan(&oldest)

	c.JSON(http.StatusOK, gin.H{
		"total_entries": total,
		"by_source":     bySrc,
		"oldest_entry":  oldest,
	})
}
