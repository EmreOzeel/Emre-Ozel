package geoip

import (
	"net"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// Lookup returns cached GeoIP data for an IP address. If the IP is not in the
// cache, it checks whether it is a private/reserved address and caches that
// result. Returns nil if the IP is unknown and no external API is configured.
func Lookup(db *gorm.DB, ip string) *models.GeoIPCache {
	var cached models.GeoIPCache
	if err := db.Where("ip = ?", ip).First(&cached).Error; err == nil {
		return &cached
	}

	// Check private/reserved ranges
	if IsPrivate(ip) {
		now := time.Now().UTC()
		entry := &models.GeoIPCache{
			IP:         ip,
			IsPrivate:  true,
			Source:     "private",
			LookedUpAt: now,
		}
		db.Create(entry)
		return entry
	}

	return nil // Not in cache, no external API yet
}

// IsPrivate returns true if the given IP string falls within a private or
// reserved address range (RFC 1918, loopback, link-local).
func IsPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}

	return parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}
