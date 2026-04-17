package geoip

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// GeoResult holds the result of a GeoIP lookup.
type GeoResult struct {
	CountryCode string
	CountryName string
	City        string
	Latitude    float64
	Longitude   float64
	ASN         int
	ASNOrg      string
	Source      string
}

// RateLimiter limits external API calls to maxPerMin per minute.
type RateLimiter struct {
	mu        sync.Mutex
	calls     []time.Time
	maxPerMin int
}

// NewRateLimiter creates a rate limiter with the given max calls per minute.
func NewRateLimiter(maxPerMin int) *RateLimiter {
	return &RateLimiter{maxPerMin: maxPerMin}
}

// Allow returns true if a call is allowed under the rate limit.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Remove old entries
	valid := r.calls[:0]
	for _, t := range r.calls {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	r.calls = valid

	if len(r.calls) >= r.maxPerMin {
		return false
	}
	r.calls = append(r.calls, now)
	return true
}

// Count returns the current number of calls in the window.
func (r *RateLimiter) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	count := 0
	for _, t := range r.calls {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// LookupExternal queries ip-api.com for geolocation data.
func LookupExternal(ip string) (*GeoResult, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,lat,lon,as,org", ip)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ip-api request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var data struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		AS          string  `json:"as"`
		Org         string  `json:"org"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if data.Status != "success" {
		return nil, fmt.Errorf("ip-api returned status: %s", data.Status)
	}

	// Parse ASN number from "AS13335 Cloudflare, Inc." format
	asn := 0
	if len(data.AS) > 2 {
		asPart := data.AS[2:] // skip "AS"
		for i, c := range asPart {
			if c < '0' || c > '9' {
				asPart = asPart[:i]
				break
			}
		}
		fmt.Sscanf(asPart, "%d", &asn)
	}

	return &GeoResult{
		CountryCode: data.CountryCode,
		CountryName: data.Country,
		City:        data.City,
		Latitude:    data.Lat,
		Longitude:   data.Lon,
		ASN:         asn,
		ASNOrg:      data.Org,
		Source:       "ip-api",
	}, nil
}

// ExternalLookupFunc is a variant that accepts a custom HTTP fetch function
// for testing purposes.
type ExternalLookupFunc func(ip string) (*GeoResult, error)
