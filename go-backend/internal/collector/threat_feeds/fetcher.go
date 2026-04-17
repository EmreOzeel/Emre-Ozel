package threat_feeds

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// FetchFeed downloads a threat intelligence feed, parses it, and upserts
// indicators into the database. Returns the number of indicators upserted.
func FetchFeed(db *gorm.DB, feed *models.ThreatFeed, timeout int, userAgent string) (int, error) {
	if feed.URL == nil || *feed.URL == "" {
		return 0, fmt.Errorf("feed %q has no URL", feed.Name)
	}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequest("GET", *feed.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch %q: %w", *feed.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("fetch %q: status %d", *feed.URL, resp.StatusCode)
	}

	// Read body (limit to 50MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}

	var entries []string
	switch feed.Format {
	case "plain":
		entries = parsePlain(string(body), feed.CommentChar)
	case "csv":
		entries = parseCSV(string(body), feed.CommentChar, feed.IPColumn)
	case "json":
		entries = parseJSON(body)
	default:
		entries = parsePlain(string(body), feed.CommentChar)
	}

	// Validate and upsert
	now := time.Now().UTC()
	count := 0
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Validate IP format
		if net.ParseIP(entry) == nil {
			// Try CIDR
			if _, _, err := net.ParseCIDR(entry); err != nil {
				continue // skip invalid
			}
		}

		indicatorType := "ip"
		if strings.Contains(entry, "/") {
			indicatorType = "cidr"
		}

		// Upsert: update if exists, create if not
		var existing models.ThreatIndicator
		err := db.Where("indicator_value = ? AND source_feed = ?", entry, feed.Name).First(&existing).Error
		if err == nil {
			// Update existing
			db.Model(&existing).Updates(map[string]interface{}{
				"last_seen":  now,
				"confidence": feed.DefaultConfidence,
			})
		} else {
			// Create new
			db.Create(&models.ThreatIndicator{
				IndicatorType:  indicatorType,
				IndicatorValue: entry,
				ThreatType:     feed.DefaultThreatType,
				Confidence:     feed.DefaultConfidence,
				SourceFeed:     feed.Name,
				FirstSeen:      now,
				LastSeen:       now,
			})
		}
		count++
	}

	// Update feed metadata
	db.Model(feed).Updates(map[string]interface{}{
		"last_fetched_at":      now,
		"last_indicator_count": count,
	})

	return count, nil
}

func parsePlain(body, commentChar string) []string {
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, commentChar) {
			continue
		}
		result = append(result, line)
	}
	return result
}

func parseCSV(body, commentChar string, ipColumn int) []string {
	var result []string
	reader := csv.NewReader(strings.NewReader(body))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // variable
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) == 0 {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(record[0]), commentChar) {
			continue
		}
		if ipColumn < len(record) {
			result = append(result, strings.TrimSpace(record[ipColumn]))
		}
	}
	return result
}

func parseJSON(body []byte) []string {
	var result []string

	// Try array of objects
	var items []map[string]interface{}
	if err := json.Unmarshal(body, &items); err == nil {
		for _, item := range items {
			for _, key := range []string{"ip", "address", "indicator"} {
				if v, ok := item[key].(string); ok && v != "" {
					result = append(result, v)
					break
				}
			}
		}
		return result
	}

	// Try object with "data" array
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err == nil {
		if data, ok := wrapper["data"]; ok {
			json.Unmarshal(data, &items)
			for _, item := range items {
				for _, key := range []string{"ip", "address", "indicator"} {
					if v, ok := item[key].(string); ok && v != "" {
						result = append(result, v)
						break
					}
				}
			}
		}
	}

	return result
}
