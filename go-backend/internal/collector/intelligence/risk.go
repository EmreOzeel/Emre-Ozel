package intelligence

import (
	"math"
	"sort"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// ComputeLiveRiskScores calculates a per-IP risk score based on deny/drop/reset
// ratios from recent flows (last 10 minutes).
func ComputeLiveRiskScores(db *gorm.DB) []map[string]interface{} {
	cutoff := time.Now().UTC().Add(-10 * time.Minute)

	type ipStats struct {
		SourceIP   string
		FlowCount  int64
		DenyCount  int64
		DropCount  int64
		ResetCount int64
	}

	var stats []ipStats
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(*) as flow_count, sum(deny_count) as deny_count, sum(drop_count) as drop_count, sum(reset_count) as reset_count").
		Where("last_seen >= ?", cutoff).
		Group("source_ip").
		Having("count(*) >= 2").
		Order("flow_count desc").
		Limit(100).
		Find(&stats)

	var result []map[string]interface{}
	for _, s := range stats {
		total := s.FlowCount
		if total == 0 {
			total = 1
		}
		denyRatio := float64(s.DenyCount) / float64(total)
		resetRatio := float64(s.ResetCount) / float64(total)

		score := int(denyRatio*40 + resetRatio*30 + math.Min(float64(s.FlowCount)/10, 30))
		if score > 100 {
			score = 100
		}

		var level string
		switch {
		case score >= 80:
			level = "critical"
		case score >= 60:
			level = "high"
		case score >= 30:
			level = "medium"
		default:
			level = "low"
		}

		var drivers []string
		if denyRatio > 0.3 {
			drivers = append(drivers, "high_deny_ratio")
		}
		if resetRatio > 0.2 {
			drivers = append(drivers, "high_reset_ratio")
		}
		if s.FlowCount > 20 {
			drivers = append(drivers, "high_volume")
		}

		result = append(result, map[string]interface{}{
			"source_ip":   s.SourceIP,
			"risk_score":  score,
			"risk_level":  level,
			"event_count": s.FlowCount,
			"drivers":     drivers,
		})
	}

	// Sort by risk_score descending
	sort.Slice(result, func(i, j int) bool {
		return result[i]["risk_score"].(int) > result[j]["risk_score"].(int)
	})

	return result
}
