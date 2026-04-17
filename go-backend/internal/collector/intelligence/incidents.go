package intelligence

import (
	"fmt"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

const (
	MergeWindowMinutes = 30
)

var sevRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
var rankSev = []string{"low", "medium", "high", "critical"}

// deriveSeverity determines incident severity from behavior type, confidence,
// and event count.
func deriveSeverity(behaviorType string, confidence float64, eventCount int) string {
	sev := 0 // low
	switch behaviorType {
	case "scanning", "suspicious":
		if confidence >= 0.8 {
			sev = 2 // high
		} else if confidence >= 0.7 {
			sev = 1 // medium
		}
	case "lateral_movement":
		if sev < 1 {
			sev = 1
		}
	case "unstable":
		if eventCount >= 3 && sev < 1 {
			sev = 1
		}
	}
	if eventCount >= 5 && sev < 2 {
		sev++
	}
	if confidence >= 0.9 && eventCount >= 3 {
		sev = 3
	}
	return rankSev[sev]
}

// UpsertIncidents creates or updates incidents from detected flow behaviors.
// It returns the count of newly created and updated incidents.
func UpsertIncidents(db *gorm.DB, behaviors []map[string]interface{}) (created, updated int) {
	now := time.Now().UTC()
	mergeWindow := now.Add(-MergeWindowMinutes * time.Minute)

	for _, b := range behaviors {
		behaviorType, _ := b["behavior_type"].(string)
		if behaviorType == "" || behaviorType == "normal" {
			continue
		}

		sourceIP, _ := b["source_ip"].(string)
		if sourceIP == "" {
			continue
		}

		confidence := getFloat(b, "confidence")
		eventCount := getIntVal(b, "event_count")
		if eventCount < 1 {
			eventCount = 1
		}

		severity := deriveSeverity(behaviorType, confidence, eventCount)

		// Try to find an existing open/investigating incident within merge window
		var existing models.LiveIncident
		err := db.Where(
			"source_ip = ? AND behavior_type = ? AND status IN (?,?) AND last_seen >= ?",
			sourceIP, behaviorType, "open", "investigating", mergeWindow,
		).Order("last_seen desc").First(&existing).Error

		if err == nil {
			// Update existing incident
			existing.LastSeen = now
			existing.EventCount++

			if confidence > 0 {
				existing.LatestConfidence = &confidence
			}

			// Re-derive severity but never downgrade
			newSev := deriveSeverity(behaviorType, confidence, existing.EventCount)
			if sevRank[newSev] > sevRank[existing.Severity] {
				existing.Severity = newSev
			}

			db.Save(&existing)
			updated++
		} else {
			// Create new incident
			incident := models.LiveIncident{
				SourceIP:     sourceIP,
				BehaviorType: behaviorType,
				Severity:     severity,
				Status:       "open",
				FirstSeen:    now,
				LastSeen:     now,
				EventCount:   eventCount,
			}
			if confidence > 0 {
				incident.LatestConfidence = &confidence
			}

			db.Create(&incident)
			created++

			// Notify admin for medium+ severity
			if sevRank[severity] >= sevRank["medium"] {
				notif := models.Notification{
					UserID:  AdminUserID,
					Type:    "drift_detected",
					Message: fmt.Sprintf("[AUTO] New %s incident: %s from %s", severity, behaviorType, sourceIP),
				}
				db.Create(&notif)
			}
		}
	}

	return created, updated
}

// getFloat extracts a float64 value from a map.
func getFloat(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

// getIntVal extracts an int value from a map.
func getIntVal(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	default:
		return 0
	}
}
