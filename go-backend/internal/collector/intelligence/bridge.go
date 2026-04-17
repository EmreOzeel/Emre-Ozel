package intelligence

import (
	"fmt"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

const (
	WindowMinutes           = 10
	BlockedFlowThreshold    = 5
	PortScanDstThreshold    = 10
	PortScanPortThreshold   = 15
	ResetFlowThreshold      = 3
	ScanningFlowThreshold   = 3
	SuspiciousFlowThreshold = 2
	AdminUserID             = 1
)

// ScanPatterns runs all pattern detectors against recent live flows and
// creates notifications when thresholds are exceeded.
func ScanPatterns(db *gorm.DB) {
	scanBlockedFlowSpike(db)
	scanPortScan(db)
	scanRepeatedReset(db)
	scanScanningFlows(db)
	scanSuspiciousFlows(db)
}

// scanBlockedFlowSpike detects sources with a spike of denied/dropped/blocked
// flows within the observation window.
func scanBlockedFlowSpike(db *gorm.DB) {
	cutoff := time.Now().UTC().Add(-WindowMinutes * time.Minute)

	type result struct {
		SourceIP string
		Total    int64
	}

	var rows []result
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(*) as total").
		Where("last_seen >= ? AND (state IN (?,?) OR flow_type = ?)", cutoff, "denied", "dropped", "blocked").
		Group("source_ip").
		Having("count(*) > ?", BlockedFlowThreshold).
		Find(&rows)

	for _, r := range rows {
		notify(db, fmt.Sprintf("Blocked flow spike: %s had %d denied/dropped flows in last %d min",
			r.SourceIP, r.Total, WindowMinutes))
	}
}

// scanPortScan detects sources with scanning flow types or that contact many
// distinct destinations / ports.
func scanPortScan(db *gorm.DB) {
	cutoff := time.Now().UTC().Add(-WindowMinutes * time.Minute)

	// Part 1: flow_type = scanning grouped by source_ip
	type scanResult struct {
		SourceIP string
		Total    int64
	}

	var scanRows []scanResult
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(*) as total").
		Where("last_seen >= ? AND flow_type = ?", cutoff, "scanning").
		Group("source_ip").
		Having("count(*) >= ?", ScanningFlowThreshold).
		Find(&scanRows)

	for _, r := range scanRows {
		notify(db, fmt.Sprintf("Port scan detected (scanning flows): %s had %d scanning flows in last %d min",
			r.SourceIP, r.Total, WindowMinutes))
	}

	// Part 2: distinct destinations > threshold
	type dstResult struct {
		SourceIP     string
		DistinctDsts int64
	}

	var dstRows []dstResult
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(distinct destination_ip) as distinct_dsts").
		Where("last_seen >= ?", cutoff).
		Group("source_ip").
		Having("count(distinct destination_ip) > ?", PortScanDstThreshold).
		Find(&dstRows)

	for _, r := range dstRows {
		notify(db, fmt.Sprintf("Port scan detected (destinations): %s contacted %d distinct destinations in last %d min",
			r.SourceIP, r.DistinctDsts, WindowMinutes))
	}

	// Part 3: distinct ports > threshold
	type portResult struct {
		SourceIP      string
		DistinctPorts int64
	}

	var portRows []portResult
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(distinct destination_port) as distinct_ports").
		Where("last_seen >= ?", cutoff).
		Group("source_ip").
		Having("count(distinct destination_port) > ?", PortScanPortThreshold).
		Find(&portRows)

	for _, r := range portRows {
		notify(db, fmt.Sprintf("Port scan detected (ports): %s probed %d distinct ports in last %d min",
			r.SourceIP, r.DistinctPorts, WindowMinutes))
	}
}

// scanRepeatedReset detects source-destination pairs with repeated connection
// resets or unstable flow types.
func scanRepeatedReset(db *gorm.DB) {
	cutoff := time.Now().UTC().Add(-WindowMinutes * time.Minute)

	type result struct {
		SourceIP      string
		DestinationIP string
		Total         int64
	}

	var rows []result
	db.Model(&models.LiveFlow{}).
		Select("source_ip, destination_ip, count(*) as total").
		Where("last_seen >= ? AND (state = ? OR flow_type = ?)", cutoff, "reset", "unstable").
		Group("source_ip, destination_ip").
		Having("count(*) > ?", ResetFlowThreshold).
		Find(&rows)

	for _, r := range rows {
		notify(db, fmt.Sprintf("Repeated resets: %s -> %s had %d reset/unstable flows in last %d min",
			r.SourceIP, r.DestinationIP, r.Total, WindowMinutes))
	}
}

// scanScanningFlows detects sources classified as scanning by the flow engine.
func scanScanningFlows(db *gorm.DB) {
	cutoff := time.Now().UTC().Add(-WindowMinutes * time.Minute)

	type result struct {
		SourceIP string
		Total    int64
	}

	var rows []result
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(*) as total").
		Where("last_seen >= ? AND flow_type = ?", cutoff, "scanning").
		Group("source_ip").
		Having("count(*) >= ?", ScanningFlowThreshold).
		Find(&rows)

	for _, r := range rows {
		notify(db, fmt.Sprintf("Scanning activity: %s had %d scanning flows in last %d min",
			r.SourceIP, r.Total, WindowMinutes))
	}
}

// scanSuspiciousFlows detects sources with suspicious flow classifications.
func scanSuspiciousFlows(db *gorm.DB) {
	cutoff := time.Now().UTC().Add(-WindowMinutes * time.Minute)

	type result struct {
		SourceIP string
		Total    int64
	}

	var rows []result
	db.Model(&models.LiveFlow{}).
		Select("source_ip, count(*) as total").
		Where("last_seen >= ? AND flow_type = ?", cutoff, "suspicious").
		Group("source_ip").
		Having("count(*) >= ?", SuspiciousFlowThreshold).
		Find(&rows)

	for _, r := range rows {
		notify(db, fmt.Sprintf("Suspicious activity: %s had %d suspicious flows in last %d min",
			r.SourceIP, r.Total, WindowMinutes))
	}
}

// notify creates a drift_detected notification for the admin user.
func notify(db *gorm.DB, message string) {
	notif := models.Notification{
		UserID:  AdminUserID,
		Type:    "drift_detected",
		Message: fmt.Sprintf("[AUTO] %s", message),
	}
	db.Create(&notif)
}
