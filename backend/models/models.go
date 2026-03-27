package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Analysis struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	UserID      uint           `gorm:"not null" json:"user_id"`
	Filename    string         `gorm:"not null" json:"filename"`
	FileSize    int64          `json:"file_size"`
	Status      string         `gorm:"default:'pending'" json:"status"` // pending, running, completed, failed
	Error       string         `json:"error,omitempty"`
	ResultJSON  string         `gorm:"type:text" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	User        User           `gorm:"foreignKey:UserID" json:"-"`
}

// AnalysisResult is the full result of a PCAP analysis (stored as JSON in ResultJSON)
type AnalysisResult struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

type Summary struct {
	TotalPackets  int            `json:"total_packets"`
	TotalBytes    int64          `json:"total_bytes"`
	DurationSec   float64        `json:"duration_sec"`
	StartTime     *time.Time     `json:"start_time"`
	EndTime       *time.Time     `json:"end_time"`
	UniqueIPs     int            `json:"unique_ips"`
	Protocols     map[string]int `json:"protocols"`
	CriticalCount int            `json:"critical_count"`
	WarningCount  int            `json:"warning_count"`
	InfoCount     int            `json:"info_count"`
	TopTalkers    []TopTalker    `json:"top_talkers"`
}

type TopTalker struct {
	IP    string `json:"ip"`
	Bytes int64  `json:"bytes"`
}

type Finding struct {
	ID          int                    `json:"id"`
	Severity    string                 `json:"severity"` // critical, warning, info
	Category    string                 `json:"category"` // tcp, security, dns, http
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	SrcIP       string                 `json:"src_ip,omitempty"`
	DstIP       string                 `json:"dst_ip,omitempty"`
	SrcPort     int                    `json:"src_port,omitempty"`
	DstPort     int                    `json:"dst_port,omitempty"`
	PacketCount int                    `json:"packet_count,omitempty"`
	FirstSeen   *time.Time             `json:"first_seen,omitempty"`
	LastSeen    *time.Time             `json:"last_seen,omitempty"`
}
