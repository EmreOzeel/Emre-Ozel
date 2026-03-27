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
	Summary     Summary         `json:"summary"`
	Findings    []Finding       `json:"findings"`
	Connections []TCPConnection `json:"connections"`
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

// TCPConnection represents a single TCP session with step-by-step packet flow
type TCPConnection struct {
	ID           int              `json:"id"`
	ClientIP     string           `json:"client_ip"`   // SYN initiator
	ServerIP     string           `json:"server_ip"`
	ClientPort   int              `json:"client_port"`
	ServerPort   int              `json:"server_port"`
	State        string           `json:"state"` // established, half-open, reset, fin-closed
	StartTime    *time.Time       `json:"start_time"`
	DurationSec  float64          `json:"duration_sec"`
	BytesClient  int64            `json:"bytes_client"` // client→server
	BytesServer  int64            `json:"bytes_server"` // server→client
	PacketCount  int              `json:"packet_count"`
	Steps        []ConnectionStep `json:"steps"`
}

// ConnectionStep is a single packet event within a TCP connection
type ConnectionStep struct {
	RelTimeSec  float64 `json:"rel_time_sec"` // seconds from connection start
	Direction   string  `json:"direction"`    // "→" (client→server) or "←" (server→client)
	Flags       string  `json:"flags"`
	SeqNum      uint32  `json:"seq_num"`
	AckNum      uint32  `json:"ack_num"`
	PayloadLen  int     `json:"payload_len"`
	Description string  `json:"description"`
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
