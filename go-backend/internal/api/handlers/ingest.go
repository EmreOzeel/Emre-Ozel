package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// verifyPacketEngineToken validates the Bearer token on packet-engine ingest
// requests against the configured PACKET_ENGINE_TOKEN. It writes the error
// response and returns false when the token is missing, unset, or wrong.
func (h *Handler) verifyPacketEngineToken(c *gin.Context) bool {
	if h.Cfg.PacketEngineToken == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"detail": "Packet engine ingest not configured"})
		return false
	}
	authz := c.GetHeader("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Missing or invalid Authorization header"})
		return false
	}
	if strings.TrimPrefix(authz, "Bearer ") != h.Cfg.PacketEngineToken {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Invalid packet engine token"})
		return false
	}
	return true
}

type packetEventsPayload struct {
	Events []map[string]interface{} `json:"events"`
}

// IngestPacketEvents receives normalized packet events (completed flows) from
// the Go packet engine and stores each as a LiveEvent row.
func (h *Handler) IngestPacketEvents(c *gin.Context) {
	if !h.verifyPacketEngineToken(c) {
		return
	}

	var payload packetEventsPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid JSON body"})
		return
	}

	rows := make([]models.LiveEvent, 0, len(payload.Events))
	for _, ev := range payload.Events {
		rows = append(rows, packetEventToLiveEvent(ev))
	}

	accepted := 0
	if len(rows) > 0 {
		if err := h.DB.Create(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to persist events"})
			return
		}
		accepted = len(rows)
	}

	c.JSON(http.StatusOK, gin.H{"accepted": accepted})
}

// packetEventToLiveEvent maps one packet-engine event map to a LiveEvent,
// applying the same defaults as the (now removed) Python ingest endpoint.
func packetEventToLiveEvent(ev map[string]interface{}) models.LiveEvent {
	span := "span"
	return models.LiveEvent{
		SourceID:        strOr(ev, "source_id", "packet_engine"),
		DeviceType:      strOr(ev, "device_type", "packet_engine"),
		DeviceRole:      &span,
		ParserID:        strOr(ev, "parser_id", "gopacket"),
		EventTime:       eventTimeFrom(ev, "first_seen"),
		SourceIP:        strOr(ev, "source_ip", "0.0.0.0"),
		DestinationIP:   strOr(ev, "destination_ip", "0.0.0.0"),
		SourcePort:      optInt(ev, "source_port"),
		DestinationPort: optInt(ev, "destination_port"),
		Protocol:        optStr(ev, "protocol"),
		Action:          strOr(ev, "action", "allow"),
		BytesIn:         optInt(ev, "bytes_in"),
		BytesOut:        optInt(ev, "bytes_out"),
		PacketsIn:       optInt(ev, "packet_count"),
		DurationMs:      optInt(ev, "duration_ms"),
	}
}

type packetAlertPayload struct {
	Timestamp string  `json:"timestamp"`
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	DstPort   int     `json:"dst_port"`
	Protocol  string  `json:"protocol"`
	AlertType string  `json:"alert_type"`
	Message   string  `json:"message"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
}

// IngestPacketAlert receives a streaming-analysis alert from the packet engine,
// records an admin notification, and annotates any open incident for the source.
func (h *Handler) IngestPacketAlert(c *gin.Context) {
	if !h.verifyPacketEngineToken(c) {
		return
	}

	var p packetAlertPayload
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid JSON body"})
		return
	}

	// 1. Notification for the admin user (user_id=1).
	notif := models.Notification{
		UserID:  1,
		Type:    "drift_detected",
		Message: fmt.Sprintf("[STREAM ALERT] %s: %s", p.AlertType, p.Message),
	}
	h.DB.Create(&notif)

	// 2. Annotate the first open/investigating incident for this source IP.
	var incident models.LiveIncident
	if err := h.DB.
		Where("source_ip = ? AND status IN ?", p.SrcIP, []string{"open", "investigating"}).
		First(&incident).Error; err == nil {
		summary := fmt.Sprintf("[%s] %s (value=%v, threshold=%v)",
			p.AlertType, p.Message, p.Value, p.Threshold)
		incident.LastActivitySummary = &summary
		h.DB.Save(&incident)
	}

	c.JSON(http.StatusOK, gin.H{"accepted": true})
}

// ── small event-map helpers (nil pointer when a field is absent) ──

func strOr(m map[string]interface{}, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func optStr(m map[string]interface{}, key string) *string {
	if v, ok := m[key].(string); ok && v != "" {
		return &v
	}
	return nil
}

func optInt(m map[string]interface{}, key string) *int {
	switch n := m[key].(type) {
	case float64:
		i := int(n)
		return &i
	case int:
		return &n
	}
	return nil
}

func eventTimeFrom(m map[string]interface{}, key string) time.Time {
	if s, ok := m[key].(string); ok && s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t
		}
	}
	return time.Now().UTC()
}
