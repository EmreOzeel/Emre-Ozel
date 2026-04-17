package stream

import (
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/parser"
)

func newTestAnalyzer() *StreamAnalyzer {
	return NewStreamAnalyzer()
}

func drainAlerts(a *StreamAnalyzer) []Alert {
	var alerts []Alert
	for {
		select {
		case al := <-a.Alerts():
			alerts = append(alerts, al)
		default:
			return alerts
		}
	}
}

func TestAlertEmittedWhenPPSExceeded(t *testing.T) {
	a := newTestAnalyzer()
	a.AddWatch(WatchRule{
		TargetIP: "10.0.0.1",
		MaxPPS:   5,
	})

	base := time.Now()
	// Send 20 packets over 2 seconds → 10 PPS, exceeds 5
	for i := 0; i < 20; i++ {
		ts := base.Add(time.Duration(i*100) * time.Millisecond)
		a.Analyze(&parser.ParsedPacket{
			Timestamp:   ts,
			SrcIP:       "192.168.1.1",
			DstIP:       "10.0.0.1",
			DstPort:     80,
			Protocol:    "TCP",
			PayloadSize: 100,
		})
	}

	alerts := drainAlerts(a)
	found := false
	for _, al := range alerts {
		if al.AlertType == "threshold_exceeded" && al.Threshold == 5 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PPS threshold_exceeded alert, got %d alerts: %+v", len(alerts), alerts)
	}
}

func TestNoAlertWhenBelowThreshold(t *testing.T) {
	a := newTestAnalyzer()
	a.AddWatch(WatchRule{
		TargetIP: "10.0.0.1",
		MaxPPS:   1000,
	})

	base := time.Now()
	// Send 5 packets over 5 seconds → 1 PPS, well below 1000
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		a.Analyze(&parser.ParsedPacket{
			Timestamp:   ts,
			SrcIP:       "192.168.1.1",
			DstIP:       "10.0.0.1",
			DstPort:     80,
			Protocol:    "TCP",
			PayloadSize: 50,
		})
	}

	alerts := drainAlerts(a)
	for _, al := range alerts {
		if al.AlertType == "threshold_exceeded" {
			t.Errorf("unexpected threshold alert: %+v", al)
		}
	}
}

func TestDNSAnomalyNXDOMAINRate(t *testing.T) {
	a := newTestAnalyzer()

	base := time.Now()
	// Send 12 DNS responses: 8 NXDOMAIN + 4 NOERROR = 66% NX rate
	for i := 0; i < 12; i++ {
		rcode := "NoError"
		if i < 8 {
			rcode = "NXDomain"
		}
		a.Analyze(&parser.ParsedPacket{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			SrcIP:     "8.8.8.8",
			DstIP:     "10.0.0.5",
			Protocol:  "UDP",
			DNSInfo: &parser.DNSInfo{
				IsQuery: false,
				RCode:   rcode,
				Domain:  "test.example.com",
			},
		})
	}

	alerts := drainAlerts(a)
	found := false
	for _, al := range alerts {
		if al.AlertType == "dns_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected dns_anomaly alert for NXDOMAIN rate > 50%")
	}
}

func TestTLSAnomalyIPAsSNI(t *testing.T) {
	a := newTestAnalyzer()

	a.Analyze(&parser.ParsedPacket{
		Timestamp: time.Now(),
		SrcIP:     "10.0.0.5",
		DstIP:     "203.0.113.1",
		DstPort:   443,
		Protocol:  "TCP",
		TLSInfo: &parser.TLSInfo{
			IsClientHello: true,
			SNI:           "203.0.113.1", // IP as SNI = anomaly
			Version:       "TLS 1.3",
		},
	})

	alerts := drainAlerts(a)
	found := false
	for _, al := range alerts {
		if al.AlertType == "tls_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected tls_anomaly alert for IP-as-SNI")
	}
}

func TestTLSNoAlertForNormalSNI(t *testing.T) {
	a := newTestAnalyzer()

	a.Analyze(&parser.ParsedPacket{
		Timestamp: time.Now(),
		SrcIP:     "10.0.0.5",
		DstIP:     "203.0.113.1",
		DstPort:   443,
		Protocol:  "TCP",
		TLSInfo: &parser.TLSInfo{
			IsClientHello: true,
			SNI:           "example.com",
			Version:       "TLS 1.3",
		},
	})

	alerts := drainAlerts(a)
	for _, al := range alerts {
		if al.AlertType == "tls_anomaly" {
			t.Errorf("unexpected tls_anomaly alert for normal hostname SNI: %+v", al)
		}
	}
}

func TestAddRemoveListWatches(t *testing.T) {
	a := newTestAnalyzer()

	a.AddWatch(WatchRule{TargetIP: "10.0.0.1", TargetPort: 80, MaxPPS: 100})
	a.AddWatch(WatchRule{TargetIP: "10.0.0.2", TargetPort: 0, MaxBPS: 5000})

	watches := a.ListWatches()
	if len(watches) != 2 {
		t.Fatalf("expected 2 watches, got %d", len(watches))
	}

	a.RemoveWatch("10.0.0.1", 80)

	watches = a.ListWatches()
	if len(watches) != 1 {
		t.Fatalf("expected 1 watch after remove, got %d", len(watches))
	}
	if watches[0].TargetIP != "10.0.0.2" {
		t.Errorf("expected remaining watch for 10.0.0.2, got %s", watches[0].TargetIP)
	}
}

func TestWindowSlides(t *testing.T) {
	a := newTestAnalyzer()
	a.AddWatch(WatchRule{
		TargetIP: "10.0.0.1",
		MaxPPS:   10000, // high threshold so no alerts
	})

	base := time.Now().Add(-2 * time.Minute)

	// Send packets 90s ago — should be pruned
	for i := 0; i < 5; i++ {
		a.Analyze(&parser.ParsedPacket{
			Timestamp:   base.Add(time.Duration(i) * time.Second),
			SrcIP:       "192.168.1.1",
			DstIP:       "10.0.0.1",
			Protocol:    "TCP",
			PayloadSize: 100,
		})
	}

	// Send a recent packet — this triggers window trimming
	recent := time.Now()
	a.Analyze(&parser.ParsedPacket{
		Timestamp:   recent,
		SrcIP:       "192.168.1.1",
		DstIP:       "10.0.0.1",
		Protocol:    "TCP",
		PayloadSize: 100,
	})

	// Check window: old samples should be pruned
	a.mu.RLock()
	rule := a.watchlist[watchKey("10.0.0.1", 0)]
	windowLen := len(rule.window)
	a.mu.RUnlock()

	if windowLen != 1 {
		t.Errorf("expected 1 sample in window after pruning (only the recent one), got %d", windowLen)
	}
}
