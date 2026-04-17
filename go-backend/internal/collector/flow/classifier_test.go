package flow

import (
	"testing"
	"time"
)

func makeFlow(allow, deny, drop, reset, alert int, bytesIn, bytesOut int64, durSec float64) *ActiveFlow {
	now := time.Now().UTC()
	return &ActiveFlow{
		FirstSeen:     now.Add(-time.Duration(durSec * float64(time.Second))),
		LastSeen:      now,
		EventCount:    allow + deny + drop + reset + alert,
		AllowCount:    allow,
		DenyCount:     deny,
		DropCount:     drop,
		ResetCount:    reset,
		AlertCount:    alert,
		TotalBytesIn:  bytesIn,
		TotalBytesOut: bytesOut,
	}
}

func TestClassify_Scanning(t *testing.T) {
	// deny-only, 0 bytes, < 5s
	f := makeFlow(0, 3, 0, 0, 0, 0, 0, 2)
	cls := ClassifyFlow(f)
	if cls.FlowType != "scanning" {
		t.Errorf("expected scanning, got %s", cls.FlowType)
	}
}

func TestClassify_Blocked(t *testing.T) {
	// deny-only, significant bytes, > 5s
	f := makeFlow(0, 5, 0, 0, 0, 5000, 1000, 10)
	cls := ClassifyFlow(f)
	if cls.FlowType != "blocked" {
		t.Errorf("expected blocked, got %s", cls.FlowType)
	}
}

func TestClassify_Unstable(t *testing.T) {
	// allow + reset mix
	f := makeFlow(5, 0, 0, 3, 0, 1000, 1000, 10)
	cls := ClassifyFlow(f)
	if cls.FlowType != "unstable" {
		t.Errorf("expected unstable, got %s", cls.FlowType)
	}
}

func TestClassify_Suspicious(t *testing.T) {
	// alert_count > 0
	f := makeFlow(5, 0, 0, 0, 2, 1000, 1000, 10)
	cls := ClassifyFlow(f)
	if cls.FlowType != "suspicious" {
		t.Errorf("expected suspicious, got %s", cls.FlowType)
	}
}

func TestClassify_Normal(t *testing.T) {
	f := makeFlow(10, 0, 0, 0, 0, 5000, 3000, 30)
	cls := ClassifyFlow(f)
	if cls.FlowType != "normal" {
		t.Errorf("expected normal, got %s", cls.FlowType)
	}
}

func TestClassify_ResetRatio(t *testing.T) {
	// 3 resets, 7 allows = 10 total → reset_ratio = 0.3
	f := makeFlow(7, 0, 0, 3, 0, 1000, 1000, 10)
	cls := ClassifyFlow(f)
	expected := 0.3
	if cls.ResetRatio < expected-0.01 || cls.ResetRatio > expected+0.01 {
		t.Errorf("expected reset_ratio ~%.1f, got %.4f", expected, cls.ResetRatio)
	}
}

func TestClassify_AsymmetricBehavior(t *testing.T) {
	// bytes_in=50000, bytes_out=100 → ratio 500:1 → asymmetric=true
	f := makeFlow(10, 0, 0, 0, 0, 50000, 100, 30)
	cls := ClassifyFlow(f)
	if !cls.AsymmetricBehavior {
		t.Error("expected asymmetric_behavior=true for 500:1 ratio")
	}
}
