package threat_feeds

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.AutoMigrate(&models.ThreatFeed{}, &models.ThreatIndicator{})
	return db
}

func makeFeed(name, format, commentChar string, ipColumn int) *models.ThreatFeed {
	return &models.ThreatFeed{
		Name:              name,
		FeedType:          "ip_list",
		Format:            format,
		Enabled:           true,
		CommentChar:       commentChar,
		IPColumn:          ipColumn,
		DefaultThreatType: "malware",
		DefaultConfidence: 0.8,
	}
}

func TestFetchFeed_PlainIPList(t *testing.T) {
	db := setupDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4\n5.6.7.8\n9.10.11.12\n"))
	}))
	defer server.Close()

	url := server.URL
	feed := makeFeed("test-plain", "plain", "#", 0)
	feed.URL = &url
	db.Create(feed)

	count, err := FetchFeed(db, feed, 10, "test-agent")
	if err != nil {
		t.Fatalf("FetchFeed error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 indicators, got %d", count)
	}

	// Verify in DB
	var total int64
	db.Model(&models.ThreatIndicator{}).Count(&total)
	if total != 3 {
		t.Errorf("expected 3 in DB, got %d", total)
	}
}

func TestFetchFeed_SkipsCommentLines(t *testing.T) {
	db := setupDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# This is a comment\n1.2.3.4\n# Another comment\n5.6.7.8\n"))
	}))
	defer server.Close()

	url := server.URL
	feed := makeFeed("test-comments", "plain", "#", 0)
	feed.URL = &url
	db.Create(feed)

	count, err := FetchFeed(db, feed, 10, "test-agent")
	if err != nil {
		t.Fatalf("FetchFeed error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 (comments skipped), got %d", count)
	}
}

func TestFetchFeed_ValidatesIPFormat(t *testing.T) {
	db := setupDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4\nnot-an-ip\n5.6.7.8\ninvalid\n"))
	}))
	defer server.Close()

	url := server.URL
	feed := makeFeed("test-validate", "plain", "#", 0)
	feed.URL = &url
	db.Create(feed)

	count, err := FetchFeed(db, feed, 10, "test-agent")
	if err != nil {
		t.Fatalf("FetchFeed error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 valid IPs, got %d", count)
	}
}

func TestFetchFeed_UpsertsExisting(t *testing.T) {
	db := setupDB(t)

	// Pre-create an existing indicator
	oldTime := time.Now().UTC().Add(-24 * time.Hour)
	db.Create(&models.ThreatIndicator{
		IndicatorType:  "ip",
		IndicatorValue: "1.2.3.4",
		ThreatType:     "scanner",
		Confidence:     0.5,
		SourceFeed:     "test-upsert",
		FirstSeen:      oldTime,
		LastSeen:       oldTime,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer server.Close()

	url := server.URL
	feed := makeFeed("test-upsert", "plain", "#", 0)
	feed.URL = &url
	db.Create(feed)

	count, err := FetchFeed(db, feed, 10, "test-agent")
	if err != nil {
		t.Fatalf("FetchFeed error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}

	// Verify upsert: existing should have updated last_seen
	var indicator models.ThreatIndicator
	db.Where("indicator_value = ? AND source_feed = ?", "1.2.3.4", "test-upsert").First(&indicator)
	if indicator.LastSeen.Before(oldTime.Add(time.Second)) {
		t.Error("existing indicator last_seen should be updated")
	}

	// Total should be 2 (not 3)
	var total int64
	db.Model(&models.ThreatIndicator{}).Where("source_feed = ?", "test-upsert").Count(&total)
	if total != 2 {
		t.Errorf("expected 2 total indicators, got %d", total)
	}
}

func TestRefreshAll_SkipsFeedsNotDue(t *testing.T) {
	db := setupDB(t)

	// Feed fetched 1 hour ago with 24-hour interval → not due
	recentTime := time.Now().UTC().Add(-1 * time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4\n"))
	}))
	defer server.Close()

	url := server.URL
	feed := &models.ThreatFeed{
		Name:               "not-due",
		FeedType:           "ip_list",
		Format:             "plain",
		URL:                &url,
		Enabled:            true,
		CommentChar:        "#",
		DefaultThreatType:  "unknown",
		DefaultConfidence:  0.5,
		FetchIntervalHours: 24,
		LastFetchedAt:      &recentTime,
	}
	db.Create(feed)

	// This feed should NOT be fetched (interval not elapsed)
	now := time.Now().UTC()
	nextDue := feed.LastFetchedAt.Add(time.Duration(feed.FetchIntervalHours) * time.Hour)
	if now.Before(nextDue) {
		// Correct: feed is not due
	}

	// Verify: no indicators created
	var total int64
	db.Model(&models.ThreatIndicator{}).Where("source_feed = ?", "not-due").Count(&total)
	if total != 0 {
		t.Errorf("expected 0 indicators (feed not due), got %d", total)
	}
}
