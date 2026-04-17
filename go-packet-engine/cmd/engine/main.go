package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/capture"
	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/config"
	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/flow"
	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/parser"
	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/sender"
	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/stream"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("[engine] starting go-packet-engine")

	cfg := config.Load()
	log.Printf("[engine] interface=%s snaplen=%d workers=%d batch=%d flush=%s flow_timeout=%s",
		cfg.Interface, cfg.SnapLen, cfg.WorkerCount, cfg.BatchSize,
		cfg.FlushInterval, cfg.FlowTimeout)

	// Capture
	cap, err := capture.New(cfg)
	if err != nil {
		log.Fatalf("[engine] capture init failed: %v", err)
	}
	defer cap.Close()

	// Flow tracker
	tracker := flow.NewFlowTracker(cfg.FlowTimeout)

	// Sender
	snd := sender.New(cfg.BackendURL, cfg.BackendToken, cfg.BatchSize)

	// Stream analyzer
	analyzer := stream.NewStreamAnalyzer()

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start capture
	packets := cap.Start(ctx)

	var pktCount atomic.Int64
	var alertCount atomic.Int64

	// Alert consumer goroutine
	go func() {
		for alert := range analyzer.Alerts() {
			alertCount.Add(1)
			alertData := map[string]interface{}{
				"timestamp":  alert.Timestamp.Format(time.RFC3339),
				"src_ip":     alert.SrcIP,
				"dst_ip":     alert.DstIP,
				"dst_port":   alert.DstPort,
				"protocol":   alert.Protocol,
				"alert_type": alert.AlertType,
				"message":    alert.Message,
				"value":      alert.Value,
				"threshold":  alert.Threshold,
			}
			if err := snd.SendAlert(ctx, alertData); err != nil {
				log.Printf("[engine] alert send error: %v", err)
			}
		}
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for pkt := range packets {
				pktCount.Add(1)

				var parsed *parser.ParsedPacket

				// Try DNS first (works for both UDP and TCP DNS)
				if pkt.Layer(layers.LayerTypeDNS) != nil {
					parsed = parser.ParseDNS(pkt)
				}

				// Try TCP
				if parsed == nil && pkt.Layer(layers.LayerTypeTCP) != nil {
					parsed = parser.ParseTCP(pkt)
				}

				// Fallback: UDP without DNS (extract IP info)
				if parsed == nil {
					parsed = parseGeneric(pkt)
				}

				if parsed != nil {
					tracker.Update(parsed)
					analyzer.Analyze(parsed)
				}
			}
		}(i)
	}

	// Management HTTP server on :8080
	mgmtServer := startManagementServer(analyzer, tracker, &pktCount, &alertCount)
	defer mgmtServer.Close()

	// Flush ticker — flush expired flows and send to backend
	flushTicker := time.NewTicker(cfg.FlushInterval)
	defer flushTicker.Stop()

	// Stats ticker
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	log.Println("[engine] capture running")

	for {
		select {
		case <-flushTicker.C:
			expired := tracker.FlushExpired(time.Now())
			for _, f := range expired {
				event := snd.FlowToEvent(f)
				snd.Add(event)
			}
			if err := snd.Flush(ctx); err != nil {
				log.Printf("[engine] flush error: %v", err)
			}

		case <-statsTicker.C:
			count := pktCount.Load()
			stats := tracker.Stats()
			batchLen := snd.BatchLen()
			alerts := alertCount.Load()
			log.Printf("[engine] stats: packets_total=%d active_flows=%d pending_batch=%d alerts_total=%d",
				count, stats["active_flows"], batchLen, alerts)

		case sig := <-sigCh:
			log.Printf("[engine] received %s, shutting down...", sig)
			cancel()

			// Wait for workers to finish
			wg.Wait()

			// Final flush
			expired := tracker.FlushExpired(time.Now().Add(cfg.FlowTimeout * 2))
			for _, f := range expired {
				event := snd.FlowToEvent(f)
				snd.Add(event)
			}
			if err := snd.Flush(context.Background()); err != nil {
				log.Printf("[engine] final flush error: %v", err)
			}
			log.Println("[engine] shutdown complete")
			return
		}
	}
}

// parseGeneric extracts basic IP info from non-TCP/non-DNS packets (UDP, ICMP, etc.)
func parseGeneric(pkt gopacket.Packet) *parser.ParsedPacket {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return nil
	}

	p := &parser.ParsedPacket{
		Timestamp: pkt.Metadata().Timestamp,
	}

	switch nl := netLayer.(type) {
	case *layers.IPv4:
		p.SrcIP = nl.SrcIP.String()
		p.DstIP = nl.DstIP.String()
		p.Protocol = nl.Protocol.String()
	case *layers.IPv6:
		p.SrcIP = nl.SrcIP.String()
		p.DstIP = nl.DstIP.String()
		p.Protocol = nl.NextHeader.String()
	default:
		return nil
	}

	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		p.SrcPort = uint16(udp.SrcPort)
		p.DstPort = uint16(udp.DstPort)
		p.Protocol = "UDP"
		p.PayloadSize = len(udp.Payload)
	}

	return p
}

// ── Management HTTP Server ──────────────────────────────────────────────────

func startManagementServer(
	analyzer *stream.StreamAnalyzer,
	tracker *flow.FlowTracker,
	pktCount *atomic.Int64,
	alertCount *atomic.Int64,
) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/watches", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			watches := analyzer.ListWatches()
			writeJSON(w, http.StatusOK, watches)

		case http.MethodPost:
			var rule stream.WatchRule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if rule.TargetIP == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_ip required"})
				return
			}
			analyzer.AddWatch(rule)
			log.Printf("[mgmt] watch added: %s:%d", rule.TargetIP, rule.TargetPort)
			writeJSON(w, http.StatusCreated, rule)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/watches/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Parse /watches/{ip}/{port}
		path := strings.TrimPrefix(r.URL.Path, "/watches/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /watches/{ip}/{port}"})
			return
		}
		ip := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid port"})
			return
		}

		analyzer.RemoveWatch(ip, uint16(port))
		log.Printf("[mgmt] watch removed: %s:%d", ip, port)
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		flowStats := tracker.Stats()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"packets_total":  pktCount.Load(),
			"active_flows":   flowStats["active_flows"],
			"alerts_total":   alertCount.Load(),
			"watch_count":    len(analyzer.ListWatches()),
		})
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		log.Println("[mgmt] management server listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[mgmt] server error: %v", err)
		}
	}()

	return server
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
