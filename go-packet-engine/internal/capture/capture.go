package capture

import (
	"context"
	"fmt"
	"log"

	"github.com/emreozeel/pcap-analyzer/packet-engine/internal/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Capture wraps a live pcap handle and produces a channel of packets.
type Capture struct {
	cfg    *config.Config
	handle *pcap.Handle
}

// New opens a live pcap handle on the configured interface.
func New(cfg *config.Config) (*Capture, error) {
	handle, err := pcap.OpenLive(
		cfg.Interface,
		cfg.SnapLen,
		cfg.Promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive(%s): %w", cfg.Interface, err)
	}

	if cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("BPF filter %q: %w", cfg.BPFFilter, err)
		}
		log.Printf("[capture] BPF filter set: %s", cfg.BPFFilter)
	}

	return &Capture{cfg: cfg, handle: handle}, nil
}

// Start returns a channel that emits captured packets until ctx is cancelled.
func (c *Capture) Start(ctx context.Context) <-chan gopacket.Packet {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.NoCopy = true
	ch := make(chan gopacket.Packet, 1024)

	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pkt, err := src.NextPacket()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			select {
			case ch <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}

// Stats returns pcap capture statistics.
func (c *Capture) Stats() (*pcap.Stats, error) {
	return c.handle.Stats()
}

// Close releases the pcap handle.
func (c *Capture) Close() {
	c.handle.Close()
}
