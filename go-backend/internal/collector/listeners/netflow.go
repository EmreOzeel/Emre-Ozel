package listeners

import "log"

// NetflowListener is a placeholder for future NetFlow/IPFIX ingestion.
type NetflowListener struct {
	host    string
	port    int
	running bool
}

// NewNetflowListener creates a new NetFlow listener (not yet implemented).
func NewNetflowListener(host string, port int) *NetflowListener {
	return &NetflowListener{host: host, port: port}
}

// Start logs that the listener is not yet implemented.
func (n *NetflowListener) Start() error {
	log.Printf("[netflow] listener not yet implemented (port %d)", n.port)
	return nil
}

// Stop marks the listener as not running.
func (n *NetflowListener) Stop() {
	n.running = false
}
