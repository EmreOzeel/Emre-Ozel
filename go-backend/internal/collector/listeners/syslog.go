package listeners

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
)

// LineHandler is the callback invoked for each received syslog line.
type LineHandler func(line string)

// SyslogListener accepts syslog messages over both UDP and TCP on a single port.
type SyslogListener struct {
	host    string
	port    int
	handler LineHandler
	udpConn *net.UDPConn
	tcpLn   net.Listener
	running bool
	mu      sync.Mutex
	wg      sync.WaitGroup
}

// NewSyslogListener creates a listener bound to the given host:port that
// delivers each line to handler.
func NewSyslogListener(host string, port int, handler LineHandler) *SyslogListener {
	return &SyslogListener{host: host, port: port, handler: handler}
}

// Start begins listening on both UDP and TCP. Returns an error if either
// socket cannot be opened.
func (s *SyslogListener) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	// UDP
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}
	s.udpConn = udpConn

	// TCP
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("TCP listen: %w", err)
	}
	s.tcpLn = tcpLn

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	s.wg.Add(2)
	go s.readUDP()
	go s.acceptTCP()

	log.Printf("[syslog] listening on %s (UDP+TCP)", addr)
	return nil
}

// Stop shuts down both listeners and waits for goroutines to exit.
func (s *SyslogListener) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	s.wg.Wait()
}

// isRunning returns the current running state (thread-safe).
func (s *SyslogListener) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// readUDP reads datagrams from the UDP socket and delivers each as a line.
func (s *SyslogListener) readUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if !s.isRunning() {
				return
			}
			continue
		}
		line := string(buf[:n])
		s.handler(line)
	}
}

// acceptTCP accepts new TCP connections and spawns a goroutine for each.
func (s *SyslogListener) acceptTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if !s.isRunning() {
				return
			}
			continue
		}
		go s.handleTCPConn(conn)
	}
}

// handleTCPConn reads newline-delimited syslog messages from a single TCP connection.
func (s *SyslogListener) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 65536), 65536)
	for scanner.Scan() {
		if !s.isRunning() {
			return
		}
		s.handler(scanner.Text())
	}
}
