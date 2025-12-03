package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanResult represents the result of a network scan
type ScanResult struct {
	Target  string       `json:"target"`
	Status  string       `json:"status"`
	Ports   []PortResult `json:"ports,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// PortResult represents the status of a single port
type PortResult struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// Scanner handles network scanning operations
type Scanner struct {
	Target      string
	Ports       []int
	ScanUDP     bool
	Threads     int
	Timeout     time.Duration
	BannerGrab  bool
	results     []PortResult
	resultsLock sync.Mutex
}

// NewScanner creates a new scanner instance
func NewScanner(target string, ports []int, udp bool, threads int, timeoutMs int, bannerGrab bool) *Scanner {
	if threads <= 0 {
		threads = 10
	}
	if timeoutMs <= 0 {
		timeoutMs = 1000
	}
	
	// If no ports specified, scan top 20 common ports
	if len(ports) == 0 {
		ports = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443}
	}

	return &Scanner{
		Target:     target,
		Ports:      ports,
		ScanUDP:    udp,
		Threads:    threads,
		Timeout:    time.Duration(timeoutMs) * time.Millisecond,
		BannerGrab: bannerGrab,
		results:    make([]PortResult, 0),
	}
}

// Scan performs the network scan
func (s *Scanner) Scan() ([]byte, error) {
	// Parse target range (CIDR or single IP)
	ips, err := parseTarget(s.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}

	var allResults []ScanResult

	// Scan each IP
	for _, ip := range ips {
		hostResult := ScanResult{
			Target: ip,
			Status: "up", // Assume up for now, or implement ping check
		}

		// Use a worker pool for ports
		portsChan := make(chan int, len(s.Ports))
		var wg sync.WaitGroup

		// Start workers
		for i := 0; i < s.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for port := range portsChan {
					result := s.scanPort(ip, port)
					if result != nil {
						s.resultsLock.Lock()
						hostResult.Ports = append(hostResult.Ports, *result)
						s.resultsLock.Unlock()
					}
				}
			}()
		}

		// Feed ports
		for _, port := range s.Ports {
			portsChan <- port
		}
		close(portsChan)

		// Wait for completion
		wg.Wait()

		// Sort ports
		sort.Slice(hostResult.Ports, func(i, j int) bool {
			return hostResult.Ports[i].Port < hostResult.Ports[j].Port
		})

		if len(hostResult.Ports) > 0 {
			allResults = append(allResults, hostResult)
		}
	}

	return json.MarshalIndent(allResults, "", "  ")
}

// scanPort scans a single port on a target IP
func (s *Scanner) scanPort(ip string, port int) *PortResult {
	target := fmt.Sprintf("%s:%d", ip, port)
	proto := "tcp"
	if s.ScanUDP {
		proto = "udp"
	}

	conn, err := net.DialTimeout(proto, target, s.Timeout)
	if err != nil {
		return nil // Port closed or filtered
	}
	defer conn.Close()

	result := &PortResult{
		Port:  port,
		Proto: proto,
		State: "open",
	}

	// Banner grabbing
	if s.BannerGrab && !s.ScanUDP {
		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		
		// Send a probe if needed (some services don't send banner on connect)
		// For now, just try to read
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			result.Banner = strings.TrimSpace(string(buffer[:n]))
		}
	}

	return result
}

// parseTarget parses a target string (IP or CIDR) into a list of IPs
func parseTarget(target string) ([]string, error) {
	// Check if CIDR
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}

		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		
		// Remove network address and broadcast address if > /31
		if len(ips) > 2 {
			return ips[1 : len(ips)-1], nil
		}
		return ips, nil
	}

	// Single IP
	if net.ParseIP(target) == nil {
		// Try to resolve hostname
		ips, err := net.LookupHost(target)
		if err != nil {
			return nil, err
		}
		return ips, nil
	}

	return []string{target}, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
