package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ── Schema types ──────────────────────────────────────────────────────────────

// Request is the JSON schema received on stdin from the Python orchestrator.
type Request struct {
	Schema         string `json:"schema"`
	Target         string `json:"target"`
	TargetType     string `json:"target_type"`
	Profile        string `json:"profile"`
	Ports          string `json:"ports"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// Observation carries a named value to the Python side.
type Observation struct {
	Name   string      `json:"name"`
	Value  interface{} `json:"value"`
	Source string      `json:"source"`
}

// Finding represents a confirmed security issue.
type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	Category       string   `json:"category"`
	Target         string   `json:"target"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references"`
}

// PortResult holds details for one open TCP port.
type PortResult struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service"`
	Banner    string `json:"banner,omitempty"`
	RiskLevel string `json:"risk_level,omitempty"`
	RiskNote  string `json:"risk_note,omitempty"`
}

// Response is the JSON schema written to stdout.
type Response struct {
	Schema       string        `json:"schema"`
	Engine       string        `json:"engine"`
	Status       string        `json:"status"`
	Target       string        `json:"target"`
	StartedAt    string        `json:"started_at"`
	FinishedAt   string        `json:"finished_at"`
	Findings     []Finding     `json:"findings"`
	Observations []Observation `json:"observations"`
	Warnings     []string      `json:"warnings"`
}

// ── Service + risk metadata ───────────────────────────────────────────────────

var serviceMap = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
	443: "https", 445: "smb", 465: "smtps", 587: "submission",
	636: "ldaps", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 1883: "mqtt",
	2049: "nfs", 2375: "docker", 2376: "docker-tls",
	2222: "ssh-alt", 3000: "dev-server", 3306: "mysql",
	3389: "rdp", 4444: "metasploit-default", 4848: "glassfish",
	5432: "postgresql", 5601: "kibana", 5900: "vnc",
	5984: "couchdb", 5985: "winrm-http", 5986: "winrm-https",
	6379: "redis", 7001: "weblogic", 7474: "neo4j",
	7687: "neo4j-bolt", 8080: "http-alt", 8443: "https-alt",
	8888: "jupyter", 9000: "portainer", 9090: "prometheus",
	9200: "elasticsearch", 9300: "elastic-cluster",
	10000: "webmin", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 28017: "mongodb-web",
	50000: "db2", 50070: "hadoop-namenode", 61616: "activemq",
}

type riskInfo struct {
	level string
	note  string
}

var riskyPorts = map[int]riskInfo{
	23:    {"critical", "Telnet — cleartext remote access, no encryption"},
	4444:  {"critical", "Default Metasploit reverse-shell port"},
	2375:  {"critical", "Docker daemon API — unauthenticated container control"},
	445:   {"critical", "SMB — ransomware attack surface, EternalBlue target"},
	1433:  {"high", "MSSQL — database engine directly exposed"},
	3306:  {"high", "MySQL — database engine directly exposed"},
	5432:  {"high", "PostgreSQL — database engine directly exposed"},
	6379:  {"high", "Redis — typically unauthenticated, full data access"},
	9200:  {"high", "Elasticsearch — often unauthenticated, full index access"},
	27017: {"high", "MongoDB — often unauthenticated, full collection access"},
	11211: {"high", "Memcached — DDoS amplification risk, no auth by default"},
	5900:  {"high", "VNC — remote desktop, often weak/no password"},
	3389:  {"high", "RDP — brute-force and BlueKeep target"},
	5601:  {"medium", "Kibana — Elasticsearch management UI exposed"},
	8888:  {"medium", "Jupyter Notebook — often runs unauthenticated"},
	4848:  {"medium", "GlassFish admin — default credentials common"},
	7001:  {"medium", "Oracle WebLogic — known RCE vulnerabilities"},
	10000: {"medium", "Webmin — remote admin, many historical CVEs"},
	15672: {"medium", "RabbitMQ management — credentials often default"},
	5984:  {"medium", "CouchDB — admin party mode possible"},
	139:   {"medium", "NetBIOS — legacy Windows sharing exposure"},
	2376:  {"medium", "Docker TLS daemon — verify certificate enforcement"},
	7474:  {"medium", "Neo4j HTTP API — may lack authentication"},
	50070: {"medium", "Hadoop NameNode — HDFS admin interface exposed"},
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	start := time.Now().UTC().Format(time.RFC3339)
	var req Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "failed to decode request:", err)
		os.Exit(1)
	}
	if req.Target == "" {
		fmt.Fprintln(os.Stderr, "target field is required")
		os.Exit(1)
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 5
	}

	ports := selectPorts(req.Ports)
	portResults := scanAllPorts(req.Target, ports, time.Duration(req.TimeoutSeconds)*time.Second)
	findings := classifyPorts(req.Target, portResults)

	openPortNums := make([]int, 0, len(portResults))
	for _, pr := range portResults {
		openPortNums = append(openPortNums, pr.Port)
	}
	sort.Ints(openPortNums)

	resp := Response{
		Schema:    "phantomscan.engine.v1",
		Engine:    "go-portscan",
		Status:    "ok",
		Target:    req.Target,
		StartedAt: start,
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:   findings,
		Observations: []Observation{
			{Name: "open_tcp_ports", Value: openPortNums, Source: "go-portscan"},
			{Name: "port_scan_results", Value: portResults, Source: "go-portscan"},
		},
		Warnings: []string{},
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, "failed to encode response:", err)
		os.Exit(1)
	}
}

// ── Port selection ────────────────────────────────────────────────────────────

// top100 contains the most scanned TCP ports for quick mode.
var top100 = []int{
	20, 21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161,
	179, 389, 443, 445, 465, 587, 636, 993, 995,
	1433, 1521, 1883, 2049, 2222, 2375, 2376, 3000, 3306, 3389,
	4444, 4848, 5432, 5601, 5900, 5984, 5985, 5986, 6379,
	7001, 7474, 7687, 8080, 8443, 8888,
	9000, 9090, 9200, 9300, 10000, 11211,
	15672, 27017, 28017, 50000, 50070, 61616,
}

// top1000 extends top100 with common alternative ports.
var top1000 = append(top100, []int{
	81, 82, 83, 84, 85, 8000, 8001, 8008, 8009, 8010, 8081, 8082,
	8083, 8090, 8091, 8161, 8181, 8182, 8243, 8280, 8281, 8333,
	8500, 8834, 8880, 8983, 9001, 9002, 9100, 9201, 9999, 10001,
	49152, 49153, 49154, 49155, 49156, 49157,
}...)

func selectPorts(mode string) []int {
	switch strings.ToLower(mode) {
	case "top1000":
		seen := map[int]struct{}{}
		out := make([]int, 0, len(top1000))
		for _, p := range top1000 {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		sort.Ints(out)
		return out
	default: // "top100" or any unrecognised value
		seen := map[int]struct{}{}
		out := make([]int, 0, len(top100))
		for _, p := range top100 {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		sort.Ints(out)
		return out
	}
}

// ── Concurrent port scanning ──────────────────────────────────────────────────

// maxConcurrency limits simultaneous TCP connect goroutines.
const maxConcurrency = 150

func scanAllPorts(host string, ports []int, connTimeout time.Duration) []PortResult {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	resultsCh := make(chan PortResult, len(ports))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if r := scanPort(ctx, host, p, connTimeout); r.State == "open" {
				resultsCh <- r
			}
		}(port)
	}

	// Close the channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]PortResult, 0)
	for r := range resultsCh {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

// ── Single port scan ──────────────────────────────────────────────────────────

func scanPort(ctx context.Context, host string, port int, timeout time.Duration) PortResult {
	address := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return PortResult{Port: port, State: "closed"}
	}
	defer conn.Close()

	banner := grabBanner(conn, port)
	service := serviceMap[port]
	if service == "" {
		service = inferServiceFromBanner(banner)
	}
	risk := riskyPorts[port]

	return PortResult{
		Port:      port,
		Protocol:  "tcp",
		State:     "open",
		Service:   service,
		Banner:    sanitizeBanner(banner),
		RiskLevel: risk.level,
		RiskNote:  risk.note,
	}
}

// ── Banner grabbing ───────────────────────────────────────────────────────────

// probes contains port-specific handshake bytes to elicit a banner.
var probes = map[int][]byte{
	21:   nil,                                                 // FTP sends banner on connect
	22:   nil,                                                 // SSH sends banner on connect
	23:   nil,                                                 // Telnet sends banner on connect
	25:   nil,                                                 // SMTP sends banner on connect
	80:   []byte("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
	8080: []byte("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
	8888: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
	9200: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
	6379: []byte("PING\r\n"),
	3306: nil, // MySQL sends greeting banner on connect
	5432: nil, // PostgreSQL startup — we just read the error banner
	27017: []byte("\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
}

func grabBanner(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	probe, hasProbe := probes[port]
	if hasProbe && len(probe) > 0 {
		conn.Write(probe) // intentionally ignore write errors
	}

	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return string(buf[:n])
}

func sanitizeBanner(raw string) string {
	out := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return '.'
	}, raw)
	out = strings.TrimSpace(out)
	if len(out) > 512 {
		out = out[:512] + "…"
	}
	return out
}

func inferServiceFromBanner(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh"):
		return "ssh"
	case strings.Contains(lower, "http"):
		return "http"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp"):
		return "smtp"
	case strings.Contains(lower, "+ok") || strings.Contains(lower, "-err"):
		return "pop3"
	case strings.Contains(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "mongo"):
		return "mongodb"
	case strings.Contains(lower, "elastic"):
		return "elasticsearch"
	}
	return "unknown"
}

// ── Risk classification ───────────────────────────────────────────────────────

func classifyPorts(target string, results []PortResult) []Finding {
	findings := []Finding{}
	for _, pr := range results {
		risk, ok := riskyPorts[pr.Port]
		if !ok {
			continue
		}
		evidence := fmt.Sprintf(
			"TCP port %d is open. Service: %s.",
			pr.Port, pr.Service,
		)
		if pr.Banner != "" {
			// Include only first 200 chars of banner as evidence
			b := pr.Banner
			if len(b) > 200 {
				b = b[:200] + "…"
			}
			evidence += fmt.Sprintf(" Banner: %s", b)
		}
		findings = append(findings, Finding{
			ID:         fmt.Sprintf("OPEN-RISKY-PORT-%d", pr.Port),
			Title:      "Risk-sensitive service is reachable",
			Severity:   risk.level,
			Confidence: "high",
			Category:   "network",
			Target:     target,
			Evidence:   evidence,
			Recommendation: fmt.Sprintf(
				"%s Restrict access to trusted networks only and verify authentication and patch status.",
				risk.note,
			),
			References: []string{},
		})
	}
	return findings
}
