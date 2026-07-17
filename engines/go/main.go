package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type Request struct {
	Schema         string `json:"schema"`
	Target         string `json:"target"`
	TargetType     string `json:"target_type"`
	Profile        string `json:"profile"`
	Ports          string `json:"ports"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type Observation struct {
	Name   string      `json:"name"`
	Value  interface{} `json:"value"`
	Source string      `json:"source"`
}

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

func main() {
	start := time.Now().UTC().Format(time.RFC3339)
	var req Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ports := selectPorts(req.Ports)
	openPorts := scanTCP(req.Target, ports, time.Duration(req.TimeoutSeconds)*time.Second)
	findings := classifyPorts(req.Target, openPorts)
	resp := Response{
		Schema:       "phantomscan.engine.v1",
		Engine:       "go-portscan",
		Status:       "ok",
		Target:       req.Target,
		StartedAt:    start,
		FinishedAt:   time.Now().UTC().Format(time.RFC3339),
		Findings:     findings,
		Observations: []Observation{{Name: "open_tcp_ports", Value: openPorts, Source: "go-portscan"}},
		Warnings:     []string{},
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func selectPorts(mode string) []int {
	top := []int{20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 1433, 2375, 3306, 5432, 5601, 6379, 8080, 8443, 9200, 27017}
	sort.Ints(top)
	return top
}

func scanTCP(host string, ports []int, timeout time.Duration) []int {
	var wg sync.WaitGroup
	results := make(chan int, len(ports))
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), timeout)
			if err != nil {
				return
			}
			closeErr := conn.Close()
			if closeErr == nil {
				results <- p
			}
		}(port)
	}
	wg.Wait()
	close(results)
	open := []int{}
	for port := range results {
		open = append(open, port)
	}
	sort.Ints(open)
	return open
}

func classifyPorts(target string, ports []int) []Finding {
	risky := map[int]string{23: "Telnet exposure", 139: "NetBIOS exposure", 445: "SMB exposure", 1433: "SQL Server exposure", 2375: "Docker API exposure", 6379: "Redis exposure", 9200: "Elasticsearch exposure", 27017: "MongoDB exposure"}
	findings := []Finding{}
	for _, port := range ports {
		if note, ok := risky[port]; ok {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("OPEN-RISKY-PORT-%d", port),
				Title:          "Risk-sensitive service is reachable",
				Severity:       "high",
				Confidence:     "high",
				Category:       "network",
				Target:         target,
				Evidence:       fmt.Sprintf("TCP port %d is open: %s", port, note),
				Recommendation: "Restrict this service to trusted networks and confirm authentication and patch status.",
				References:     []string{},
			})
		}
	}
	return findings
}

