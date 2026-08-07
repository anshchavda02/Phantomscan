package main

import "testing"

func TestSelectPortsIncludesWeb(t *testing.T) {
	ports := selectPorts("top100")
	found := false
	for _, port := range ports {
		if port == 443 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 443 in selected ports")
	}
}

func TestClassifyRiskyPort(t *testing.T) {
	results := []PortResult{
		{Port: 80, State: "open", Service: "http"},
		{Port: 6379, State: "open", Service: "redis"},
	}
	findings := classifyPorts("127.0.0.1", results)
	if len(findings) != 1 {
		t.Fatalf("expected one risky finding, got %d", len(findings))
	}
}

