package audit

import (
	"adreview/internal/models"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func LateralMap(cfg models.Config, computers []models.ComputerRecord) models.LateralResult {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 32
	}

	timeout := 3 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
		if timeout < 2*time.Second {
			timeout = 2 * time.Second
		}
	}

	type job struct {
		Computer models.ComputerRecord
	}

	type result struct {
		Target *models.LateralService
	}

	jobs := make(chan job)
	results := make(chan result, len(computers))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				target := scanComputer(cfg, j.Computer, timeout)
				results <- result{Target: target}
			}
		}()
	}

	go func() {
		for _, c := range computers {
			jobs <- job{Computer: c}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := models.LateralResult{
		Targets: make([]models.LateralService, 0),
	}

	for r := range results {
		if r.Target != nil {
			out.Targets = append(out.Targets, *r.Target)
		}
	}

	return out
}

func scanComputer(cfg models.Config, c models.ComputerRecord, timeout time.Duration) *models.LateralService {
	candidates := buildHostCandidates(cfg, c)
	if len(candidates) == 0 {
		return nil
	}

	ports := []struct {
		Port  int
		Label string
	}{
		{135, "RPC (135)"},
		{139, "NetBIOS Session (139)"},
		{445, "SMB (445)"},
		{3389, "RDP (3389)"},
		{5985, "WinRM HTTP (5985)"},
		{5986, "WinRM HTTPS (5986)"},
		{47001, "WinRM Compatibility (47001)"},
	}

	services := make([]string, 0, len(ports))
	reachableHost := ""

	for _, host := range candidates {
		found := false
		for _, p := range ports {
			if tcpOpen(host, p.Port, timeout) {
				services = appendIfMissing(services, p.Label)
				found = true
			}
		}
		if found && reachableHost == "" {
			reachableHost = host
		}
	}

	if len(services) == 0 {
		return nil
	}

	displayHost := reachableHost
	if displayHost == "" {
		displayHost = c.DNSHostName
	}
	if displayHost == "" {
		displayHost = c.Name
	}

	return &models.LateralService{
		Host:     displayHost,
		Services: services,
	}
}

func buildHostCandidates(cfg models.Config, c models.ComputerRecord) []string {
	seen := map[string]bool{}
	out := []string{}

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		v = strings.TrimSuffix(v, "$")
		if !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}

	add(c.DNSHostName)
	add(c.Name)

	if c.Name != "" && !strings.Contains(c.Name, ".") && cfg.Domain != "" {
		add(c.Name + "." + cfg.Domain)
	}

	if c.DNSHostName != "" {
		short := strings.Split(c.DNSHostName, ".")[0]
		add(short)
	}

	return out
}

func appendIfMissing(items []string, item string) []string {
	for _, v := range items {
		if v == item {
			return items
		}
	}
	return append(items, item)
}

func tcpOpen(host string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err == nil {
		_ = conn.Close()
		return true
	}

	ips, resolveErr := net.LookupHost(host)
	if resolveErr != nil {
		return false
	}

	for _, ip := range ips {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}

	return false
}
