package audit

import (
	"argus/internal/models"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type lateralPort struct {
	Port int
	Name string
}

var defaultLateralPorts = []lateralPort{
	{22, "SSH"},
	{80, "HTTP"},
	{88, "Kerberos"},
	{135, "RPC"},
	{139, "NetBIOS"},
	{389, "LDAP"},
	{443, "HTTPS"},
	{445, "SMB"},
	{636, "LDAPS"},
	{3389, "RDP"},
	{5985, "WinRM"},
	{5986, "WinRM TLS"},
	{1433, "MSSQL"},
	{3268, "Global Catalog"},
	{3269, "GC TLS"},
	{47001, "WinRM Compatibility"},
}

func LateralMap(cfg models.Config, computers []models.ComputerRecord, ipMap map[string][]string) models.LateralResult {
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
				results <- result{Target: scanComputer(j.Computer, ipMap, timeout)}
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
		Targets: make([]models.LateralService, 0, len(computers)),
	}

	for r := range results {
		if r.Target != nil {
			out.Targets = append(out.Targets, *r.Target)
		}
	}

	sort.Slice(out.Targets, func(i, j int) bool {
		return strings.ToLower(out.Targets[i].Host) < strings.ToLower(out.Targets[j].Host)
	})

	return out
}

func scanComputer(c models.ComputerRecord, ipMap map[string][]string, timeout time.Duration) *models.LateralService {
	displayHost := preferredComputerName(c)
	if displayHost == "" {
		return nil
	}

	ips := lookupComputerIPs(c, ipMap)
	if len(ips) == 0 {
		return &models.LateralService{
			Host:     displayHost,
			Services: []string{"no IP mapping found in ADIDNS"},
		}
	}

	services := scanPortsAcrossIPs(ips, timeout)

	display := fmt.Sprintf("%s [%s]", displayHost, strings.Join(ips, ", "))

	if len(services) == 0 {
		return &models.LateralService{
			Host:     display,
			Services: []string{"no tested ports reachable"},
		}
	}

	return &models.LateralService{
		Host:     display,
		Services: services,
	}
}

func scanPortsAcrossIPs(ips []string, timeout time.Duration) []string {
	type portResult struct {
		Label string
	}

	results := make(chan portResult, len(defaultLateralPorts))
	var wg sync.WaitGroup

	for _, p := range defaultLateralPorts {
		wg.Add(1)
		go func(p lateralPort) {
			defer wg.Done()

			for _, ip := range ips {
				if tcpOpen(ip, p.Port, timeout) {
					results <- portResult{
						Label: fmt.Sprintf("%d/tcp %s", p.Port, p.Name),
					}
					return
				}
			}
		}(p)
	}

	wg.Wait()
	close(results)

	seen := make(map[string]struct{})
	out := make([]string, 0, len(defaultLateralPorts))

	for r := range results {
		if _, exists := seen[r.Label]; exists {
			continue
		}
		seen[r.Label] = struct{}{}
		out = append(out, r.Label)
	}

	sort.Strings(out)
	return out
}

func lookupComputerIPs(c models.ComputerRecord, ipMap map[string][]string) []string {
	keys := computerLookupKeys(c)

	seen := make(map[string]struct{})
	out := make([]string, 0)

	for _, key := range keys {
		ips, ok := ipMap[key]
		if !ok {
			continue
		}

		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if net.ParseIP(ip) == nil {
				continue
			}
			if _, exists := seen[ip]; exists {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}

	sort.Strings(out)
	return out
}

func computerLookupKeys(c models.ComputerRecord) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 4)

	add := func(v string) {
		v = normalizeDNSKey(v)
		if v == "" {
			return
		}
		if _, exists := seen[v]; exists {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	add(c.DNSHostName)
	add(c.Name)

	if c.DNSHostName != "" {
		add(strings.Split(strings.TrimSpace(c.DNSHostName), ".")[0])
	}

	if c.Name != "" && strings.Contains(c.Name, ".") {
		add(strings.Split(strings.TrimSpace(c.Name), ".")[0])
	}

	return out
}

func normalizeDNSKey(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "$")
	v = strings.TrimSuffix(v, ".")
	return strings.ToLower(v)
}

func preferredComputerName(c models.ComputerRecord) string {
	if strings.TrimSpace(c.DNSHostName) != "" {
		return strings.TrimSpace(c.DNSHostName)
	}
	if strings.TrimSpace(c.Name) != "" {
		return strings.TrimSpace(strings.TrimSuffix(c.Name, "$"))
	}
	return ""
}

func tcpOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
