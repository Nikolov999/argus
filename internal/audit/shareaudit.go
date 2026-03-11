package audit

import (
	"adreview/internal/models"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func ShareAudit(cfg models.Config, computers []models.ComputerRecord) models.ShareResult {
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

	jobs := make(chan models.ComputerRecord)
	results := make(chan *models.ShareFinding, len(computers))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				results <- scanShare(cfg, c, timeout)
			}
		}()
	}

	go func() {
		for _, c := range computers {
			jobs <- c
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := models.ShareResult{
		Shares: make([]models.ShareFinding, 0),
	}

	for r := range results {
		if r != nil {
			out.Shares = append(out.Shares, *r)
		}
	}

	return out
}

func scanShare(cfg models.Config, c models.ComputerRecord, timeout time.Duration) *models.ShareFinding {
	host := c.DNSHostName
	if host == "" {
		host = c.Name
	}
	if host == "" {
		return nil
	}

	reachable := smbOpen(host, timeout)
	if !reachable && c.Name != "" && !strings.Contains(c.Name, ".") && cfg.Domain != "" {
		host = c.Name + "." + cfg.Domain
		reachable = smbOpen(host, timeout)
	}
	if !reachable {
		return nil
	}

	notes := []string{"SMB reachable on TCP/445"}
	if strings.Contains(strings.ToLower(c.DN), "ou=domain controllers") || strings.EqualFold(c.Name, cfg.DC) || strings.EqualFold(c.DNSHostName, cfg.DC) {
		notes = append(notes, "Domain Controller detected; review SYSVOL and NETLOGON exposure")
	}

	return &models.ShareFinding{
		Host:         host,
		SMBReachable: true,
		Notes:        notes,
	}
}

func smbOpen(host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, 445), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
