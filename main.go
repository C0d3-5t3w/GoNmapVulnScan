package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gocarina/gocsv"
)

type SharedData struct {
	VulnSummaryFileURL   string
	VulnerabilitiesDir   string
	NmapScanAggressivity string
}

type NmapVulnScanner struct {
	sharedData  *SharedData
	scanResults []ScanResult
}

type ScanResult struct {
	IP              string
	Hostname        string
	MACAddress      string
	Port            string
	Vulnerabilities string
}

func NewNmapVulnScanner(sharedData *SharedData) *NmapVulnScanner {
	scanner := &NmapVulnScanner{sharedData: sharedData}
	scanner.createSummaryFile()
	return scanner
}

func (n *NmapVulnScanner) createSummaryFile() {
	resp, err := http.Get(n.sharedData.VulnSummaryFileURL)
	if err != nil {
		log.Fatalf("Error fetching summary file: %v", err)
	}
	defer resp.Body.Close()

	file, err := os.Create(filepath.Join(n.sharedData.VulnerabilitiesDir, "summary_file.csv"))
	if err != nil {
		log.Fatalf("Error creating local summary file: %v", err)
	}
	defer file.Close()

	_, err = file.ReadFrom(resp.Body)
	if err != nil {
		log.Fatalf("Error reading summary file: %v", err)
	}
}

func (n *NmapVulnScanner) updateSummaryFile(ip, hostname, mac, port, vulnerabilities string) {
	file, err := os.OpenFile(filepath.Join(n.sharedData.VulnerabilitiesDir, "summary_file.csv"), os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Error opening summary file: %v", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{ip, hostname, mac, port, vulnerabilities})
}

func (n *NmapVulnScanner) scanVulnerabilities(ip, hostname, mac string, ports []string) (string, bool) {
	log.Printf("Scanning IP: %s", ip)
	cmd := exec.Command("nmap", n.sharedData.NmapScanAggressivity, "-sV", "--script", "vulners.nse", "-p", strings.Join(ports, ","), ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error scanning %s: %v", ip, err)
		return "", false
	}
	vulnerabilities := n.parseVulnerabilities(string(output))
	n.updateSummaryFile(ip, hostname, mac, strings.Join(ports, ","), vulnerabilities)
	return string(output), true
}

func (n *NmapVulnScanner) execute(ip string, row map[string]string) string {
	log.Printf("Executing scan for IP: %s", ip)
	ports := strings.Split(row["Ports"], ";")
	scanResult, success := n.scanVulnerabilities(ip, row["Hostnames"], row["MAC Address"], ports)
	if success {
		n.scanResults = append(n.scanResults, ScanResult{IP: ip, Hostname: row["Hostnames"], MACAddress: row["MAC Address"]})
		n.saveResults(row["MAC Address"], ip, scanResult)
		return "success"
	}
	return "success"
}

func (n *NmapVulnScanner) parseVulnerabilities(scanResult string) string {
	var vulnerabilities []string
	lines := strings.Split(scanResult, "\n")
	capture := false
	for _, line := range lines {
		if strings.Contains(line, "VULNERABLE") || strings.Contains(line, "CVE-") || strings.Contains(line, "*EXPLOIT*") {
			capture = true
		}
		if capture {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "|_") {
				vulnerabilities = append(vulnerabilities, strings.TrimSpace(line))
			} else {
				capture = false
			}
		}
	}
	return strings.Join(vulnerabilities, "; ")
}

func (n *NmapVulnScanner) saveResults(macAddress, ip, scanResult string) {
	sanitizedMacAddress := strings.ReplaceAll(macAddress, ":", "")
	resultDir := n.sharedData.VulnerabilitiesDir
	os.MkdirAll(resultDir, os.ModePerm)
	resultFile := filepath.Join(resultDir, fmt.Sprintf("%s_%s_vuln_scan.txt", sanitizedMacAddress, ip))
	file, err := os.Create(resultFile)
	if err != nil {
		log.Printf("Error saving scan results for %s: %v", ip, err)
		return
	}
	defer file.Close()
	file.WriteString(scanResult)
	log.Printf("Results saved to %s", resultFile)
}

func (n *NmapVulnScanner) saveSummary() {
	finalSummaryFile := filepath.Join(n.sharedData.VulnerabilitiesDir, "final_vulnerability_summary.csv")
	file, err := os.Create(finalSummaryFile)
	if err != nil {
		log.Fatalf("Error creating final summary file: %v", err)
	}
	defer file.Close()
	writer := gocsv.DefaultCSVWriter(file)
	defer writer.Flush()
	writer.Write([]string{"IP", "Hostname", "MAC Address", "Vulnerabilities"})
	for _, result := range n.scanResults {
		writer.Write([]string{result.IP, result.Hostname, result.MACAddress, result.Vulnerabilities})
	}
}

func ensureDir(dirName string) {
	err := os.MkdirAll(dirName, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating directory %s: %v", dirName, err)
	}
}

func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error getting home directory: %v", err)
	}

	vulnSummaryFileURL := "https://example.com/summary_file.csv" // Replace with a real URL to a vulnerability summary file
	vulnerabilitiesDir := filepath.Join(homeDir, "vulnerabilities_dir")

	ensureDir(vulnerabilitiesDir)

	sharedData := &SharedData{
		VulnSummaryFileURL:   vulnSummaryFileURL,
		VulnerabilitiesDir:   vulnerabilitiesDir,
		NmapScanAggressivity: "-A",
	}
	nmapVulnScanner := NewNmapVulnScanner(sharedData)
	log.Println("Starting vulnerability scans...")

	// Scan the whole WiFi network
	cmd := exec.Command("nmap", "-sn", "192.168.1.0/24")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error scanning network: %v", err)
	}
	ipsToScan := parseNmapOutput(string(output))

	var wg sync.WaitGroup
	for _, row := range ipsToScan {
		if row["Alive"] == "1" {
			ip := row["IPs"]
			wg.Add(1)
			go func(ip string, row map[string]string) {
				defer wg.Done()
				nmapVulnScanner.execute(ip, row)
			}(ip, row)
		}
	}
	wg.Wait()

	nmapVulnScanner.saveSummary()
	log.Printf("Total scans performed: %d", len(nmapVulnScanner.scanResults))
}

func parseNmapOutput(output string) []map[string]string {
	var ipsToScan []map[string]string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Nmap scan report for") {
			ip := strings.Fields(line)[4]
			ipsToScan = append(ipsToScan, map[string]string{
				"IPs":         ip,
				"Alive":       "1",
				"Ports":       "80,443",
				"Hostnames":   "unknown",
				"MAC Address": "unknown",
			})
		}
	}
	return ipsToScan
}
