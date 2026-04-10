// Package secretscan detects hardcoded secrets, API keys, and tokens in source files.
package secretscan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SecretPattern defines a pattern for detecting a specific type of secret.
type SecretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
}

// Finding represents a detected secret in a file.
type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Context  string `json:"context"`
}

var defaultPatterns = []SecretPattern{
	{Name: "AWS Access Key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: "critical"},
	{Name: "GitHub PAT", Regex: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), Severity: "critical"},
	{Name: "Slack Token", Regex: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,250}`), Severity: "critical"},
	{Name: "Stripe Secret", Regex: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), Severity: "critical"},
	{Name: "OpenAI Key", Regex: regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), Severity: "critical"},
	{Name: "HuggingFace Token", Regex: regexp.MustCompile(`hf_[A-Za-z0-9]{34}`), Severity: "high"},
	{Name: "npm Token", Regex: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), Severity: "critical"},
	{Name: "Google API Key", Regex: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), Severity: "high"},
	{Name: "Private Key", Regex: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), Severity: "critical"},
	{Name: "JWT", Regex: regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+-]+`), Severity: "high"},
	{Name: "Generic Secret", Regex: regexp.MustCompile(`(?i)(password|secret|token|api_key)\s*[=:]\s*['"][^'"]{8,}['"]`), Severity: "medium"},
	{Name: "SendGrid Key", Regex: regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), Severity: "critical"},
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	"vendor": true, ".venv": true, "venv": true,
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".ico": true, ".zip": true, ".tar": true, ".gz": true,
	".bin": true, ".exe": true, ".pdf": true, ".woff": true,
}

// Scanner scans files for secrets.
type Scanner struct {
	Patterns []SecretPattern
}

// NewScanner creates a scanner with default patterns.
func NewScanner() *Scanner {
	return &Scanner{Patterns: defaultPatterns}
}

// ScanFile scans a single file for secrets.
func (s *Scanner) ScanFile(filePath string) ([]Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		for _, p := range s.Patterns {
			if p.Regex.MatchString(line) {
				context := line
				if len(context) > 100 {
					context = context[:100]
				}
				findings = append(findings, Finding{
					File:     filePath,
					Line:     i + 1,
					Type:     p.Name,
					Severity: p.Severity,
					Context:  context,
				})
			}
		}
	}
	return findings, nil
}

// ScanDir recursively scans a directory for secrets.
func (s *Scanner) ScanDir(dir string) ([]Finding, error) {
	var findings []Finding
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(info.Name())
		if binaryExts[ext] {
			return nil
		}
		if info.Size() > 1*1024*1024 {
			return nil
		}
		fileFindings, scanErr := s.ScanFile(path)
		if scanErr != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	return findings, err
}
