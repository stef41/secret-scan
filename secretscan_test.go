package secretscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewScanner(t *testing.T) {
	s := NewScanner()
	if len(s.Patterns) == 0 {
		t.Error("expected default patterns")
	}
}

func TestScanFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.py")
	// Use a generic secret pattern that won't trigger GitHub push protection
	os.WriteFile(testFile, []byte("password = \"supersecretvalue123\"\nnormal_code = True\n"), 0644)
	s := NewScanner()
	findings, err := s.ScanFile(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 1 {
		t.Error("expected at least one finding")
	}
}

func TestScanDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "clean.py"), []byte("x = 42\n"), 0644)
	s := NewScanner()
	findings, err := s.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in clean file, got %d", len(findings))
	}
}
