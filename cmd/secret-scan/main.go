package main

import (
	"encoding/json"
	"fmt"
	"os"

	ss "github.com/stef41/secret-scan"
)

func main() {
	dir := "."
	jsonOutput := false
	for _, arg := range os.Args[1:] {
		if arg == "--json" {
			jsonOutput = true
		} else {
			dir = arg
		}
	}
	scanner := ss.NewScanner()
	findings, err := scanner.ScanDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	} else {
		if len(findings) == 0 {
			fmt.Println("No secrets found.")
			return
		}
		for _, f := range findings {
			fmt.Printf("[%s] %s:%d - %s\n", f.Severity, f.File, f.Line, f.Type)
		}
		fmt.Printf("\nTotal: %d potential secrets found\n", len(findings))
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}
