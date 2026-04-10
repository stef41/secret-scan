# secret-scan

Go library to detect hardcoded secrets, API keys, and tokens in source files. Supports 12+ secret types including AWS, GitHub, Stripe, OpenAI, and more.

## Installation

```bash
go get github.com/stef41/secret-scan
```

## Usage

```go
scanner := secretscan.NewScanner()
findings, _ := scanner.ScanDir("./src")
for _, f := range findings {
    fmt.Printf("[%s] %s:%d - %s\n", f.Severity, f.File, f.Line, f.Type)
}
```

## License

MIT
