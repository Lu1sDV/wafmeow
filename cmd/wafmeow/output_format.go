package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Report formats are independent of --jsonl, which only selects stdout.
// Reject unknown suffixes rather than silently creating a TXT report named
// like a structured report. Extensionless names explicitly remain TXT.
func reportFormat(path string) (string, error) {
	if path == "-" {
		return "", errors.New("--output - is not stdout; use --jsonl for stdout, or --output ./- for a literal file")
	}
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".json":
		return "json", nil
	case ".jsonl", ".ndjson":
		return "jsonl", nil
	case ".csv":
		return "csv", nil
	case ".txt", "":
		return "txt", nil
	default:
		return "", fmt.Errorf("unsupported --output extension %q; use .json, .jsonl/.ndjson, .csv or .txt (or no extension for TXT)", ext)
	}
}
