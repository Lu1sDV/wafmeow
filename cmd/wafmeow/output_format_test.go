package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportFormatIsExplicitAndIndependentOfStdout(t *testing.T) {
	for _, tc := range []struct {
		path, format, problem string
	}{
		{"report.json", "json", ""},
		{"report.JSONL", "jsonl", ""},
		{"report.ndjson", "jsonl", ""},
		{"report.csv", "csv", ""},
		{"report.txt", "txt", ""},
		{"report", "txt", ""},
		{"./-", "txt", ""},
		{"report.josnl", "", "unsupported --output extension"},
		{"report.zip", "", "unsupported --output extension"},
		{"-", "", "--output - is not stdout"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			format, err := reportFormat(tc.path)
			if tc.problem == "" && (err != nil || format != tc.format) {
				t.Fatalf("format=%q, err=%v; want %q", format, err, tc.format)
			}
			if tc.problem != "" && (err == nil || !strings.Contains(err.Error(), tc.problem)) {
				t.Fatalf("missing actionable format error: format=%q, err=%v", format, err)
			}
		})
	}
}

func TestCLIOutputNDJSONAndStdoutCanUseDifferentFormats(t *testing.T) {
	dir := t.TempDir()
	ndjson := filepath.Join(dir, "report.ndjson")
	code, stdout, stderr := runCLI(t, nil, "--target=invalid://fixture", "--output", ndjson, "--jsonl", "--silent")
	if code != 0 || stderr != "" || len(decodeResultLines(t, stdout)) != 1 {
		t.Fatalf("JSONL stdout changed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	data, err := os.ReadFile(ndjson)
	if err != nil || len(decodeResultLines(t, string(data))) != 1 {
		t.Fatalf("named NDJSON is not result JSONL: %q, %v", data, err)
	}
	csv := filepath.Join(dir, "report.csv")
	code, stdout, stderr = runCLI(t, nil, "--target=invalid://fixture", "--output", csv, "--jsonl", "--silent")
	if code != 0 || stderr != "" || len(decodeResultLines(t, stdout)) != 1 {
		t.Fatalf("JSONL stdout changed with CSV output: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	data, err = os.ReadFile(csv)
	if err != nil || !strings.HasPrefix(string(data), "target,state,") {
		t.Fatalf("report extension did not select CSV: %q, %v", data, err)
	}
}

func TestCLIRejectsSurprisingReportFilenamesBeforeOutput(t *testing.T) {
	for _, ext := range []string{".josnl", ".zip"} {
		path := filepath.Join(t.TempDir(), "previous"+ext)
		const previous = "preserved report"
		if err := os.WriteFile(path, []byte(previous), 0600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runCLI(t, nil, "--target=invalid://fixture", "--jsonl", "--silent", "--output", path)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "unsupported --output extension") {
			t.Fatalf("unknown extension silently accepted: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != previous {
			t.Fatalf("report changed on format error: %q: %v", data, err)
		}
	}
	code, stdout, stderr := runCLI(t, nil, "--target=invalid://fixture", "--output", "-", "--jsonl", "--silent")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "--output ./-") {
		t.Fatalf("literal stdout filename did not explain recovery: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCLIRequireResultsProtectsPreviousReportOnEmptyInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.jsonl")
	const previous = "previous report"
	if err := os.WriteFile(path, []byte(previous), 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, strings.NewReader(" \n\t\n"), "--target-file=-", "--jsonl", "--silent",
		"--output", path, "--require-results")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "no targets were processed") ||
		!strings.Contains(stderr, "report not replaced") {
		t.Fatalf("empty-input guard did not fail with guidance: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != previous {
		t.Fatalf("empty-input guard replaced previous report: %q, %v", data, err)
	}

	// A target that fails evaluation still counts as an input occurrence;
	// --require-results does not replace --strict's quality predicate.
	code, stdout, stderr = runCLI(t, nil, "--target=invalid://fixture", "--jsonl", "--silent",
		"--output", path, "--require-results")
	if code != 0 || stderr != "" || len(decodeResultLines(t, stdout)) != 1 {
		t.Fatalf("nonempty input incorrectly rejected: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
