package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
)

func TestRunPlanExplainsModeParallelismAndTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fast     bool
		baseline bool
		want     []string
	}{
		{"deep", false, false, []string{"DEEP MODE", "8 planned HTTP checks", "up to 1/target"}},
		{"fast", true, false, []string{"FAST MODE", "3 planned HTTP checks", "up to 3/target"}},
		{"baseline", false, true, []string{"BASELINE MODE", "1 planned HTTP checks", "up to 1/target"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := wafmeow.DefaultConfig()
			config.FastMode, config.BaselineOnly = tc.fast, tc.baseline
			config.MaxConnections = 0
			config.RequestsPerSecond = 5
			config.AllowedOrigins = []string{"https://private.invalid"}
			config.Headers = []wafmeow.Header{{Name: "Authorization", Value: "private-token"}}
			opts := newOptions(config)
			opts.Target, opts.OutputFile, opts.JSONL, opts.Strict = "https://private.invalid/token", "/private/report.JSON", true, true
			var output bytes.Buffer
			if err := printRunPlan(&output, opts, config); err != nil {
				t.Fatal(err)
			}
			for _, want := range append(tc.want, "RUN PLAN", "20 target workers", "Timeouts: 5s/request, 30s/target",
				"5 requests/s global", "origin allowlist on", "JSONL stdout", "JSON report", "strict") {
				if !strings.Contains(output.String(), want) {
					t.Errorf("plan lacks %q: %s", want, output.String())
				}
			}
			for _, secret := range []string{"private-token", "private.invalid", "/private/"} {
				if strings.Contains(output.String(), secret) {
					t.Errorf("plan leaked %q: %s", secret, output.String())
				}
			}
		})
	}
}

func TestRunPlanIsRoundedBoundedAndFollowedByBlankLine(t *testing.T) {
	plan := runPlanText(newOptions(wafmeow.DefaultConfig()), wafmeow.DefaultConfig())
	if !strings.HasPrefix(plan, "╭─ RUN PLAN ") || !strings.Contains(plan, "╰") || !strings.HasSuffix(plan, "╯\n\n") {
		t.Fatalf("run plan missing rounded box or blank-line separation: %q", plan)
	}
	for _, line := range strings.Split(strings.TrimSuffix(plan, "\n\n"), "\n") {
		if width := utf8.RuneCountInString(line); width != 72 {
			t.Fatalf("box row width=%d, want 72: %q", width, line)
		}
	}
	for _, redundant := range []string{"unlimited", "strict off", "output: human", "5s/req"} {
		if strings.Contains(plan, redundant) {
			t.Errorf("default plan contains ambiguous or redundant detail %q: %s", redundant, plan)
		}
	}
}

func TestCustomizedRunPlanWrapsWithoutLeakingValues(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.MaxConnections, config.MaxRequests = 1, 4
	config.RedirectPolicy = "none"
	config.AllowedOrigins = []string{"https://private.invalid"}
	config.RequestsPerSecond, config.PerOriginRequestsPerSecond = 5, 2
	opts := newOptions(config)
	opts.OutputFile, opts.Strict = "/private/report.ndjson", true
	plan := runPlanText(opts, config)
	for _, want := range []string{"1 in flight", "4 attempts/target", "redirects off", "origin allowlist on",
		"5 requests/s global", "2 requests/s per origin", "JSONL report", "strict"} {
		if !strings.Contains(plan, want) {
			t.Errorf("missing override %q: %s", want, plan)
		}
	}
	if strings.Contains(plan, "/private") || strings.Contains(plan, "private.invalid") {
		t.Fatalf("plan leaked sensitive values: %q", plan)
	}
	for _, line := range strings.Split(strings.TrimSuffix(plan, "\n\n"), "\n") {
		if utf8.RuneCountInString(line) != 72 {
			t.Errorf("incorrect box width: %q", line)
		}
	}
}

func TestRunPlanEffectiveParallelismRespectsConnectionCaps(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.Concurrency, config.ProbeConcurrency, config.MaxConnections = 2, 8, 0
	plan := runPlanText(newOptions(config), config)
	for _, want := range []string{"2 target workers", "8 in flight", "up to 7/target"} {
		if !strings.Contains(plan, want) {
			t.Errorf("effective parallelism lacks %q: %s", want, plan)
		}
	}
	config.MaxConnections = 1
	config.FastMode = true
	plan = runPlanText(newOptions(config), config)
	for _, want := range []string{"1 in flight", "up to 1/target"} {
		if !strings.Contains(plan, want) {
			t.Errorf("connection limit ignored %q: %s", want, plan)
		}
	}
}

func TestRunPlanOfflineDoesNotSuggestNetworkActivity(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	for _, tc := range []struct{ format, want string }{
		{"native", "2 classification workers"},
		{"httpx", "serial import"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			config := wafmeow.DefaultConfig()
			opts := newOptions(config)
			opts.EvidenceFile, opts.EvidenceFormat = "/private/captures.jsonl", tc.format
			plan := runPlanText(opts, config)
			for _, want := range []string{"OFFLINE " + strings.ToUpper(tc.format), "no network requests", tc.want} {
				if !strings.Contains(plan, want) {
					t.Errorf("offline plan lacks %q: %s", want, plan)
				}
			}
			for _, unwanted := range []string{"attempts/target", "requests/s", "5s/request", "/private/"} {
				if strings.Contains(plan, unwanted) {
					t.Errorf("offline plan implies live acquisition or leaks path: %s", plan)
				}
			}
		})
	}
}

func TestRunPlanSilenceAndOutputErrors(t *testing.T) {
	config := wafmeow.DefaultConfig()
	opts := newOptions(config)
	opts.Silent = true
	if err := printRunPlan(failedConsole{}, opts, config); err != nil {
		t.Fatalf("silent plan wrote to sink: %v", err)
	}
	opts.Silent = false
	if err := printRunPlan(failedConsole{}, opts, config); err == nil {
		t.Fatal("plan swallowed writer failure")
	}
	if err := printRunPlan(shortPlanWriter{}, opts, config); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("plan swallowed short write: %v", err)
	}
}

func TestCLIRunPlanKeepsMachineStdoutAndSilentContract(t *testing.T) {
	for _, silent := range []bool{false, true} {
		args := []string{"--target=invalid://fixture", "--fast", "--jsonl"}
		if silent {
			args = append(args, "--silent")
		}
		code, stdout, stderr := runCLI(t, nil, args...)
		if code != 0 || len(decodeResultLines(t, stdout)) != 1 {
			t.Fatalf("plan polluted JSONL: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if silent && stderr != "" || !silent && !strings.Contains(stderr, "FAST MODE") {
			t.Fatalf("run plan ignored quiet selection: silent=%t stderr=%q", silent, stderr)
		}
	}
}

func TestCLIRunPlanFailureStopsBeforeRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var stdout bytes.Buffer
	code := runContext(context.Background(), []string{"--target", server.URL, "--baseline", "--jsonl"}, nil, false, &stdout, failedConsole{})
	if code != 1 || calls.Load() != 0 || stdout.Len() != 0 {
		t.Fatalf("failed plan publication started acquisition: exit=%d requests=%d stdout=%q", code, calls.Load(), stdout.String())
	}
}

func TestRunPlanDisclosesUserAgentOverrideWithoutValue(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.FastMode = true
	config.Headers = []wafmeow.Header{{Name: "user-agent", Value: "private-client"}}
	plan := runPlanText(newOptions(config), config)
	if !strings.Contains(plan, "custom User-Agent overrides every probe") || strings.Contains(plan, "private-client") {
		t.Fatalf("plan leaked header or hid override: %q", plan)
	}
}

type shortPlanWriter struct{}

func (shortPlanWriter) Write(data []byte) (int, error) { return len(data) / 2, nil }
