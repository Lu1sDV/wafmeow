package main

import (
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
)

// The default plan fits one line. Only customized safety controls need extra
// lines. Never print targets, header values, origin values, or local paths.
func runPlanText(opts options, config wafmeow.Config) string {
	if opts.Silent {
		return ""
	}
	var heading, limits string
	var details []string
	defaults := wafmeow.DefaultConfig()
	if opts.EvidenceFile != "" {
		if opts.EvidenceFormat == "httpx" {
			heading = "OFFLINE HTTPX | serial import | no network requests"
		} else {
			heading = fmt.Sprintf("OFFLINE %s | %d classification workers | no network requests",
				strings.ToUpper(terminalText(opts.EvidenceFormat)), min(config.Concurrency, runtime.GOMAXPROCS(0)))
		}
		limits = "Saved responses only; no new requests to targets"
		if config.MaxBodyBytes != defaults.MaxBodyBytes {
			details = append(details, fmt.Sprintf("body limit %dB", config.MaxBodyBytes))
		}
	} else {
		connections := config.MaxConnections
		if connections == 0 {
			connections = max(config.Concurrency, config.ProbeConcurrency)
		}
		mode, checks, fanout := "DEEP", 8, min(config.ProbeConcurrency, connections, 7)
		if config.BaselineOnly {
			mode, checks, fanout = "BASELINE", 1, 1
		} else if config.FastMode {
			mode, checks, fanout = "FAST", 3, min(3, connections)
		}
		checkUnit := "checks"
		if checks == 1 {
			checkUnit = "check"
		}
		heading = fmt.Sprintf("%s MODE | %d planned HTTP %s | %d target workers", mode, checks, checkUnit, config.Concurrency)
		limits = fmt.Sprintf("Parallel checks: up to %d/target | Timeouts: %s/request, %s/target",
			fanout, config.RequestTimeout, config.TargetTimeout)
		if connections != config.Concurrency || (config.MaxConnections != 0 && config.MaxConnections != defaults.MaxConnections) {
			details = append(details, fmt.Sprintf("%d in flight", connections))
		}
		if config.MaxRequests != defaults.MaxRequests {
			details = append(details, fmt.Sprintf("%d attempts/target", config.MaxRequests))
		}
		if config.MaxRedirects != defaults.MaxRedirects || config.RedirectPolicy != defaults.RedirectPolicy {
			if config.RedirectPolicy == "none" {
				details = append(details, "redirects off")
			} else {
				details = append(details, fmt.Sprintf("%d redirects (%s)", config.MaxRedirects, terminalText(config.RedirectPolicy)))
			}
		}
		if len(config.AllowedOrigins) != 0 {
			details = append(details, "origin allowlist on")
		}
		if config.RequestsPerSecond != 0 {
			details = append(details, planRate(config.RequestsPerSecond)+" global")
		}
		if config.PerOriginRequestsPerSecond != 0 {
			details = append(details, planRate(config.PerOriginRequestsPerSecond)+" per origin")
		}
		if !config.BaselineOnly {
			for _, header := range config.Headers {
				if strings.EqualFold(header.Name, "User-Agent") {
					details = append(details, "custom User-Agent overrides every probe")
					break
				}
			}
		}
		if config.Browser != nil && config.Browser.Mode != "off" {
			details = append(details, fmt.Sprintf("browser %s (%s)", terminalText(config.Browser.Mode), config.Browser.Timeout))
		}
	}
	if opts.JSONL {
		details = append(details, "JSONL stdout")
	}
	if opts.OutputFile != "" {
		format, _ := reportFormat(opts.OutputFile) // Validated before execution.
		details = append(details, strings.ToUpper(format)+" report")
	}
	if opts.JournalFile != "" {
		details = append(details, "journal")
	}
	if opts.Strict {
		details = append(details, "strict")
	}
	return runPlanBox(heading, limits, details)
}

// Use a restrained, rounded terminal box with a blank line after it. The fixed
// width fits a standard 80-column terminal, and long optional settings wrap.
func runPlanBox(heading, limits string, details []string) string {
	const interior = 68
	const title = "╭─ RUN PLAN "
	var plan strings.Builder
	plan.WriteString(title)
	plan.WriteString(strings.Repeat("─", interior+4-len([]rune(title))-1))
	plan.WriteString("╮\n")
	lines := []string{heading, limits}
	if len(details) != 0 {
		// Keep every complete setting together. A wrapping word in the middle
		// of "origin allowlist on" or "JSONL report" obscures its meaning.
		current := "Settings: "
		for _, detail := range details {
			separator := ""
			if strings.TrimSpace(current) != "Settings:" && strings.TrimSpace(current) != "" {
				separator = " | "
			}
			if len([]rune(current))+len([]rune(separator))+len([]rune(detail)) > interior &&
				strings.TrimSpace(current) != "Settings:" {
				lines = append(lines, strings.TrimRight(current, " "))
				current, separator = "          ", ""
			}
			current += separator + detail
		}
		lines = append(lines, current)
	}
	for _, raw := range lines {
		indent := strings.Repeat(" ", len(raw)-len(strings.TrimLeft(raw, " ")))
		line := indent
		for _, word := range strings.Fields(raw) {
			separator := ""
			if strings.TrimSpace(line) != "" {
				separator = " "
			}
			if strings.TrimSpace(line) != "" && len([]rune(line))+len([]rune(separator))+len([]rune(word)) > interior {
				fmt.Fprintf(&plan, "│ %-*s │\n", interior, line)
				line, separator = indent, ""
			}
			line += separator + word
		}
		fmt.Fprintf(&plan, "│ %-*s │\n", interior, line)
	}
	plan.WriteString("╰")
	plan.WriteString(strings.Repeat("─", interior+2))
	plan.WriteString("╯\n\n")
	return plan.String()
}

// Keep run-plan content on stderr, including human scans.
func printRunPlan(writer io.Writer, opts options, config wafmeow.Config) error {
	return writeRunPlan(writer, runPlanText(opts, config))
}

func writeRunPlan(writer io.Writer, plan string) error {
	if plan == "" {
		return nil
	}
	n, err := io.WriteString(writer, plan)
	if err == nil && n != len(plan) {
		return io.ErrShortWrite
	}
	return err
}

func planRate(rate float64) string {
	if rate == 0 {
		return "unlimited"
	}
	return strconv.FormatFloat(rate, 'g', -1, 64) + " requests/s"
}
