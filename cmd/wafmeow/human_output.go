package main

import (
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
	"github.com/rivo/uniseg"
)

// printReadableResult is the human presentation of a full Result. The machine
// output, supporting evidence indices, diagnostics and redirect URLs are not
// modified; the compact view intentionally does not repeat probe payload URLs.
func printReadableResult(stdout, stderr io.Writer, result wafmeow.Result, suppressWarnings bool, colors, diagnostics *aurora.Aurora) error {
	var out strings.Builder
	outcome := humanOutcome(result)
	status := colors.Yellow("[ " + outcome + " ]")
	switch outcome {
	case "WAF MATCH", "ERROR":
		status = colors.Red("[ " + outcome + " ]")
	case "NO WAF MATCH":
		status = colors.Green("[ " + outcome + " ]")
	}
	fmt.Fprintf(&out, "%s  %s\n", colors.Bold(terminalText(result.Target)), colors.Bold(status))

	for _, match := range result.Outcome.Matches {
		support := compactMatchSupport(result, match)
		fmt.Fprintf(&out, "  %s  %s", colors.Bold("WAF"), colors.Bold(colors.Green(terminalText(match.Product))))
		if support != "" {
			fmt.Fprintf(&out, "  (%s)", support)
		}
		out.WriteByte('\n')
	}
	checkUnit := "checks"
	if len(result.Evidence) == 1 {
		checkUnit = "check"
	}
	fmt.Fprintf(&out, "  %s  %s HTTP %s recorded\n", colors.Bold("Checks"), colors.Bold(strconv.Itoa(len(result.Evidence))), checkUnit)

	if result.Generic.Mode != "" || result.Generic.Reason != "" {
		humanWrapRow(&out, "Review", humanReviewReason(result.Generic))
	}
	if channels := compactChannelLimitations(result); channels != "" {
		humanWrapRow(&out, "Channels", channels)
	}
	redirects, redirectCount := compactScopeRedirects(result)
	for _, item := range redirects {
		humanWrapRow(&out, "Redirect", item)
	}
	if browser := result.Browser; browser != nil {
		humanWrapRow(&out, "Browser", fmt.Sprintf("%s (%s); text %s, image %s (separate from HTTP)",
			terminalText(browser.State), terminalText(browser.Mode),
			terminalText(browser.DOM.State), terminalText(browser.Screenshot.State)))
		if browser.DOM.SaveState != "" || browser.Screenshot.SaveState != "" {
			humanWrapRow(&out, "Artifacts", fmt.Sprintf("text save %s; image save %s",
				terminalText(browser.DOM.SaveState), terminalText(browser.Screenshot.SaveState)))
		}
	}
	if reason := humanResultExplanation(result, redirectCount); reason != "" {
		label := "Review"
		if result.Outcome.State == wafmeow.Incomplete {
			label = "Why incomplete"
		} else if result.Outcome.State == wafmeow.Failed {
			label = "Why failed"
		} else if len(result.Outcome.Matches) != 0 {
			label = "Note"
		}
		humanWrapRow(&out, label, reason)
	}
	out.WriteByte('\n')
	if _, err := io.WriteString(stdout, out.String()); err != nil {
		return err
	}
	if suppressWarnings {
		return nil
	}

	// Redirect-scope and truncation problems have already been summarized
	// above. Emit remaining detailed diagnostics to stderr (or --debug for all
	// details) without overwhelming the normal output with probe payload URLs.
	warnings := result
	warnings.Outcome.Diagnostics = nil
	for _, diagnostic := range result.Outcome.Diagnostics {
		if diagnostic.Code != "redirect_scope" && diagnostic.Code != "body_truncated" {
			warnings.Outcome.Diagnostics = append(warnings.Outcome.Diagnostics, diagnostic)
		}
	}
	if writersShareTerminal(stdout, stderr) {
		return printNestedResultDiagnostics(stderr, warnings, diagnostics, "  ")
	}
	return printResultDiagnostics(stderr, warnings, diagnostics)
}

// The library's "observation" count is not a wire-request count: redirects
// and retries can send multiple HTTP requests for one observation.
func compactMatchSupport(result wafmeow.Result, match wafmeow.Match) string {
	indices := supportingEvidence(match, len(result.Evidence))
	if len(indices) == 0 {
		return "supporting response unavailable"
	}
	support := make([]string, 0, min(2, len(indices)))
	for _, index := range indices[:min(2, len(indices))] {
		observation := result.Evidence[index]
		role := terminalText(observation.Role)
		if role == "" {
			role = "observation " + strconv.Itoa(index+1)
		}
		if uniseg.StringWidth(role) > 36 {
			role = limitHumanText(role, 36)
		}
		status := ""
		if observation.StatusCode >= 100 && observation.StatusCode <= 999 {
			status = fmt.Sprintf(" HTTP %d", observation.StatusCode)
		}
		support = append(support, role+status)
	}
	if remaining := len(indices) - len(support); remaining > 0 {
		support = append(support, fmt.Sprintf("+%d more", remaining))
	}
	return strings.Join(support, ", ")
}

type scopeDestination struct {
	origin string
	status int
	count  int
}

// Report the destination origin, never the request-specific path, query,
// userinfo or probe payload. A full URL stays in JSONL and --debug.
func compactScopeRedirects(result wafmeow.Result) ([]string, int) {
	var grouped []scopeDestination
	index := make(map[string]int)
	seenEvidence := make(map[int]bool)
	total := 0
	for _, diagnostic := range result.Outcome.Diagnostics {
		if diagnostic.Code != "redirect_scope" || seenEvidence[diagnostic.Evidence] {
			continue
		}
		seenEvidence[diagnostic.Evidence] = true
		total++
		origin := "unknown destination"
		status := 0
		if diagnostic.Evidence >= 0 && diagnostic.Evidence < len(result.Evidence) {
			evidence := result.Evidence[diagnostic.Evidence]
			status = evidence.StatusCode
			if parsed, err := url.Parse(evidence.BlockedRedirectURL); err == nil && parsed.Host != "" &&
				(parsed.Scheme == "https" || parsed.Scheme == "http") {
				origin = parsed.Scheme + "://" + parsed.Host
			}
		}
		origin = limitHumanText(terminalText(origin), 64)
		key := fmt.Sprintf("%d/%s", status, origin)
		if at, ok := index[key]; ok {
			grouped[at].count++
		} else {
			index[key] = len(grouped)
			grouped = append(grouped, scopeDestination{origin: origin, status: status, count: 1})
		}
	}
	var lines []string
	for _, dest := range grouped[:min(3, len(grouped))] {
		code := "HTTP redirect"
		if dest.status >= 300 && dest.status <= 399 {
			code = fmt.Sprintf("HTTP %d", dest.status)
		}
		unit := "checks"
		if dest.count == 1 {
			unit = "check"
		}
		lines = append(lines, fmt.Sprintf("%d %s: %s to %s (outside allowed scope)", dest.count, unit, code, dest.origin))
	}
	if len(grouped) > 3 {
		lines = append(lines, fmt.Sprintf("%d additional destinations (see --debug or JSONL)", len(grouped)-3))
	}
	return lines, total
}

// Surface only non-complete explicit channels. These limitations matter even
// when catalogue-relative classification is complete. Group identical channel
// states to avoid 8 repeated lines for the same unavailable response.
func compactChannelLimitations(result wafmeow.Result) string {
	var limitations []string
	seen := make(map[string]bool)
	for _, evidence := range result.Evidence {
		availability := evidence.Availability
		if availability == nil {
			continue
		}
		for _, channel := range []struct {
			name  string
			state wafmeow.ChannelState
		}{
			{"status", availability.Status},
			{"headers", availability.Headers},
			{"reason", availability.Reason},
			{"body", availability.Body},
		} {
			if channel.state == wafmeow.ChannelComplete {
				continue
			}
			state := string(channel.state)
			if channel.state == wafmeow.ChannelIncomplete {
				state = "partial"
			}
			description := channel.name + " " + terminalText(state)
			if !seen[description] {
				seen[description] = true
				limitations = append(limitations, description)
			}
		}
	}
	return strings.Join(limitations, "; ")
}

// A complete classification can still contain truncated bodies or diagnostics.
// Only explain incompleteness when the classifier actually reports it; matches
// can coexist with incomplete evaluation of other products.
func humanResultExplanation(result wafmeow.Result, scopeRedirects int) string {
	if result.Outcome.State == wafmeow.Failed {
		for _, d := range result.Outcome.Diagnostics {
			switch d.Code {
			case "invalid_target":
				return "The target URL could not be parsed or accepted; review its scheme and syntax."
			case "target_scope":
				return "The starting URL is outside the allowed origins. No scan was sent to that origin."
			case "invalid_evidence":
				return "Saved HTTP evidence is invalid; check the capture's channel metadata."
			}
		}
		return "Target evaluation failed; inspect the diagnostic details before drawing a WAF conclusion."
	}

	truncated := 0
	for _, e := range result.Evidence {
		if e.BodyTruncated {
			truncated++
		}
	}
	timeoutOrFailure := 0
	for _, d := range result.Outcome.Diagnostics {
		switch d.Code {
		case "body_truncated":
			// Already counted from the observation to avoid duplicate diagnostics.
		case "redirect_scope":
			// Reported separately above.
		default:
			if d.Code != "" {
				timeoutOrFailure++
			}
		}
	}
	unknownChannels := 0
	for _, e := range result.Evidence {
		if e.Availability != nil &&
			(e.Availability.Body != wafmeow.ChannelComplete ||
				e.Availability.Headers != wafmeow.ChannelComplete ||
				e.Availability.Status != wafmeow.ChannelComplete ||
				e.Availability.Reason != wafmeow.ChannelComplete) {
			unknownChannels++
		}
	}
	if result.Outcome.State == wafmeow.Incomplete {
		var causes []string
		if scopeRedirects > 0 {
			unit := "checks"
			if scopeRedirects == 1 {
				unit = "check"
			}
			causes = append(causes, fmt.Sprintf("%d %s stopped at redirects outside the allowed scope; destination responses were not fetched", scopeRedirects, unit))
		}
		if truncated > 0 {
			causes = append(causes, humanTruncationPhrase(truncated))
		}
		if timeoutOrFailure > 0 {
			if timeoutOrFailure == 1 {
				causes = append(causes, "1 HTTP diagnostic was recorded")
			} else {
				causes = append(causes, fmt.Sprintf("%d HTTP diagnostics were recorded", timeoutOrFailure))
			}
		}
		if unknownChannels > 0 {
			if unknownChannels == 1 {
				causes = append(causes, "1 observation has partial, unavailable or unverified response channels")
			} else {
				causes = append(causes, fmt.Sprintf("%d observations have partial, unavailable or unverified response channels", unknownChannels))
			}
		}
		if len(causes) == 0 {
			if len(result.Evidence) == 0 {
				causes = append(causes, "no usable HTTP responses were collected")
			} else {
				causes = append(causes, "available responses cannot settle every relevant fingerprint rule")
			}
		}
		return "Some WAF fingerprint checks remain unresolved because " + strings.Join(causes, "; ") +
			". A missing match here is not evidence that no WAF is present."
	}
	if truncated > 0 {
		return humanTruncationPhrase(truncated) + ". The classification resolved, but not all HTTP content was retained."
	}
	if unknownChannels > 0 {
		return "Classification resolved against the available evidence, but some HTTP channels are partial, unavailable or unverified."
	}
	if humanOutcome(result) == "REVIEW" && len(result.Outcome.Diagnostics) > 0 {
		return "HTTP diagnostics were recorded. Classification may be complete despite individual acquisition problems."
	}
	return ""
}

func humanTruncationPhrase(count int) string {
	if count == 1 {
		return "1 response body was truncated"
	}
	return fmt.Sprintf("%d response bodies were truncated", count)
}

// Wrap only explanatory prose, not arbitrary URL query values. Keep the label
// fixed and align continuation lines for narrow terminal readability.
func humanWrapRow(out *strings.Builder, label, content string) {
	const width = 76
	prefix := "  " + label + "  "
	indent := strings.Repeat(" ", uniseg.StringWidth(prefix))
	line := prefix
	for _, word := range strings.Fields(content) {
		spacer := ""
		if line != prefix {
			spacer = " "
		}
		if line != prefix && uniseg.StringWidth(line)+len(spacer)+uniseg.StringWidth(word) > width {
			out.WriteString(line)
			out.WriteByte('\n')
			line, spacer = indent, ""
		}
		if line == indent {
			line += word
		} else {
			line += spacer + word
		}
	}
	out.WriteString(line)
	out.WriteByte('\n')
}

func limitHumanText(value string, maxWidth int) string {
	if uniseg.StringWidth(value) <= maxWidth {
		return value
	}
	var out strings.Builder
	for _, r := range value {
		next := out.String() + string(r)
		if uniseg.StringWidth(next)+1 > maxWidth {
			break
		}
		out.WriteRune(r)
	}
	return out.String() + "…"
}
