package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
)

// A synthetic reproduction of a common cross-origin redirect: multiple
// selected checks yield the same blocked destination origin but distinct
// request-specific query payloads. No external network activity is involved.
func TestHumanGroupsRedirectedProbesWithoutDumpingPayloadURLs(t *testing.T) {
	result := wafmeow.Result{
		Target:  "https://source.example.test",
		Outcome: wafmeow.Outcome{State: wafmeow.Incomplete},
	}
	for i := 0; i < 8; i++ {
		destination := fmt.Sprintf("https://visitor:secret@destination.example.test/path/%d?p=long-encoded-canary-%d", i, i)
		result.Evidence = append(result.Evidence, wafmeow.EvidenceSummary{
			Role: "Probe", StatusCode: 302, ErrorCode: "redirect_scope", BlockedRedirectURL: destination,
		})
		result.Outcome.Diagnostics = append(result.Outcome.Diagnostics, wafmeow.Diagnostic{
			Code: "redirect_scope", Evidence: i, Message: "redirect outside allowed scope",
		})
	}
	var out, errOut bytes.Buffer
	noColors := aurora.New(aurora.WithColors(false))
	if err := printResult(&out, &errOut, result, false, noColors, noColors); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	for _, want := range []string{
		"https://source.example.test  [ INCOMPLETE ]",
		"Checks  8 HTTP checks recorded",
		"Redirect  8 checks: HTTP 302 to https://destination.example.test",
		"Why incomplete", "destination responses were not fetched",
	} {
		if !strings.Contains(strings.Join(strings.Fields(rendered), " "), strings.Join(strings.Fields(want), " ")) {
			t.Fatalf("missing useful redirect explanation %q: %q", want, rendered)
		}
	}
	for _, secret := range []string{"secret", "visitor", "canary", "path/0", "p=", "WARN", "302×8", "evidence  incomplete"} {
		if strings.Contains(rendered+errOut.String(), secret) {
			t.Fatalf("human output leaked verbose/private redirect details %q: %q / %q", secret, rendered, errOut.String())
		}
	}
	if strings.Count(rendered, "Redirect  ") != 1 || !strings.HasSuffix(rendered, "present.\n\n") {
		t.Fatalf("redirects not grouped or incomplete explanation not last: %q", rendered)
	}
}

func TestHumanReportsCompleteClassificationWithUnknownChannels(t *testing.T) {
	result := wafmeow.Result{
		Target:  "saved native",
		Outcome: wafmeow.Outcome{State: wafmeow.Complete},
		Evidence: []wafmeow.EvidenceSummary{{
			Role: "Normal", StatusCode: 200,
			Availability: &wafmeow.EvidenceAvailability{
				Status: wafmeow.ChannelComplete, Headers: wafmeow.ChannelIncomplete,
				Reason: wafmeow.ChannelUnavailable, Body: wafmeow.ChannelUnknown,
			},
		}},
	}
	var out, errOut bytes.Buffer
	noColors := aurora.New(aurora.WithColors(false))
	if err := printResult(&out, &errOut, result, true, noColors, noColors); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[ REVIEW ]", "Channels  headers partial; reason unavailable; body unknown",
		"Classification resolved", "1 HTTP check recorded"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("complete classification lost channel limitations %q: %q", want, out.String())
		}
	}
	if strings.Contains(out.String(), "NO WAF MATCH") || errOut.Len() != 0 {
		t.Fatalf("unavailable channels incorrectly shown as clean or diagnostics leaked: %q / %q", out.String(), errOut.String())
	}
}
