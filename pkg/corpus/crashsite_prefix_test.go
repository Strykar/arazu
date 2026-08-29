// SPDX-License-Identifier: Apache-2.0

package corpus

import "testing"

// These land BEFORE any instrumentation-prefix stripping, and pin the behaviour
// that stripping must not break.
//
// The hazard is specific: normalising a symbol name to make a known-good pair
// agree can also collapse pairs that genuinely differ. That trades a matcher
// which fails safe for one which manufactures agreement — a strictly worse
// failure, because "same site" is the verdict that lets a patch through.

func summaryFor(fn string) string {
	return "SUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow " +
		"/src/libpng/pngrutil.c:1447:10 in " + fn
}

// A different function in the same file must never read as the same site,
// prefix stripping or not. Same file is what makes this the dangerous case:
// the file matches, so only the function can separate them.
func TestDifferentFunctionSameFileIsNotSame(t *testing.T) {
	declared := CrashSite{File: "pngrutil.c", Function: "png_handle_iCCP"}
	for _, fn := range []string{
		"png_handle_zTXt",            // plainly different
		"OSS_FUZZ_png_handle_zTXt",   // different, and wearing the prefix
		"png_handle_iCCP_helper",     // shares the declared name as a prefix
		"OSS_FUZZ_png_handle_iCCP_x", // both traps at once
	} {
		if got := MatchSite(declared, summaryFor(fn)); got == SiteSame {
			t.Errorf("%s vs declared %s: got SiteSame, want anything else",
				fn, declared.Function)
		}
	}
}

// A declared symbol that itself begins with the prefix must still match its own
// report. Stripping only one side would break this.
func TestDeclaredSymbolWearingThePrefixStillMatchesItself(t *testing.T) {
	declared := CrashSite{File: "pngrutil.c", Function: "OSS_FUZZ_png_handle_iCCP"}
	if got := MatchSite(declared, summaryFor("OSS_FUZZ_png_handle_iCCP")); got != SiteSame {
		t.Errorf("identical symbols: got %v, want SiteSame", got)
	}
}

// An empty or unparseable report stays undetermined. Stripping must not turn
// "no information" into a decision.
func TestNoInformationStaysUndetermined(t *testing.T) {
	declared := CrashSite{File: "pngrutil.c", Function: "png_handle_iCCP"}
	for _, report := range []string{"", "no sanitizer output here"} {
		if got := MatchSite(declared, report); got != SiteUndetermined {
			t.Errorf("report %q: got %v, want SiteUndetermined", report, got)
		}
	}
}

// The case this fix exists for. oss-fuzz renames instrumented symbols with an
// OSS_FUZZ_ prefix, so libpng's real reproduction reports
// OSS_FUZZ_png_handle_iCCP against a case declaring png_handle_iCCP. Before the
// strip this returns undetermined: fail-safe, but it means the matcher can only
// ever decline on the one case the corpus has for it.
func TestInstrumentationPrefixDoesNotHideAMatch(t *testing.T) {
	declared := CrashSite{File: "pngrutil.c", Function: "png_handle_iCCP"}
	if got := MatchSite(declared, summaryFor("OSS_FUZZ_png_handle_iCCP")); got != SiteSame {
		t.Errorf("got %v, want SiteSame: the prefix is a build artifact of the "+
			"harness, not part of the function's identity", got)
	}
}
