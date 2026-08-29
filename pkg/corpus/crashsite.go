// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"path/filepath"
	"regexp"
	"strings"
)

// CrashSite is a sanitizer report location reduced to the parts a toolchain
// does not vary. File is a base name because the reported path records where
// the build ran. Line and Column are absent: a patch above the site moves the
// line, -fsanitize-recover=address reports one bug at adjacent lines, and the
// column moves with the compiler.
type CrashSite struct {
	File     string
	Function string
}

func (s CrashSite) String() string { return s.Function + " (" + s.File + ")" }

func (s CrashSite) empty() bool { return s.File == "" && s.Function == "" }

// SiteMatch is three-valued: calling an undetermined comparison "different"
// would manufacture a finding out of an optimisation setting.
type SiteMatch string

const (
	SiteSame   SiteMatch = "same"
	SiteDiffer SiteMatch = "different"
	// Not comparable. Inlining is what forces it: ASan reports an inlined
	// function under its caller's name, and calling that a new site would let
	// an optimisation flag produce a new-sanitizer-finding verdict.
	SiteUndetermined SiteMatch = "undetermined"
)

// "<function> /path/to/file.c:LINE:COL", the form normalise-nginx.sh writes.
var declaredRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(\S+?):\d+(?::\d+)?\s*$`)

// "SUMMARY: AddressSanitizer: <kind> /path/file.c:LINE:COL in <function>", and
// the stack-frame form "#N 0xADDR in <function> /path/file.c:LINE:COL".
var summaryRe = regexp.MustCompile(`SUMMARY:\s+\w+Sanitizer:\s+\S+\s+(\S+?):\d+(?::\d+)?\s+in\s+([A-Za-z_][A-Za-z0-9_]*)`)
var frameRe = regexp.MustCompile(`#\d+\s+0x[0-9a-f]+\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S+?):\d+(?::\d+)?`)

// ParseDeclaredSite reads a case's crash_location.
func ParseDeclaredSite(s string) CrashSite {
	m := declaredRe.FindStringSubmatch(s)
	if m == nil {
		return CrashSite{}
	}
	return CrashSite{File: filepath.Base(m[2]), Function: m[1]}
}

// ParseReportSites returns every site a sanitizer report names, summaries and
// stack frames alike. Frames matter because an inlined function's name can
// appear in the stack while the summary names its caller.
func ParseReportSites(report string) []CrashSite {
	var out []CrashSite
	seen := map[CrashSite]bool{}
	add := func(file, fn string) {
		s := CrashSite{File: filepath.Base(file), Function: fn}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, m := range summaryRe.FindAllStringSubmatch(report, -1) {
		add(m[1], m[2])
	}
	for _, m := range frameRe.FindAllStringSubmatch(report, -1) {
		add(m[2], m[1])
	}
	return out
}

// Prefixes a harness adds when it instruments a build: oss-fuzz reports
// OSS_FUZZ_png_handle_iCCP for a case declaring png_handle_iCCP, a property of
// how the target was built. An explicit list, not a pattern: something like
// ^[A-Z_]+_ would swallow real differences, and SiteSame lets a patch through.
var instrumentationPrefixes = []string{"OSS_FUZZ_"}

// sameFunction compares symbols with instrumentation prefixes stripped from
// both sides, so an instrumented report matches a plain declaration either way.
func sameFunction(a, b string) bool {
	strip := func(s string) string {
		for _, p := range instrumentationPrefixes {
			s = strings.TrimPrefix(s, p)
		}
		return s
	}
	return strip(a) == strip(b)
}

// MatchSite decides whether a report shows the same vulnerability the case
// declares, a different one, or cannot say. An unparseable declaration or an
// empty report is undetermined, never different.
func MatchSite(declared CrashSite, report string) SiteMatch {
	if declared.empty() {
		return SiteUndetermined
	}
	sites := ParseReportSites(report)
	if len(sites) == 0 {
		return SiteUndetermined
	}
	sameFile := false
	for _, s := range sites {
		if s.File == declared.File && sameFunction(s.Function, declared.Function) {
			return SiteSame
		}
		if strings.EqualFold(s.File, declared.File) {
			sameFile = true
		}
	}
	// Same file, different function is ambiguous between a different bug and
	// the declared function having been inlined into its caller.
	if sameFile {
		return SiteUndetermined
	}
	return SiteDiffer
}
