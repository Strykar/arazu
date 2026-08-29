// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"path/filepath"
	"regexp"
	"strings"
)

// CrashSite is a sanitizer report location reduced to the parts a toolchain
// does not vary.
//
// File is a base name, not a path: the challenge reports container paths like
// /src/harnesses/bld/src/core/ngx_string.c, and the prefix is a property of
// where the build ran. Function survives what Line and Column do not.
//
// Line is deliberately absent. It shifts for two independent reasons, both
// demonstrated on this corpus: a patch that adds lines above the site moves it,
// and enabling -fsanitize-recover=address made one bug report at 1328, 1329 and
// 1330 in a single run, because recovery let execution continue into adjacent
// writes. Column shifts with the compiler. A discriminator has to be invariant
// to everything the experiment varies, and the experiment varies both.
type CrashSite struct {
	File     string
	Function string
}

func (s CrashSite) String() string { return s.Function + " (" + s.File + ")" }

func (s CrashSite) empty() bool { return s.File == "" && s.Function == "" }

// SiteMatch is three-valued for the same reason the gate's verdict is: the
// comparison can fail to determine an answer, and calling that "different"
// would manufacture a finding out of an optimisation setting.
type SiteMatch string

const (
	SiteSame   SiteMatch = "same"
	SiteDiffer SiteMatch = "different"
	// The report cannot be compared to the declaration. The case that forces
	// this is inlining: ASan names the frame it can attribute, so a small
	// function inlined into its caller is reported under the CALLER's name.
	// Same bug, same file, different reported function. Treating that as a new
	// crash site would let an optimisation flag produce a
	// new-sanitizer-finding verdict.
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
// stack frames alike.
//
// Frames matter as much as summaries: when a function is inlined its name can
// still appear in the stack even though the summary names the caller, so a
// report that mentions the declared site anywhere is evidence the same code was
// reached.
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

// Prefixes a harness adds to symbol names when it instruments a build. oss-fuzz
// renames the functions it wraps, so libpng's real reproduction reports
// OSS_FUZZ_png_handle_iCCP for a case declaring png_handle_iCCP. That prefix is
// a property of HOW the target was built, not of the function — the same reason
// File is reduced to a base name and Line is absent entirely.
//
// Deliberately an explicit list rather than a pattern. Something like ^[A-Z_]+_
// would also swallow a genuinely-named symbol, and a normaliser that eats real
// differences turns a matcher which fails safe into one that manufactures
// agreement — strictly worse, because SiteSame is the verdict that lets a patch
// through. crashsite_prefix_test.go pins that: functions differing by more than
// a known prefix must never compare equal, including ones wearing the prefix.
var instrumentationPrefixes = []string{"OSS_FUZZ_"}

// sameFunction compares symbols after removing instrumentation prefixes from
// BOTH sides, so a declaration written against an instrumented build still
// matches a report from one, and vice versa.
func sameFunction(a, b string) bool {
	strip := func(s string) string {
		for _, p := range instrumentationPrefixes {
			s = strings.TrimPrefix(s, p)
		}
		return s
	}
	return strip(a) == strip(b)
}

// MatchSite decides whether a report shows the SAME vulnerability the case
// declares, a DIFFERENT one, or cannot say.
//
// Fails safe in both directions. An unparseable declaration or an empty report
// is undetermined rather than different, because "we could not tell" must never
// be recorded as "this is a new bug".
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
	// Same file, different function: ambiguous between a genuinely different
	// bug in the same file and the declared function having been inlined into
	// its caller. Undetermined, and the operator gets both sites to look at.
	if sameFile {
		return SiteUndetermined
	}
	return SiteDiffer
}
