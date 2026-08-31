// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `
id: nginx-cpv1
language: c
cwe: CWE-787
cwe_name: Out-of-bounds write
target: nginx
harness: pov_harness
source:
  cp_repo: https://example.invalid/cp.git
  cp_commit: bd4490502e9e8f42b45e536cbc05d78ebc41aa0e
  src_repo: https://example.invalid/src.git
  src_ref: hg-asc-v2.0.0
  src_commit: 077e305de7e7f7a960d0ad440e7ed66f3da5a5ce
pov:
  input: .internal_only/cpv1/blobs/vuln_014.bin
  expected_sanitizer: "AddressSanitizer: heap-buffer-overflow"
  crash_location: "ngx_http_validate_from src/http/ngx_http_request.c:2231"
  signal: stderr.log
reference_patch: .internal_only/cpv1/patches/nginx/good_patch.diff
candidates:
  - id: cpv1-bad
    patch: .internal_only/cpv1/patches/nginx/bad_patch.diff
    label: unclassified
    expected_gate_reason: null
`

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "case.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAWellFormedCaseLoads(t *testing.T) {
	c, err := Load(write(t, good))
	if err != nil {
		t.Fatalf("a well-formed case was rejected: %v", err)
	}
	if c.ID != "nginx-cpv1" || c.PoV.ExpectedSanitizer == "" || len(c.Candidates) != 1 {
		t.Fatalf("loaded the wrong thing: %+v", c)
	}
}

// The oracle has to know the answer. A case missing its expected sanitizer
// still runs, and every candidate is then judged against an empty string,
// which matches anything: the corpus would silently grade everything correct.
//
// Each arm below is the good case with exactly one field removed, so a
// rejection is attributable to that field and not to the fixture.
func TestACaseMissingWhatItIsGradedOnIsRefused(t *testing.T) {
	drop := map[string]string{
		"expected sanitizer": `  expected_sanitizer: "AddressSanitizer: heap-buffer-overflow"`,
		"pov input":          `  input: .internal_only/cpv1/blobs/vuln_014.bin`,
		"reference patch":    `reference_patch: .internal_only/cpv1/patches/nginx/good_patch.diff`,
		"source commit":      `  src_commit: 077e305de7e7f7a960d0ad440e7ed66f3da5a5ce`,
		"harness":            `harness: pov_harness`,
	}
	for name, line := range drop {
		body := strings.Replace(good, line+"\n", "", 1)
		if body == good {
			t.Fatalf("fixture drift: %q not found in the good case", line)
		}
		if _, err := Load(write(t, body)); !errors.Is(err, ErrIncomplete) {
			t.Errorf("a case with no %s was accepted: %v", name, err)
		}
	}
}

// A candidate whose class is known must say what the gate should conclude.
// Scoring accept/reject alone would pass a gate broken into rejecting
// everything, which is exactly the failure the expected-reason column exists
// to catch.
func TestAClassifiedCandidateMustNameItsExpectedReason(t *testing.T) {
	classified := strings.Replace(good, "label: unclassified", "label: nonfunctional-plausible", 1)
	if _, err := Load(write(t, classified)); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a classified candidate with no expected reason was accepted: %v", err)
	}

	withReason := strings.Replace(classified, "expected_gate_reason: null",
		`expected_gate_reason: revert-attribute-fail`, 1)
	if _, err := Load(write(t, withReason)); err != nil {
		t.Fatalf("a classified candidate naming its reason was rejected: %v", err)
	}

	// And the unclassified case is still allowed to carry no reason, which is
	// what keeps the strictness above from blocking a corpus mid-build.
	if _, err := Load(write(t, good)); err != nil {
		t.Fatalf("an unclassified candidate with no reason was rejected: %v", err)
	}
}

// A candidate the gate is supposed to catch by replaying the input class needs
// a class to replay. Without one the stage never runs, and the candidate would
// be scored against a check that did not execute, which is the same false pass
// the expected-reason column exists to prevent.
func TestAClassReplayCandidateNeedsAFalsifyingClass(t *testing.T) {
	body := strings.Replace(good, "label: unclassified", "label: incomplete-fix", 1)
	body = strings.Replace(body, "expected_gate_reason: null",
		"expected_gate_reason: class-replay-fail", 1)

	if _, err := Load(write(t, body)); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a class-replay candidate with no falsifying class was accepted: %v", err)
	}

	withClass := body + `
falsifying_class:
  description: any PNG carrying an iCCP chunk
  generator: corpus/falsifying-class/libpng-iccp/mkpng.py
  discriminator: libpng names the keyword when it parses it correctly
  size: 79
`
	if _, err := Load(write(t, withClass)); err != nil {
		t.Fatalf("a class-replay candidate with a falsifying class was rejected: %v", err)
	}
}

// A class that cannot be run, or whose result cannot be read, is not a class.
func TestAFalsifyingClassNeedsAGeneratorAndADiscriminator(t *testing.T) {
	// Each arm withholds exactly one field and supplies the rest, or the
	// refusal comes from the wrong check and the other one stops being tested.
	for name, block := range map[string]string{
		"no generator":     "falsifying_class:\n  description: d\n  generator: \"\"\n  discriminator: x\n  size: 79\n",
		"no discriminator": "falsifying_class:\n  description: d\n  generator: g\n  discriminator: \"\"\n  size: 79\n",
		// Without it a replayed subset cannot be told from a covered class,
		// and agreement across a subset is the shape that accepts.
		"no size": "falsifying_class:\n  description: d\n  generator: g\n  discriminator: x\n",
	} {
		if _, err := Load(write(t, good+"\n"+block)); !errors.Is(err, ErrIncomplete) {
			t.Errorf("a falsifying class with %s was accepted: %v", name, err)
		}
	}
}

func TestAnUnknownLabelIsRefused(t *testing.T) {
	body := strings.Replace(good, "label: unclassified", "label: probably-fine", 1)
	if _, err := Load(write(t, body)); !errors.Is(err, ErrUnknownLabel) {
		t.Fatalf("an unknown label was accepted: %v", err)
	}
}

// A field we do not recognise means we are reading the case differently from
// whoever wrote it, and the difference could be the grading criterion.
func TestAnUnrecognisedFieldIsRefused(t *testing.T) {
	body := good + "\nseverity: critical\n"
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("a case carrying an unrecognised field was accepted")
	}
}

func TestDuplicateCandidateIDsAreRefused(t *testing.T) {
	body := good + `  - id: cpv1-bad
    patch: other.diff
    label: unclassified
    expected_gate_reason: null
`
	if _, err := Load(write(t, body)); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a case listing one candidate id twice was accepted: %v", err)
	}
}

func TestLoadDirRefusesAnEmptyCorpus(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("an empty corpus directory was accepted: %v", err)
	}
}
