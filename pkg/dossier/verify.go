// SPDX-License-Identifier: Apache-2.0

package dossier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"arazu/pkg/contentstore"
	"arazu/pkg/gate"
)

// Outcomes of a verification. These are about the DOSSIER, never about the
// patch it describes.
//
// A dossier can be perfectly honest about a rejected patch, and a dossier can
// lie about an accepted one. Reporting the second as a patch failure would send
// an operator to debug a candidate when the fault is in the record, which is
// the wrong-artifact routing problem in the one tool whose job is telling them
// where to look. So none of these names a candidate.
const (
	// Verified: every machine-checkable claim was re-derived and held.
	Verified = "dossier-verified"
	// UnsupportedClaim: the dossier asserts something its own artifacts do not
	// support. This is the finding the verifier exists for.
	UnsupportedClaim = "dossier-unsupported-claim"
	// NotSelfContained: the dossier carries no artifacts, so there is nothing to
	// re-derive from.
	//
	// A NAMED REFUSAL, not a failure, and the distinction was decided before the
	// first such dossier was in front of us. Every dossier written before
	// pkg/dossier existed has this shape: it is pre-contract, not dishonest.
	// Folding it into UnsupportedClaim would report history as fraud.
	NotSelfContained = "dossier-not-self-contained"
	// Unreadable: the verifier could not run. Says nothing either way.
	Unreadable = "dossier-unreadable"
)

// Report is what a verification establishes.
type Report struct {
	Outcome string `json:"outcome"`
	Dir     string `json:"dir"`
	// Checks are the re-derivations attempted, in order, each with its result.
	// Present even on success: a verifier that prints nothing when it passes
	// cannot be told from one that checked nothing.
	Checks []Check `json:"checks"`
	// Problems is empty iff Outcome is Verified.
	Problems []string `json:"problems,omitempty"`
}

// Check is one re-derivation.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Verify re-derives every machine-checkable claim a dossier makes, from the
// bytes in the dossier.
//
// RE-DERIVE, NOT RE-READ. Parsing the JSON and checking it against itself is a
// schema check wearing an auditor's name: it would pass every dossier ever
// written, including one whose artifacts were replaced after the fact. So each
// check here recomputes something and compares: the artifacts are rehashed, the
// content root is recomputed over the directory, and coverage is established
// from the measurement rather than from the decision's say-so.
func Verify(dir, expectRoot string) (Report, error) {
	r := Report{Dir: dir, Outcome: Verified}

	raw, err := os.ReadFile(filepath.Join(dir, DecisionFile))
	if err != nil {
		return Report{Dir: dir, Outcome: Unreadable,
			Problems: []string{fmt.Sprintf("no %s: %v", DecisionFile, err)}}, nil
	}
	var d gate.Decision
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Report{Dir: dir, Outcome: Unreadable,
			Problems: []string{fmt.Sprintf("%s does not parse: %v", DecisionFile, err)}}, nil
	}
	r.add("decision parses", true, "")

	// The invariants the gate enforces on emit, re-checked on read by someone
	// who does not trust the process that produced them. That is the whole
	// argument for the schema.
	if err := d.Validate(); err != nil {
		r.fail("decision is internally consistent", err.Error())
	} else {
		r.add("decision is internally consistent", true, "")
	}

	if len(d.Artifacts) == 0 {
		r.Outcome = NotSelfContained
		r.add("carries its artifacts", false,
			"no artifacts recorded, so nothing can be re-derived; written before pkg/dossier existed")
		return r, nil
	}

	// Each artifact: relative, present, and hashing to what was recorded.
	for _, a := range d.Artifacts {
		name := "artifact " + a.Role
		if filepath.IsAbs(a.Path) || strings.Contains(a.Path, "..") {
			r.fail(name, fmt.Sprintf("path %q escapes the dossier, so it names a file this "+
				"directory does not carry", a.Path))
			continue
		}
		sum, err := hashFile(filepath.Join(dir, a.Path))
		if err != nil {
			r.fail(name, fmt.Sprintf("%s: %v", a.Path, err))
			continue
		}
		if sum != a.SHA256 {
			r.fail(name, fmt.Sprintf("%s hashes to %s, decision claims %s",
				a.Path, sum[:16], short(a.SHA256)))
			continue
		}
		r.add(name, true, a.Path)
	}

	// The content root, recomputed. A decision that records one is claiming the
	// directory was sealed under it; if the recomputation differs, either the
	// dossier changed after sealing or the root was never over this content.
	files, root, err := contentstore.MeasureBundle(dir)
	if err != nil {
		r.fail("content root recomputes", err.Error())
		return r.done(), nil
	}
	// expectRoot is the value the seal was taken over, supplied by the caller
	// because the dossier cannot carry it: writing a root into decision.json
	// changes the root. Empty means the caller has no seal to check against, so
	// the recomputation is reported and compared to nothing.
	switch {
	case expectRoot == "":
		r.add("content root recomputes", true,
			short(root)+" (no expected root supplied, so nothing to compare)")
	case root != expectRoot:
		r.fail("content root matches the seal", fmt.Sprintf(
			"directory measures to %s, seal was taken over %s", short(root), short(expectRoot)))
	default:
		r.add("content root matches the seal", true, short(root))
	}

	// Coverage, established from the measurement rather than assumed. The seal
	// binds whatever was measured: an artifact outside the root can be replaced
	// with the seal still verifying, which is the ordering hazard one artifact
	// along from the decision itself.
	covered := map[string]bool{}
	for _, f := range files {
		covered[filepath.ToSlash(f.Path)] = true
	}
	var uncovered []string
	for _, want := range append([]string{DecisionFile}, artifactPaths(d)...) {
		if !covered[filepath.ToSlash(want)] {
			uncovered = append(uncovered, want)
		}
	}
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		r.fail("measured root covers the evidence",
			"outside the root: "+strings.Join(uncovered, ", "))
	} else {
		r.add("measured root covers the evidence", true,
			fmt.Sprintf("%d files", len(files)))
	}

	return r.done(), nil
}

func artifactPaths(d gate.Decision) []string {
	out := make([]string, 0, len(d.Artifacts))
	for _, a := range d.Artifacts {
		out = append(out, a.Path)
	}
	return out
}

func (r *Report) add(name string, ok bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail})
}

func (r *Report) fail(name, detail string) {
	r.add(name, false, detail)
	r.Problems = append(r.Problems, name+": "+detail)
}

// done sets the outcome from the problems found, unless an earlier stage
// already named a more specific one.
func (r Report) done() Report {
	if len(r.Problems) > 0 && r.Outcome == Verified {
		r.Outcome = UnsupportedClaim
	}
	return r
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("named by the decision and not in the dossier")
		}
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
