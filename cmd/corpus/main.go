// SPDX-License-Identifier: Apache-2.0

// Command corpus checks the case files the gate is graded against.
//
// The generator scripts prove each case round-trips by running it. This
// checks the written form: that every case still parses, still says what it
// is graded on, and that the files it points at are actually there. A corpus
// entry whose blob has been moved would fail at gate time as an
// indistinguishable "the patch did not stop it".
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"arazu/pkg/corpus"
)

type report struct {
	Dir          string   `json:"dir"`
	Cases        int      `json:"cases"`
	Candidates   int      `json:"candidates"`
	Unclassified []string `json:"unclassified,omitempty"`
	Problems     []string `json:"problems,omitempty"`
	Decision     string   `json:"decision"`
}

func main() {
	dir := flag.String("dir", "corpus/cases/nginx", "directory of case files")
	root := flag.String("root", "", "challenge checkout the case paths are relative to, for existence checks")
	repo := flag.String("repo", ".", "this repository, which is where synthesised candidates live")
	flag.Parse()

	r := report{Dir: *dir}

	cases, err := corpus.LoadDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		emit(report{Dir: *dir, Decision: "REJECT", Problems: []string{err.Error()}}, 1)
	}
	r.Cases = len(cases)

	for _, c := range cases {
		r.Candidates += len(c.Candidates)
		for _, cand := range c.Candidates {
			if cand.Label == corpus.LabelUnclassified {
				r.Unclassified = append(r.Unclassified, cand.ID)
			}
		}
		if *root == "" {
			continue
		}
		// The paths are only meaningful against a checked-out challenge, so
		// this is checked when a root is given rather than assumed.
		for label, p := range map[string]string{
			"pov input":       c.InputPath(*root, *repo),
			"reference patch": c.ReferencePatchPath(*root, *repo),
		} {
			if _, err := os.Stat(p); err != nil {
				r.Problems = append(r.Problems, fmt.Sprintf("%s: %s %s is missing", c.ID, label, p))
			}
		}
		for _, cand := range c.Candidates {
			// Candidates we synthesised live in this repository, not in the
			// challenge checkout, so the path is resolved against the tree the
			// candidate names rather than against *root for everything.
			if _, err := os.Stat(c.CandidatePatchPath(cand, *root, *repo)); err != nil {
				r.Problems = append(r.Problems, fmt.Sprintf("%s: candidate %s patch %s is missing", c.ID, cand.ID, cand.Patch))
			}
		}
	}

	if len(r.Problems) > 0 {
		emit(r, 1)
	}
	emit(r, 0)
}

func emit(r report, code int) {
	if r.Decision == "" {
		if code == 0 {
			r.Decision = "ACCEPT"
		} else {
			r.Decision = "REJECT"
		}
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))

	fmt.Fprintf(os.Stderr, "%s: %d cases, %d candidates", r.Decision, r.Cases, r.Candidates)
	if n := len(r.Unclassified); n > 0 {
		fmt.Fprintf(os.Stderr, ", %d still unclassified", n)
	}
	fmt.Fprintln(os.Stderr)
	for _, p := range r.Problems {
		fmt.Fprintln(os.Stderr, "  "+p)
	}
	os.Exit(code)
}
