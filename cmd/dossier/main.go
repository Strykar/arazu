// SPDX-License-Identifier: Apache-2.0

// dossier verify re-checks an evidence bundle without trusting whatever
// produced it.
//
// EXIT CODES ARE ABOUT THE RECORD, NOT THE PATCH, and deliberately share no
// vocabulary with the gate's. The gate's exit 1 means a candidate was refused;
// this tool's exit 1 means the dossier lies. Conflating them would send an
// operator to debug a patch when the fault is in the paperwork, in the one tool
// whose job is telling them where to look.
//
//	0  dossier-verified            every machine-checkable claim re-derived and held
//	1  dossier-unsupported-claim   the dossier asserts what its artifacts do not support
//	3  dossier-not-self-contained  no artifacts to re-derive from; pre-contract, not dishonest
//	2  dossier-unreadable          the verifier could not run, so it establishes nothing
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"arazu/pkg/dossier"
)

func main() {
	root := flag.String("content-root", "",
		"the root the seal was taken over; the dossier cannot carry it, because writing a root into decision.json changes the root")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dossier verify <dir> [-content-root <sha256>]")
	}
	// Subcommand first so the tool has room to grow, and so `dossier <dir>`
	// cannot be mistaken for a verification that ran.
	args := os.Args[1:]
	if len(args) < 2 || args[0] != "verify" {
		flag.Usage()
		os.Exit(2)
	}
	dir := args[1]
	_ = flag.CommandLine.Parse(args[2:])

	r, err := dossier.Verify(dir, *root)
	if err != nil {
		emit(dossier.Report{Dir: dir, Outcome: dossier.Unreadable,
			Problems: []string{err.Error()}}, 2)
	}
	emit(r, code(r.Outcome))
}

func code(outcome string) int {
	switch outcome {
	case dossier.Verified:
		return 0
	case dossier.UnsupportedClaim:
		return 1
	case dossier.NotSelfContained:
		return 3
	default:
		return 2
	}
}

func emit(r dossier.Report, exit int) {
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
	os.Exit(exit)
}
