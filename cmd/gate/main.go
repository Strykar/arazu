// SPDX-License-Identifier: Apache-2.0

// Command gate decides whether a candidate patch has earned credit for fixing
// a vulnerability in a corpus case.
//
// Exit codes are three-valued. ACCEPT is 0, REJECT is 1 and is a correct
// outcome rather than an error. Exit 2 means the gate could not decide, and a
// check that failed to run has established nothing.
//
// Fail-closed is not the same as fine. Exit 2 is a defect report about the gate
// or the case; treating it as the system working is how a gradeable case sits
// broken while every verdict it produces is correct.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

func main() {
	casePath := flag.String("case", "", "path to a corpus case file")
	repoRoot := flag.String("repo", ".", "this repository, where synthesised candidates live")
	candID := flag.String("candidate", "", "id of the candidate patch to verify")
	root := flag.String("root", "", "directory the case's paths are relative to")
	stage := flag.String("stage", "m0",
		"which gate to run: m0 patch-effect, m1 revert-to-attribute, "+
			"m2 falsifying-class replay, m3 sanitizer-gated reachability")
	shim := flag.String("shim", "/var/lib/arazu-corpus/shim", "directory holding the docker shim")
	// M2 only. Class replay needs BOTH checkouts, the source and the oss-fuzz
	// tooling, which stage-corpus.sh clones side by side under this root.
	corpusRoot := flag.String("corpus", "/var/lib/arazu-corpus",
		"root stage-corpus.sh cloned into; m2 resolves both checkouts under it")
	workDir := flag.String("work", "", "where m2 writes generated class members (default: a temp dir)")
	// Each member costs a container start on every replay, so this bounds the
	// run's dominant cost. Default 0 means the stage's own default.
	members := flag.Int("members", 0, "m2: how many class members to generate (0 = stage default)")
	bundle := flag.String("bundle", "",
		"bundle directory to write decision.json into, BEFORE it is measured")
	logPath := flag.String("log", "", "audit log to record the verdict in")
	flag.Parse()

	if *casePath == "" || *candID == "" {
		fmt.Fprintln(os.Stderr, "usage: gate -case <file> -candidate <id> [-root <dir>]")
		os.Exit(2)
	}

	outs := outputs{bundle: *bundle, log: *logPath}

	// An unrecognised stage must REFUSE, not fall through. Before this, any
	// name the switch did not list ran patch-effect and reported ACCEPT, so a
	// typo bought a passing verdict from a weaker stage than the one asked for
	// and nothing in the output said which stage had run.
	switch *stage {
	case "m1", "m2", "m3":
		runSweep(*stage, *casePath, *candID, *root, *repoRoot, *shim,
			*corpusRoot, *workDir, *members, outs)
		return
	case "m0":
		// falls through to the patch-effect path below
	default:
		fmt.Fprintf(os.Stderr, "unknown stage %q: known stages are m0, m1, m2, m3\n", *stage)
		os.Exit(2)
	}

	c, err := corpus.Load(*casePath)
	if err != nil {
		undecided(err)
	}

	var cand corpus.Candidate
	found := false
	for _, x := range c.Candidates {
		if x.ID == *candID {
			cand, found = x, true
			break
		}
	}
	if !found {
		undecided(fmt.Errorf("case %s has no candidate %q", c.ID, *candID))
	}

	// The files this verdict is about, so the dossier carries them rather than
	// pointing at them. Resolved through the case's own root machinery, which is
	// the only thing that knows whether a path is relative to the repository or
	// to the challenge checkout.
	outs.sources = map[string]string{
		"case":            *casePath,
		"candidate-patch": c.CandidatePatchPath(cand, *root, *repoRoot),
		"pov":             c.InputPath(*root, *repoRoot),
	}

	// What M0 cannot establish, written where the verdict is read rather than
	// left to the reader to infer from which stages are present.
	notProven := []string{
		"only the patch-effect stage has run; revert-attribution, falsifying-class replay, sanitizer-gated reachability, isolated red-team and the non-determinism control are not implemented yet",
		"a passing patch-effect stage means the patch changes lines, not that the change is correct",
	}

	d, err := gate.Verify(context.Background(), gate.Input{Case: c, Candidate: cand, Root: *root, RepoRoot: *repoRoot},
		[]gate.Stage{gate.EffectStage{}}, notProven)
	if err != nil {
		undecided(err)
	}

	emitDecision(d, outs)
}

// emitDecision prints the decision and exits with the verdict's code.
// outputs are where a verdict is made durable. Empty means stdout only, which
// is what every existing caller gets.
type outputs struct {
	bundle string
	log    string
	// sources maps an artifact role to a path on this machine. The dossier
	// copies them in, so a reader who was not here can re-derive from the bytes
	// rather than from a path that resolved only for the process that wrote it.
	sources map[string]string
}

func emitDecision(d gate.Decision, o outputs) {
	// The dossier is written FIRST, because Emit returns the decision as
	// recorded: it carries the artifact list, and printing the pre-emit copy
	// would put a different document on stdout than in the dossier.
	written, p, err := writeDecision(o.bundle, d, o.sources)
	if err == nil {
		d = written
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(b))

	// A verdict that is not recorded did not happen, as far as everything
	// downstream of here can tell.
	if err != nil {
		fmt.Fprintf(os.Stderr, "the verdict was not written to the bundle: %v\n", err)
		os.Exit(2)
	} else if p != "" {
		fmt.Fprintf(os.Stderr, "dossier written to %s (measure it after this, not before)\n", p)
	}
	if err := logDecision(o.log, d); err != nil {
		fmt.Fprintf(os.Stderr, "the verdict was not logged: %v\n", err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "%s %s/%s", d.Verdict, d.CaseID, d.CandidateID)
	if d.Reason != "" {
		fmt.Fprintf(os.Stderr, ": %s", d.Reason)
	}
	fmt.Fprintln(os.Stderr)

	switch d.Verdict {
	case gate.VerdictReject:
		os.Exit(1)
	case gate.VerdictError:
		// Nothing was demonstrated, so no verdict was reached on the patch.
		// Same exit code as a gate that could not run its own check.
		os.Exit(2)
	}
}

// undecided reports that no verdict was reached. Deliberately not a REJECT.
func undecided(err error) {
	b, _ := json.MarshalIndent(map[string]string{
		"verdict": "UNDECIDED",
		"error":   err.Error(),
	}, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintln(os.Stderr, "UNDECIDED: "+err.Error())
	os.Exit(2)
}
