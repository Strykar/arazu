// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"arazu/pkg/auditlog"
	"arazu/pkg/dossier"
	"arazu/pkg/gate"
)

// writeDecision puts the verdict in the bundle so the seal can bind it.
//
// ORDER IS THE WHOLE RISK. ContentRoot hashes whatever MeasureBundle scanned, so
// a decision written BEFORE measurement is covered for free. Written after, it
// sits outside the root and every check still passes. Nothing in the type system
// enforces this.
func writeDecision(bundleDir string, d gate.Decision, sources map[string]string) (gate.Decision, string, error) {
	if bundleDir == "" {
		return d, "", nil
	}
	if fi, err := os.Stat(bundleDir); err != nil || !fi.IsDir() {
		return d, "", fmt.Errorf("bundle directory %s does not exist, so the decision "+
			"would not be under any content root", bundleDir)
	}
	written, err := dossier.Emit(bundleDir, d, sources)
	if err != nil {
		return d, "", err
	}
	return written, filepath.Join(bundleDir, dossier.DecisionFile), nil
}

// logDecision records that a verdict was reached, with its reason.
//
// A missing log is not silently tolerated the way seal-tool tolerates it: the
// gate is the thing whose verdict the log exists to record, so failing to write
// it is reported. The caller decides whether that is fatal.
func logDecision(logPath string, d gate.Decision) error {
	if logPath == "" {
		return nil
	}
	ev := auditlog.EvGateAccept
	switch d.Verdict {
	case gate.VerdictReject:
		ev = auditlog.EvGateReject
	case gate.VerdictError:
		ev = auditlog.EvGateError
	}
	detail := fmt.Sprintf("%s/%s", d.CaseID, d.CandidateID)
	if d.Reason != "" {
		detail += ": " + d.Reason
	}

	l, err := auditlog.Open(logPath)
	if err != nil {
		return fmt.Errorf("cannot open audit log %s: %w", logPath, err)
	}
	defer l.Close()
	if _, err := l.Append(ev, detail); err != nil {
		return fmt.Errorf("cannot append the verdict to %s: %w", logPath, err)
	}
	return nil
}
