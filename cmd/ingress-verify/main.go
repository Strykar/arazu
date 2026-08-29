// SPDX-License-Identifier: Apache-2.0

// Command ingress-verify is the gate on the boundary.
//
// It runs the transfer protocol's checks in order, fails closed on anything
// it cannot verify, and emits a machine-readable decision. A rejection
// consumes no content and does not advance the accepted-version state.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"arazu/pkg/auditlog"
	"arazu/pkg/contentstore"
	"arazu/pkg/manifest"
)

// requiredSigners is the two-person control threshold. Two independent
// keys must sign the manifest.
const requiredSigners = 2

type check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"`
}

type decision struct {
	Decision    string   `json:"decision"`
	Reason      string   `json:"reason,omitempty"`
	BundleID    string   `json:"bundle_id,omitempty"`
	Version     uint64   `json:"version,omitempty"`
	ContentRoot string   `json:"content_root,omitempty"`
	Signers     []string `json:"signers,omitempty"`
	Checks      []check  `json:"checks"`
}

type allowList []string

func (a *allowList) String() string     { return strings.Join(*a, ",") }
func (a *allowList) Set(v string) error { *a = append(*a, v); return nil }

type gate struct {
	bundle  string
	trusted string
	state   string
	logPath string
	allow   allowList
	d       decision
}

func main() {
	g := &gate{}
	flag.StringVar(&g.bundle, "bundle", "", "bundle directory to verify")
	flag.StringVar(&g.trusted, "trusted", "", "trusted public keys file")
	flag.StringVar(&g.state, "state", "", "directory holding the last-accepted version")
	flag.StringVar(&g.logPath, "log", "", "audit log path")
	flag.Var(&g.allow, "allow", "allowed path prefix, repeatable")
	flag.Parse()

	if g.bundle == "" || g.trusted == "" || g.state == "" || g.logPath == "" {
		g.emit("ERROR", "usage", 2)
	}
	if len(g.allow) == 0 {
		g.allow = allowList{"content/"}
	}

	m, root, err := g.verify()
	if err != nil {
		g.reject(err)
	}
	g.accept(m, root)
}

// verify runs the ordered checks. The first failure decides, and its
// sentinel error carries the reason the gate reports.
func (g *gate) verify() (manifest.Manifest, string, error) {
	canonical, err := os.ReadFile(filepath.Join(g.bundle, "manifest.json"))
	if err != nil {
		g.note("manifest-present", false, err.Error())
		return manifest.Manifest{}, "", fmt.Errorf("%w: %v", manifest.ErrNotCanonical, err)
	}
	g.note("manifest-present", true, "")

	m, err := manifest.Parse(canonical)
	if err != nil {
		g.note("manifest-canonical", false, err.Error())
		return m, "", err
	}
	g.note("manifest-canonical", true, "")
	g.d.BundleID, g.d.Version = m.BundleID, m.Version

	trusted, err := manifest.LoadPublicKeys(g.trusted)
	if err != nil {
		g.note("trusted-keys", false, err.Error())
		return m, "", fmt.Errorf("trusted-keys: %w", err)
	}
	g.note("trusted-keys", true, fmt.Sprintf("%d provisioned", len(trusted)))

	sigFile, err := os.ReadFile(filepath.Join(g.bundle, "manifest.sig"))
	if err != nil && !os.IsNotExist(err) {
		g.note("signatures", false, err.Error())
		return m, "", fmt.Errorf("%w: %v", manifest.ErrBadSignature, err)
	}

	signers, err := manifest.VerifySignatures(canonical, sigFile, trusted, requiredSigners)
	if err != nil {
		g.note("signatures", false, err.Error())
		return m, "", err
	}
	for _, s := range signers {
		g.d.Signers = append(g.d.Signers, string(s))
	}
	g.note("signatures", true, fmt.Sprintf("%d distinct trusted signers", len(signers)))

	last, err := g.lastAccepted(m.BundleID)
	if err != nil {
		g.note("version-rollback", false, err.Error())
		return m, "", err
	}
	if m.Version <= last {
		err := fmt.Errorf("version-rollback: version %d is not newer than the last accepted %d", m.Version, last)
		g.note("version-rollback", false, err.Error())
		return m, "", err
	}
	g.note("version-rollback", true, fmt.Sprintf("version %d follows %d", m.Version, last))

	if err := contentstore.VerifyAgainst(g.bundle, m, g.allow); err != nil {
		g.note("content", false, err.Error())
		return m, "", err
	}
	g.note("content", true, fmt.Sprintf("%d files", len(m.Files)))

	root := contentstore.ContentRoot(m.Files)
	g.note("content-root", true, root)
	return m, root, nil
}

func (g *gate) versionFile(bundleID string) string {
	safe := strings.ReplaceAll(bundleID, string(os.PathSeparator), "_")
	return filepath.Join(g.state, "last-accepted-"+safe)
}

func (g *gate) lastAccepted(bundleID string) (uint64, error) {
	b, err := os.ReadFile(g.versionFile(bundleID))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("version-rollback: unreadable state: %w", err)
	}
	return v, nil
}

func (g *gate) note(name string, ok bool, note string) {
	g.d.Checks = append(g.d.Checks, check{Name: name, OK: ok, Note: note})
}

// reasonOf maps an error to the reason string the acceptance table expects.
// Matching on sentinels rather than message text keeps the reported reason
// stable when the wording changes.
func reasonOf(err error) string {
	for _, s := range []error{
		contentstore.ErrHashMismatch,
		contentstore.ErrUnmanifestedFile,
		contentstore.ErrMissingFile,
		contentstore.ErrAllowlistViolation,
		contentstore.ErrUnsafePath,
		manifest.ErrUntrustedSigner,
		manifest.ErrInsufficientSignatures,
		manifest.ErrDuplicateSigner,
		manifest.ErrBadSignature,
		manifest.ErrNotCanonical,
	} {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	if strings.HasPrefix(err.Error(), "version-rollback") {
		return "version-rollback"
	}
	return "unverifiable"
}

func (g *gate) reject(err error) {
	reason := reasonOf(err)
	g.appendLog(auditlog.EvIngressReject,
		fmt.Sprintf("bundle=%s version=%d reason=%s detail=%s",
			g.d.BundleID, g.d.Version, reason, err.Error()))
	g.d.Reason = reason
	g.emit("REJECT", reason, 1)
}

func (g *gate) accept(m manifest.Manifest, root string) {
	if err := os.MkdirAll(g.state, 0o700); err != nil {
		g.emit("ERROR", err.Error(), 2)
	}
	if err := os.WriteFile(g.versionFile(m.BundleID),
		[]byte(strconv.FormatUint(m.Version, 10)+"\n"), 0o600); err != nil {
		g.emit("ERROR", err.Error(), 2)
	}
	g.d.ContentRoot = root
	g.appendLog(auditlog.EvIngressAccept,
		fmt.Sprintf("bundle=%s version=%d content_root=%s signers=%s",
			m.BundleID, m.Version, root, strings.Join(g.d.Signers, ",")))
	g.emit("ACCEPT", "", 0)
}

func (g *gate) appendLog(event, detail string) {
	if err := os.MkdirAll(filepath.Dir(g.logPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create log directory: %v\n", err)
		return
	}
	l, err := auditlog.Open(g.logPath)
	if err != nil {
		// A log that cannot be written is itself a failure to record, so say
		// so loudly rather than proceeding as if the event were recorded.
		// ERROR, not REJECT. The bundle may be perfectly good; we cannot say so
		// without a record. Counting this as a rejection class would make eleven
		// and erase the three-valued design.
		fmt.Fprintf(os.Stderr, "cannot open audit log: %v\n", err)
		g.emit("ERROR", "audit-log-unavailable", 2)
	}
	defer l.Close()
	if _, err := l.Append(event, detail); err != nil {
		fmt.Fprintf(os.Stderr, "cannot append to audit log: %v\n", err)
		g.emit("ERROR", "audit-log-unavailable", 2)
	}
}

func (g *gate) emit(dec, reason string, code int) {
	g.d.Decision = dec
	if reason != "" {
		g.d.Reason = reason
	}
	b, err := json.Marshal(g.d)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot render decision: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(b))

	fmt.Fprintf(os.Stderr, "%s", dec)
	if g.d.Reason != "" {
		fmt.Fprintf(os.Stderr, ": %s", g.d.Reason)
	}
	fmt.Fprintln(os.Stderr)
	for _, c := range g.d.Checks {
		status := "ok"
		if !c.OK {
			status = "FAIL"
		}
		fmt.Fprintf(os.Stderr, "  %-18s %-5s %s\n", c.Name, status, c.Note)
	}
	os.Exit(code)
}
