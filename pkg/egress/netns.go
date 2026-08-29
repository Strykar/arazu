// SPDX-License-Identifier: Apache-2.0

// Package egress creates the contained network namespace and attaches the
// kernel-enforced egress denial to it.
//
// The namespace is the primary control: with only loopback up and no veth,
// there is no path off the box at all. The BPF program is defence in depth,
// and it exists mostly so the two layers can be told apart at run time.
package egress

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Netns is a named network namespace.
type Netns struct {
	Name  string
	Inode uint32

	// keep suppresses deletion in Close, for a namespace shared across runs.
	keep bool
}

func run(argv ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %w: %s", argv, err, stderr.String())
	}
	return nil
}

// netnsInodeOfPath returns the namespace inode behind a nsfs path.
//
// The nsfs inode number is what struct net's ns.inum holds, which is what
// the BPF program compares against.
func netnsInodeOfPath(path string) (uint32, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint32(st.Ino), nil
}

// CreateNetns creates a named network namespace with only loopback up.
//
// A named namespace is used rather than unshare so the inode is readable
// from its bind mount before any workload starts. Attaching the deny
// program to a known inode first is what removes the window in which the
// workload would run uncontained.
//
// No veth pair is created, on purpose. With no interface but lo there is no
// route out, and "no path exists" is a stronger claim than "a path exists
// and something blocks it".
// OpenOrCreate returns the named namespace, creating it only if it is absent,
// and does NOT delete it on Close.
//
// This exists so a model server can live inside the boundary across many
// analysis runs. `ip netns add` makes a filesystem-backed namespace at
// /var/run/netns/<name> that outlives the process that created it, and
// netnsInodeOfPath reads the inode from that path — so a process joining later
// gets the SAME inode the BPF policy is keyed on. That identity is the whole
// mechanism: without it the model would sit in a different namespace and the
// policy would not apply to it.
//
// The caller is responsible for removing a persistent namespace. CleanupStale
// still does it by name.
func OpenOrCreate(name string) (*Netns, error) {
	path := filepath.Join("/var/run/netns", name)
	if _, err := os.Stat(path); err == nil {
		ino, err := netnsInodeOfPath(path)
		if err != nil {
			return nil, err
		}
		return &Netns{Name: name, Inode: ino, keep: true}, nil
	}
	ns, err := CreateNetns(name)
	if err != nil {
		return nil, err
	}
	ns.keep = true
	return ns, nil
}

func CreateNetns(name string) (*Netns, error) {
	if err := run("ip", "netns", "add", name); err != nil {
		return nil, err
	}
	if err := run("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"); err != nil {
		_ = run("ip", "netns", "del", name)
		return nil, err
	}

	ino, err := netnsInodeOfPath(filepath.Join("/var/run/netns", name))
	if err != nil {
		_ = run("ip", "netns", "del", name)
		return nil, err
	}
	return &Netns{Name: name, Inode: ino}, nil
}

// Exec runs a command inside the namespace.
func (n *Netns) Exec(ctx context.Context, argv []string) (stdout, stderr []byte, code int, err error) {
	full := append([]string{"ip", "netns", "exec", n.Name}, argv...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)

	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	code = cmd.ProcessState.ExitCode()

	// A non-zero exit is information here, not a failure to report. The
	// probe is expected to fail inside containment.
	if _, ok := err.(*exec.ExitError); ok {
		err = nil
	}
	return out.Bytes(), errb.Bytes(), code, err
}

// HostNetnsInode returns the inode of the host network namespace, for tests
// that need to prove the contained namespace is a different one.
func HostNetnsInode() (uint32, error) {
	return netnsInodeOfPath("/proc/1/ns/net")
}

func (n *Netns) Close() error {
	if n == nil || n.Name == "" {
		return nil
	}
	if n.keep {
		// A persistent namespace outlives the run that used it. Deleting it
		// here would take the model server down with it and, worse, the next
		// run would get a DIFFERENT inode — so the policy would be attached to
		// one namespace and the workload would be in another, which looks
		// exactly like containment working.
		n.Name = ""
		return nil
	}
	err := run("ip", "netns", "del", n.Name)
	n.Name = ""
	return err
}

// CleanupStale removes a leftover namespace of the given name, so a crashed
// run does not block the next one.
func CleanupStale(name string) {
	if _, err := os.Stat(filepath.Join("/var/run/netns", name)); err == nil {
		_ = run("ip", "netns", "del", name)
	}
}
