// SPDX-License-Identifier: Apache-2.0

// Package egress creates the contained network namespace and attaches the
// kernel-enforced egress denial to it. The namespace is the primary control:
// only lo, no veth, so no path off the box exists. The BPF program is defence
// in depth.
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

// netnsInodeOfPath returns the namespace inode behind a nsfs path. This is
// struct net's ns.inum, the value the BPF program compares against.
func netnsInodeOfPath(path string) (uint32, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint32(st.Ino), nil
}

// OpenOrCreate returns the named namespace, creating it only if absent, and
// does not delete it on Close. The namespace at /var/run/netns/<name> outlives
// the process that made it, so a model server joining later lands on the same
// inode the BPF policy is keyed on, not in one the policy never covers. The
// caller removes it; CleanupStale still does it by name.
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

// CreateNetns creates a named network namespace with only loopback up. Named
// rather than unshare, so the inode is readable before any workload starts and
// the deny program attaches first. No veth: with only lo there is no route out
// to block.
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

	// A non-zero exit is expected inside containment, so it is not an error.
	if _, ok := err.(*exec.ExitError); ok {
		err = nil
	}
	return out.Bytes(), errb.Bytes(), code, err
}

// HostNetnsInode returns the inode of the host network namespace.
func HostNetnsInode() (uint32, error) {
	return netnsInodeOfPath("/proc/1/ns/net")
}

func (n *Netns) Close() error {
	if n == nil || n.Name == "" {
		return nil
	}
	if n.keep {
		// Deleting a shared namespace takes the model server down and gives the
		// next run a different inode, which still looks contained.
		n.Name = ""
		return nil
	}
	err := run("ip", "netns", "del", n.Name)
	n.Name = ""
	return err
}

// CleanupStale removes a leftover namespace so a crashed run does not block
// the next one.
func CleanupStale(name string) {
	if _, err := os.Stat(filepath.Join("/var/run/netns", name)); err == nil {
		_ = run("ip", "netns", "del", name)
	}
}
