// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Counter indices, matching the defines in bpf/egress_deny.bpf.c.
const (
	ctrConnectDenied   = 0
	ctrSendmsgDenied   = 1
	ctrConnectSeen     = 2
	ctrSendmsgSeen     = 3
	ctrLoopbackAllowed = 4
)

// Counters is the kernel's own account of what the hooks did.
type Counters struct {
	ConnectDenied uint64 `json:"connect_denied"`
	SendmsgDenied uint64 `json:"sendmsg_denied"`
	ConnectSeen   uint64 `json:"connect_seen"`
	SendmsgSeen   uint64 `json:"sendmsg_seen"`
	// LoopbackAllowed is the one thing this program permits from inside the
	// boundary: an AF_INET destination on 127.0.0.0/8, which is internal to the
	// namespace. Counted separately from a plain allow so the carve-out is
	// visible as its own number rather than as the absence of a denial — a
	// permitted egress and a hook that never ran are otherwise the same zero.
	LoopbackAllowed uint64 `json:"loopback_allowed"`
}

// Deny is an attached egress denial.
type Deny struct {
	coll  *ebpf.Collection
	links []link.Link
}

// RequireBPFLSM reports whether the bpf LSM is in the active list.
//
// Checking this before attaching matters because attach succeeds either way.
// A kernel with the bpf LSM built in but absent from the runtime lsm= list
// loads the program, passes the verifier, returns a live link, and never
// fires the hook. That failure is indistinguishable from a working gate
// that permits everything.
func RequireBPFLSM() error {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("cannot read the active LSM list: %w", err)
	}
	for _, name := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if strings.TrimSpace(name) == "bpf" {
			return nil
		}
	}
	return fmt.Errorf("the bpf LSM is not active (list: %s); add bpf to the kernel lsm= cmdline",
		strings.TrimSpace(string(b)))
}

// AttachDeny loads the program, scopes it to one namespace inode, and
// attaches both hooks.
//
// Either both hooks attach or none do. A half-attached denial would cover
// connect but not sendmsg, which is exactly the gap the program exists to
// close.
func AttachDeny(objPath string, inode uint32) (*Deny, error) {
	if err := RequireBPFLSM(); err != nil {
		return nil, err
	}
	if inode == 0 {
		return nil, errors.New("refusing to attach with a zero namespace inode, which would deny nothing")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", objPath, err)
	}

	v, ok := spec.Variables["contained_netns_ino"]
	if !ok {
		return nil, errors.New("object has no contained_netns_ino variable")
	}
	if err := v.Set(inode); err != nil {
		return nil, fmt.Errorf("set contained_netns_ino: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected the program: %+v", ve)
		}
		return nil, err
	}

	d := &Deny{coll: coll}
	for _, name := range []string{"arazu_connect", "arazu_sendmsg"} {
		prog, ok := coll.Programs[name]
		if !ok {
			d.Close()
			return nil, fmt.Errorf("object has no program %s", name)
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			d.Close()
			return nil, fmt.Errorf("attach %s: %w", name, err)
		}
		d.links = append(d.links, l)
	}
	return d, nil
}

// Counters reads the kernel-side denial account.
func (d *Deny) Counters() (Counters, error) {
	var c Counters
	if d == nil || d.coll == nil {
		return c, nil
	}
	m, ok := d.coll.Maps["egress_counters"]
	if !ok {
		return c, errors.New("object has no egress_counters map")
	}
	for _, f := range []struct {
		idx uint32
		dst *uint64
	}{
		{ctrConnectDenied, &c.ConnectDenied},
		{ctrSendmsgDenied, &c.SendmsgDenied},
		{ctrConnectSeen, &c.ConnectSeen},
		{ctrSendmsgSeen, &c.SendmsgSeen},
		{ctrLoopbackAllowed, &c.LoopbackAllowed},
	} {
		if err := m.Lookup(f.idx, f.dst); err != nil {
			return c, fmt.Errorf("read counter %d: %w", f.idx, err)
		}
	}
	return c, nil
}

func (d *Deny) Close() error {
	if d == nil {
		return nil
	}
	for _, l := range d.links {
		l.Close()
	}
	d.links = nil
	if d.coll != nil {
		d.coll.Close()
		d.coll = nil
	}
	return nil
}
