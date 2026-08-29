// SPDX-License-Identifier: GPL-2.0
//
// Deny network egress for sockets living in one network namespace.
//
// The namespace inode is the predicate because it is the containment
// boundary itself. A workload cannot leave its netns without CAP_SYS_ADMIN
// and a namespace file descriptor, so the mark cannot be shed the way a
// cgroup membership can. A zero inode matches nothing, so a partial or
// misconfigured load denies nothing and cannot affect the host.
//
// Both connect and sendmsg are hooked. connect alone would miss
// connectionless UDP and raw sockets, which is the same shape of gap as
// covering socket creation but not accept.
// bpftool's BTF dump emits a few empty forward declarations, which trip
// -Wmissing-declarations. Scope the suppression to the generated header so
// -Werror stays strict for the code below.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET    2
#define AF_INET6  10
#define AF_PACKET 17
#define EPERM      1

// Set from userspace before attach. Zero means deny nothing.
const volatile __u32 contained_netns_ino = 0;

#define CTR_CONNECT_DENIED 0
#define CTR_SENDMSG_DENIED 1
#define CTR_CONNECT_SEEN   2
#define CTR_SENDMSG_SEEN   3
// The loopback carve-out is counted separately from a plain allow. A permitted
// AF_INET connect from inside the boundary is the one thing this program now
// lets through, so it must be visible as its own number rather than as the
// absence of a denial.
#define CTR_LOOPBACK_ALLOWED 4

// Kernel-side evidence that the hooks ran and what they decided. A userspace
// probe seeing a failed connect cannot tell whether the namespace or this
// program refused it; these counters can.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u64);
} egress_counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&egress_counters, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int in_contained_netns(struct socket *sock)
{
	struct sock *sk;
	struct net *net;
	unsigned short family;
	unsigned int ino;

	if (!contained_netns_ino)
		return 0;

	// Cache sk in a local. Two BPF_CORE_READ loads of the same field get
	// separate pointer ids and the verifier will not carry a null check on
	// the first one forward to the second.
	sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	// Only the families that carry traffic off the box. AF_UNIX and netlink
	// are left alone so the probe's own failures stay attributable to the
	// thing being tested.
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6 && family != AF_PACKET)
		return 0;

	net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
	if (!net)
		return 0;

	ino = BPF_CORE_READ(net, ns.inum);
	return ino == contained_netns_ino;
}

// Is this AF_INET destination on 127.0.0.0/8?
//
// Loopback INSIDE a netns is internal to that netns: there is no process
// outside the boundary at the other end, because the namespace has only lo up
// and no veth. Permitting it therefore creates no path out, which is what lets
// a model server live inside the boundary without a relay and without anything
// outside becoming reachable.
//
// AF_INET ONLY, DELIBERATELY. ::1 is not permitted. The serving stack binds
// 127.0.0.1 (ollama's OLLAMA_HOST defaults to 127.0.0.1:11434 and accepts an
// IP, not a unix socket), so v4 is sufficient today and a carve-out is easier
// to defend the smaller it is.
//
// The symptom if that changes: bind the model to ::1 and every request from
// inside the boundary fails as a refused connection with nothing in the logs
// explaining why, because this program denies AF_INET6 by family with no
// destination check at all. That is intended, and it is written here so the
// cause is findable from the code rather than from the decision's history.
static __always_inline int dst_is_loopback_v4(struct sockaddr *address)
{
	struct sockaddr_in *sin;
	unsigned short fam = 0;
	__be32 daddr = 0;

	if (!address)
		return 0;
	if (bpf_probe_read_kernel(&fam, sizeof(fam), &address->sa_family))
		return 0;
	if (fam != AF_INET)
		return 0;
	sin = (struct sockaddr_in *)address;
	if (bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin->sin_addr.s_addr))
		return 0;
	// 127.0.0.0/8. In network byte order the first octet is the low byte.
	return (daddr & 0xff) == 127;
}

// The connected peer, for a sendmsg carrying no explicit destination.
static __always_inline int peer_is_loopback_v4(struct socket *sock)
{
	struct sock *sk = BPF_CORE_READ(sock, sk);
	unsigned short family;
	__be32 daddr;

	if (!sk)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return 0;
	daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	return (daddr & 0xff) == 127;
}

SEC("lsm/socket_connect")
int BPF_PROG(arazu_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	// Respect a denial another LSM already made. Returning 0 here would
	// override it and turn this program into a way to permit what apparmor
	// or landlock refused.
	if (ret)
		return ret;

	bump(CTR_CONNECT_SEEN);

	if (in_contained_netns(sock)) {
		if (dst_is_loopback_v4(address)) {
			bump(CTR_LOOPBACK_ALLOWED);
			return 0;
		}
		bump(CTR_CONNECT_DENIED);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(arazu_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size, int ret)
{
	if (ret)
		return ret;

	bump(CTR_SENDMSG_SEEN);

	if (in_contained_netns(sock)) {
		// A connectionless send names its destination in msg_name. A send on a
		// connected socket does not, and that destination was already gated at
		// connect, so fall back to the peer the socket holds rather than
		// permitting a NULL name by default.
		struct sockaddr *dst = (struct sockaddr *)BPF_CORE_READ(msg, msg_name);

		if (dst ? dst_is_loopback_v4(dst) : peer_is_loopback_v4(sock)) {
			bump(CTR_LOOPBACK_ALLOWED);
			return 0;
		}
		bump(CTR_SENDMSG_DENIED);
		return -EPERM;
	}
	return 0;
}
