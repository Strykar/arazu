#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Attempt to reach the network and report exactly how each attempt failed.
#
# The errno is the point. A namespace with no route gives ENETUNREACH; the
# bpf lsm hook gives EPERM. Recording which one occurred is what lets the
# two containment layers be told apart, so neither gets credit for the
# other's work.
#
# Probes come in three classes:
#   REACH   attempts to actually reach something off this box. These must
#           succeed on the host and fail under containment.
#   LOCAL   exercises a kernel send path that stays inside the namespace.
#           Succeeding is not egress, so it is never counted as a leak. Its
#           value is attribution: the namespace cannot stop a raw send onto
#           its own loopback, so a denial here can only have come from the
#           bpf hook.
#   CONFIG  attempts to reconfigure the namespace. Inside a namespace as
#           root some of these genuinely succeed, and calling them failures
#           would be false. They are recorded truthfully, and a REACH probe
#           is repeated afterwards to show that a successful configuration
#           change still yields no egress.
#
# Emits one JSON object per line on stdout.
set -uo pipefail

TARGET_IP="${ARAZU_PROBE_IP:-1.1.1.1}"
TARGET_PORT="${ARAZU_PROBE_PORT:-443}"

emit() {
  printf '{"name":"%s","class":"%s","reached":%s,"errno":"%s","detail":"%s"}\n' \
    "$1" "$2" "$3" "$4" "$5"
}

# py runs a probe body and prints either "OK" or the errno name.
py() {
  timeout 10 python3 -c "$1" "${2:-$TARGET_IP}" "${3:-$TARGET_PORT}" 2>&1 | tail -n 1
}

probe_tcp() {
  local name="${1:-tcp-connect}"
  local ip="${2:-$TARGET_IP}"
  local port="${3:-$TARGET_PORT}"
  local cls="${4:-REACH}"
  local r
  r=$(py '
import socket, sys, errno
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect((ip, port))
    print("OK")
except OSError as e:
    print(errno.errorcode.get(e.errno, "E?%s" % e.errno))
except Exception as e:
    print(type(e).__name__)
' "$ip" "$port")
  if [ "$r" = "OK" ]; then
    emit "$name" "$cls" true NONE "connected to $ip:$port"
  elif [ "$r" = "ECONNREFUSED" ] && { [ "$cls" = PERMITTED ] || [ "$cls" = LOCAL ]; }; then
    # Permitted by policy, refused by the kernel for want of a listener. For the
    # loopback arm that is the PASSING case, and the two outcomes are genuinely
    # distinguishable: EPERM is the LSM refusing, ECONNREFUSED is the LSM
    # allowing and the kernel finding nothing bound. The loopback_allowed
    # counter corroborates it kernel-side.
    emit "$name" "$cls" true NONE "reached $ip:$port, no listener (policy permitted)"
  else
    emit "$name" "$cls" false "$r" "connect to $ip:$port refused with $r"
  fi
}

probe_udp_dns() {
  local r
  r=$(py '
import socket, sys, errno
ip = sys.argv[1]
q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(q, (ip, 53))
    s.recvfrom(512)
    print("OK")
except OSError as e:
    print(errno.errorcode.get(e.errno, "E?%s" % e.errno))
except Exception as e:
    print(type(e).__name__)
')
  if [ "$r" = "OK" ]; then
    emit dns-udp REACH true NONE "resolved via $TARGET_IP:53"
  else
    emit dns-udp REACH false "$r" "udp send or receive to $TARGET_IP:53 failed with $r"
  fi
}

probe_dns_resolver() {
  local r resolver cls
  # This is the only probe whose destination comes from the host rather than
  # from this script. Every other one names its target, so its verdict
  # attributes to a known cause; this one inherits /etc/resolv.conf.
  #
  # Under a policy that denies AF_INET by family the destination is irrelevant
  # and the row attributes cleanly to the egress hook. Under a loopback
  # carve-out it decides the verdict: a query to a 127.x resolver is permitted
  # by policy and then fails because nothing is listening inside the namespace.
  # Same "refused" outcome, different cause, and nothing in the row would say
  # so. So record which resolver answered, and demote the row to LOCAL when it
  # cannot attribute, because a LOCAL probe is already defined as one whose
  # success proves nothing was reached.
  resolver=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
  resolver="${resolver:-unset}"
  # COVERAGE, not REACH. This row returns EAI under netns-only AND under
  # containment, so it has never separated the two layers — a pre-existing
  # weakness the loopback carve-out only made visible. getaddrinfo resolves
  # through the ambient config, so it cannot be given a discriminating
  # destination without editing the host's resolv.conf, and dns-udp already
  # covers the discriminating DNS case against a literal target. Kept because
  # it exercises the libc resolver path, which raw UDP does not; excluded from
  # the containment verdict because it cannot attribute.
  # ALWAYS COVERAGE. There used to be a demotion to LOCAL for a loopback
  # resolver, on the reasoning that "a LOCAL probe is already defined as one
  # whose success proves nothing was reached". That definition was true when the
  # demotion was written on 2026-08-10 and stopped being true on 2026-08-11,
  # when the loopback carve-out gave LOCAL the opposite meaning: a LOCAL probe
  # must be DENIED, because that denial is the one the namespace cannot produce
  # and is what attributes containment to the bpf hook. contained-run therefore
  # reads a LOCAL probe that reached as a leak.
  #
  # So on any machine whose resolver is 127.x — anything running
  # systemd-resolved — this row was classed LOCAL, permitted by the carve-out,
  # reached, and failed the whole containment run. The development box resolves
  # via a non-loopback address, so the demotion never fired here; the first
  # machine to run it was the bootable image, and it failed there.
  #
  # COVERAGE is the honest class either way: this probe resolves through ambient
  # configuration rather than a destination we choose, so it cannot separate the
  # namespace from the bpf hook no matter what the resolver is. dns-udp already
  # covers DNS against a literal target, which is the row that attributes.
  cls=COVERAGE
  r=$(py '
import socket, errno
try:
    socket.setdefaulttimeout(5)
    socket.getaddrinfo("example.com", 443)
    print("OK")
except OSError as e:
    print(errno.errorcode.get(e.errno, "EAI"))
except Exception as e:
    print(type(e).__name__)
')
  if [ "$r" = "OK" ]; then
    emit dns-resolve "$cls" true NONE "system resolver $resolver returned an address"
  else
    emit dns-resolve "$cls" false "$r" "system resolver $resolver failed with $r"
  fi
}

probe_icmp() {
  local r
  r=$(py '
import socket, sys, errno, struct
ip = sys.argv[1]
def cksum(b):
    if len(b) % 2: b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff
hdr = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
pkt = struct.pack("!BBHHH", 8, 0, cksum(hdr + b"arazu"), 1, 1) + b"arazu"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(5)
    s.sendto(pkt, (ip, 0))
    s.recvfrom(1024)
    print("OK")
except OSError as e:
    print(errno.errorcode.get(e.errno, "E?%s" % e.errno))
except Exception as e:
    print(type(e).__name__)
')
  if [ "$r" = "OK" ]; then
    emit icmp-echo REACH true NONE "icmp echo reply from $TARGET_IP"
  else
    emit icmp-echo REACH false "$r" "raw icmp to $TARGET_IP failed with $r"
  fi
}

# A raw send onto the namespace's own loopback is not egress: the frame
# reaches nothing. It is classified LOCAL because the namespace cannot
# refuse it, so a denial here is attributable to the bpf hook alone.
probe_raw_packet_local() {
  local r
  r=$(py '
import socket, errno
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.settimeout(5)
    s.bind(("lo", 0))
    s.send(b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00" + b"arazu" * 8)
    print("OK")
except OSError as e:
    print(errno.errorcode.get(e.errno, "E?%s" % e.errno))
except Exception as e:
    print(type(e).__name__)
')
  if [ "$r" = "OK" ]; then
    emit raw-packet-loopback LOCAL true NONE "af_packet send on lo accepted, which reaches nothing"
  else
    emit raw-packet-loopback LOCAL false "$r" "af_packet send on lo refused with $r"
  fi
}

# The off-box version. It needs an interface that leads somewhere, and a
# namespace holding only lo has none, which is itself the result.
probe_raw_packet_offbox() {
  local r
  r=$(py '
import socket, errno, os
def pick():
    for name in sorted(os.listdir("/sys/class/net")):
        if name == "lo":
            continue
        try:
            if open("/sys/class/net/%s/operstate" % name).read().strip() in ("up", "unknown"):
                return name
        except OSError:
            continue
    return None
nic = pick()
if nic is None:
    print("ENODEV")
else:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        s.settimeout(5)
        s.bind((nic, 0))
        print("OK")
    except OSError as e:
        print(errno.errorcode.get(e.errno, "E?%s" % e.errno))
    except Exception as e:
        print(type(e).__name__)
')
  if [ "$r" = "OK" ]; then
    emit raw-packet-offbox REACH true NONE "bound a raw socket to an interface that carries traffic off the box"
  elif [ "$r" = "ENODEV" ]; then
    emit raw-packet-offbox REACH false ENODEV "no non-loopback interface exists in this namespace"
  else
    emit raw-packet-offbox REACH false "$r" "raw bind to a non-loopback interface refused with $r"
  fi
}

probe_route_add() {
  local out
  if out=$(ip route add default via 10.255.255.1 2>&1); then
    emit route-add CONFIG true NONE "default route added, which grants no path by itself"
  else
    emit route-add CONFIG false EPERM_OR_UNREACH "${out//\"/}"
  fi
}

probe_link_add() {
  local out
  if out=$(ip link add arazu-esc type dummy 2>&1); then
    ip link set arazu-esc up >/dev/null 2>&1
    emit link-add CONFIG true NONE "dummy interface created inside the namespace"
  else
    emit link-add CONFIG false EPERM "${out//\"/}"
  fi
}

probe_tcp
# R1.1(d): the model server lives INSIDE the boundary, reached over loopback.
# LOCAL, not REACH — loopback inside a netns is internal to it, so success
# proves nothing was reached. This is the only row where success is the correct
# result, which makes it the one a broken probe would pass by accident. It runs
# through the SAME body as the off-box arm above with only the destination
# changed, so the two verdicts attribute to the destination and not to two
# code paths that happen to disagree.
probe_tcp model-loopback 127.0.0.1 11434 PERMITTED
probe_udp_dns
probe_dns_resolver
probe_icmp
probe_raw_packet_offbox
probe_raw_packet_local

# The control run happens on the host, where adding routes and interfaces
# would change the operator's own machine. Reaching the network is all the
# control run needs to show, so the configuration probes are skipped there.
if [ "${ARAZU_PROBE_SKIP_CONFIG:-0}" != "1" ]; then
  probe_route_add
  probe_link_add
  # Repeat the reach probe after the configuration attempts. Even where the
  # namespace let us add a route and an interface, there is still no path out.
  probe_tcp tcp-connect-after-config
fi
