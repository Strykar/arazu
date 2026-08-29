# Contributing

## Sign your commits

No CLA. Contributions are taken under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
Agree to it by signing off:

    git commit -s

Set `git config user.name` and `user.email` to a real name and working address.

## Licence

Apache-2.0. New files carry `SPDX-License-Identifier: Apache-2.0` as the first
line, after the shebang in a script.

`bpf/egress_deny.bpf.c` is GPL-2.0 and stays that way: it declares
`char LICENSE[] SEC("license") = "GPL"` to the kernel, and the verifier refuses
a non-GPL program the helpers this LSM uses. See NOTICE.

## Before a pull request

    make build          # gofmt and go vet clean
    make test           # unprivileged suite
    make test-root      # netns, LSM, TPM. needs root and a TPM 2.0
    make mutation-test  # must report 0 uncaught
    shellcheck $(git ls-files '*.sh' | grep -v ^vendor/)

The root targets touch PCR 23 and create namespaces. They do not work in a
container.

## What a change carries

**A new security-relevant check needs a mutation entry.** Break the check
deliberately, confirm a test fails, and record it. Add it to `testdata/mutations.json`, or `mutations-root.json` if it needs root,
naming the test predicted to catch it. A check with no mutation record is not
known to be tested.

**A runner must exit non-zero when it did not run.** Three harnesses here
reported success while testing nothing: missing `vendor/`, then an inherited
build environment, then a stale BPF object. All three looked green.

**Skip on absent capability, do not fail.** Use `hostcap.HasSysAdmin` and
`hostcap.HasTPM` with `t.Skip` and a reason. A missing TPM is a property of the
machine, not a wrong prediction.

**File predictions before results.** See `corpus/reports/*-predictions.yaml`.

**Say what you could not establish.** Verdicts carry a `notProven` list. A new
stage adds to it.

## Commit messages

Imperative mood. Say what changed and why, not what the diff shows. Check any
falsifiable claim before writing it.
