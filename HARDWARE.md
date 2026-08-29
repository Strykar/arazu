# Hardware signers

Two-person control in the spike is cryptographic: two distinct trusted keys
must sign the manifest. Whether the two keys are held by two different people
is an organisational control, and `SCOPE.md` has to disclaim it.

A hardware signer narrows that gap. The private half cannot be copied off the
token, so a second signature needs the second token, physically. It does not
close the gap (one person can hold two tokens) but it changes what an attacker
has to steal from a file to an object.

## What is present on this host

| device | role | status |
|---|---|---|
| AuthenTrend ATKey.Pro, `/dev/hidraw5` | FIDO2 signer | eddsa and es256, touch sensor, biometric enrolment, 8 PIN retries |
| Nitrokey HSM, PKCS#11 slot 0 | PKCS#11 signer | token label `authnft`, PIN initialised, ECDSA-SHA256 in hardware |

The FIDO2 token advertises `eddsa`, which is what makes
`ssh-keygen -t ed25519-sk` usable rather than forcing the ecdsa variant.

The HSM already holds one EC P-256 key, label `authnft-ebpf-key`, id `0x10`,
usage `verify, derive`. It predates this spike and nothing here touches it.

The HSM needs `pcscd`:

```sh
sudo systemctl start pcscd.socket
pkcs11-tool --module /usr/lib/opensc-pkcs11.so --list-slots
```

## PIN handling

**No PIN is ever guessed by the tooling or by an assistant working on this
repository.**

The Nitrokey HSM locks the user PIN after 3 wrong attempts, needs the SO-PIN
to unlock, and is permanently lost after 3 wrong SO-PINs. The FIDO2 token has
8 retries before it needs a reset that destroys every credential on it. Both
counters are decremented by a wrong attempt and neither is worth spending on
a guess.

Enrolment and signing therefore run in the operator's own terminal, where the
PIN prompt reaches a TTY.

### The askpass guard does not work, and this is why it is written down

The obvious way to let automation attempt an enrolment without risking the
counter looks like this, and it is wrong:

```sh
# WRONG. Does not abort; submits an empty PIN.
SSH_ASKPASS=/bin/false SSH_ASKPASS_REQUIRE=force ssh-keygen -t ed25519-sk ...
```

`/bin/false` exits non-zero having printed nothing, and `ssh-keygen` treats
the empty output as the PIN and submits it. Tried on this host it produced
two `PIN incorrect` lines and then `Too many incorrect PINs`, exit 255, with
no key created.

The token's counter survived: it read 8 of 8 before and after, because an
empty string fails the 4-character minimum (`minpinlen: 4`) before it reaches
the token. That is luck about this token's configuration, not a property of
the guard. On a token with `minpinlen` at 0, or a different client, those
would have been two real attempts out of eight.

CTAP also enforces three consecutive wrong PINs per power cycle, separately
from the retry counter, so a loop like this can wedge a token into needing a
replug while the counter still reads full.

**So there is no safe automated attempt.** Enrolment with a PIN-protected
token is an interactive operation, and the honest engineering answer is to
hand it to the operator rather than to find a cleverer flag. An aborted
prompt costs nothing only if the prompt is genuinely aborted, and no
environment variable achieves that reliably.

## Enrolling a signer

```sh
ssh-keygen -t ed25519-sk -C arazu-signer-b -f ~/.ssh/arazu_signer_b
```

Add `-O resident` for a discoverable credential that survives losing the
private-key stub, and `-O verify-required` to force user verification (PIN or
fingerprint) at every signature rather than mere presence. Both need a PIN and
so must be run interactively.

`verify-required` is the stronger property for this use: presence proves
someone touched the token, verification proves it was the enrolled person.
Prefer it for a real deployment.

Provision the public key by appending its `.pub` line to the trusted-keys
file. `sk-ssh-ed25519@openssh.com ...` lines are recognised as hardware backed
and counted separately by `TrustStore.HardwareBackedCount`.

## Signing

```sh
ssh-keygen -Y sign -f ~/.ssh/arazu_signer_b -n arazu-manifest manifest.json
```

The namespace `arazu-manifest` is not decoration. A signature made in another
namespace does not verify as a manifest approval, so an SSH signature the
signer produced for some other purpose cannot be replayed as one. There is a
test for that.

## What is tested, and what a token adds

An `sk-ssh-ed25519` signature verifies through the same code as a software
`ssh-ed25519` one. So the verification path the boundary depends on is tested
end to end with a software SSH key, with no token present and nobody to touch
it, and the hardware tests cover only what cannot be faked:

- the token is present and enumerable
- an enrolled key reports itself as hardware backed, not as a software key
- a real token signature verifies, and does not verify over a tampered message

Run them with:

```sh
ARAZU_SK_KEY=~/.ssh/arazu_signer_b go test ./pkg/signer/ -run Hardware -v
```

They are opt-in because signing blocks on a physical touch, which a test
runner cannot supply. A suite that tried would hang rather than fail, and a
hang is worse than a failure.

## The property worth stating carefully

A key provisioned as `sk-ssh-ed25519` cannot be satisfied by a software
signature carrying the same key ID. Without that check, requiring a token
would buy nothing: anyone holding extracted or forged key material could
present it through the cheaper backend. `TestASoftwareSignatureCannotSatisfyAHardwareProvisionedKey`
pins it.

Equally, the same key material provisioned twice under two algorithms is
refused. Both lines name one signer, and accepting them would let one person
fill two provisioned slots and satisfy two-person control alone.
