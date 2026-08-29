# Hardware-backed manifest signing

## Why this exists

The spike's original two-person control is two ed25519 secret key files. Anyone who can read both
files can produce both signatures, so what it actually proves is that some process had access to
two files, not that two people agreed. `SCOPE.md` has always said so.

A FIDO2 assertion moves the secret into a device that will not export it and will not sign
without a physical act. Under a user-verification policy it will not sign without a PIN or a
fingerprint either. That is the difference between two-person control being a property of a
filesystem and being a property of two people.

## What a signature line looks like

    ed25519 <keyid> <base64 sig>
    fido2 <credential-id> <base64 authenticator-data> <base64 signature>

The authenticator signs over `authenticatorData || clientDataHash`, where

    clientDataHash = SHA256("arazu-manifest-sig-v1\n" || canonical-manifest-bytes)

The domain prefix separates a manifest signature from every other assertion the same token could
ever produce. Without it, an assertion the token made while logging in somewhere could be
presented here if the challenge happened to collide.

## The paths, and why each is its own reason code

A raw ed25519 signature has exactly one way to fail: it does not verify. An assertion carries a
relying-party binding, a presence flag, a verification flag, and a counter, and each of those is
a separate attack that checking the signature alone would wave through. They report separately
because an operator's response differs.

| Reason | What happened | Why it is not just "bad signature" |
|---|---|---|
| `fido-bad-signature` | The maths does not check out. | |
| `fido-rp-mismatch` | The assertion was made for a different service, or the credential is recorded under one. | The signature is genuine and the human really did touch the key. They were logging in somewhere else at the time. |
| `fido-no-user-presence` | The presence flag is clear. | Nobody touched anything. The assertion was computed, not performed. |
| `fido-no-user-verification` | Policy demands PIN or biometric; the flag is clear. | Presence proves the token was there. Verification proves who was holding it. |
| `fido-counter-regression` | The counter did not advance. | This is what a cloned authenticator looks like. Every credential on that token is now suspect, which is a different response from re-signing. |
| `fido-counter-unsupported` | The token does not count, and policy requires it. | A fact about the token, not a fault in this assertion. |
| `fido-unknown-credential` | The credential is not provisioned here. | |
| `fido-malformed-authdata` | Truncated, or carrying trailing bytes with no flag claiming them. | |
| `fido-algorithm-mismatch` | The assertion is presented under an algorithm the credential was not enrolled with. | Without the pin, the verifier would take its interpretation from attacker-supplied data. |
| `duplicate-signer` | One person signed twice. | See below. |

## Two-person control counts people, not credentials

This is the path a per-credential check misses. Two credentials, two different tokens, two genuine
touches, two valid assertions, two distinct credential IDs: everything a credential-counting check
looks at says this is two signers. It is one person with two keys, which is exactly as much
two-person control as one person with one key.

So `Credential.Signer` names the person, and distinctness is over that. `LoadStore` refuses a
credential with a blank signer rather than defaulting it, because an unnamed credential would
silently join whichever group the empty string lands in.

## Testing without hardware

Every rejection above needs an assertion a real authenticator would refuse to make. The hardware
can only produce correct assertions, so the hardware alone can test exactly one of these paths.
`pkg/fido`'s tests therefore build assertions directly from a software authenticator, which is
what makes the other paths reachable at all.

Mutation testing then confirms the tests have teeth. It found two checks in this package that
were doing nothing observable; both are written up in `docs/mutation-testing.md`.

## What this does NOT prove

- **One token is present on this host, so hardware two-person control is not demonstrated
  end to end.** The AuthenTrend ATKey.Pro on `/dev/hidraw5` reports `es256`, `eddsa`, resident
  keys, `clientPin` and `bioEnroll`. Two people needs two tokens. Everything below the signature
  line is exercised with a software authenticator, and that is a fixture, not a second signer.
- **Whether this specific token maintains a signature counter is not established.** Determining it
  requires making an assertion, which requires a physical touch, which cannot happen in an
  unattended run. The verifier handles both cases and reports which one applied, rather than
  letting an unchecked counter look like a checked one. No PIN operation was attempted against the
  token, deliberately: the device reports eight PIN retries and burning them on a guess is not a
  risk worth taking for a capability probe.
- **A verified assertion says a person was present and verified to the token. It does not say they
  read the patch.** The signature binds a human act to a specific manifest. It cannot bind it to
  comprehension, and no cryptography can. That is what the evidence dossier and the human review
  step are for.
- **The gate cannot tell that an unnamed software key and a named FIDO credential belong to the
  same human.** Software keys without a signer name fall back to their key ID as identity. That is
  fail-closed in the direction that matters, since it can only make identities more distinct and
  never fewer, but it means mixed-mode two-person control depends on the provisioning being
  honest.
- **Nothing here is an accreditation.** Same caveat as the rest of the spike.
