// SPDX-License-Identifier: Apache-2.0

package fido

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Store is the set of credentials provisioned on the high side, plus the
// highest signature counter seen for each. The counters are state, in the same
// sense as the last-accepted bundle version: they only mean anything if they
// persist across runs.
type Store struct {
	Policy      Policy                `json:"policy"`
	Credentials []Credential          `json:"credentials"`
	Counters    map[string]uint32     `json:"counters"`
	byID        map[string]Credential `json:"-"`
}

// LoadStore reads the provisioned credentials.
//
// A credential whose signer is blank is refused rather than defaulted. The
// signer field is what two-person control counts, so an unnamed credential
// would silently join whichever group the empty string happens to land in.
func LoadStore(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Counters == nil {
		s.Counters = map[string]uint32{}
	}
	s.byID = make(map[string]Credential, len(s.Credentials))
	for _, c := range s.Credentials {
		if c.ID == "" || c.Signer == "" {
			return nil, fmt.Errorf("%s: credential %q has no id or no signer", path, c.ID)
		}
		if _, dup := s.byID[c.ID]; dup {
			return nil, fmt.Errorf("%s: credential %s is provisioned twice", path, c.ID)
		}
		s.byID[c.ID] = c
	}
	if len(s.byID) == 0 {
		return nil, fmt.Errorf("%s: no credentials provisioned", path)
	}
	return &s, nil
}

func (s *Store) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// VerifyAll checks every assertion and returns the distinct signers.
//
// Distinctness is over the person named by the credential, not over the
// credential. One person holding two enrolled authenticators is still one
// person, and counting credentials would let them satisfy a two-signer
// threshold without anyone else being involved. That is the same failure as
// the same key signing twice, so it reports the same reason.
func (s *Store) VerifyAll(assertions []Assertion, canonical []byte, minDistinct int) ([]Result, error) {
	seen := map[string]bool{}
	var results []Result

	for i, a := range assertions {
		c, ok := s.byID[a.CredentialID]
		if !ok {
			return nil, fmt.Errorf("%w: credential %s is not provisioned on this side",
				ErrUnknownCredential, a.CredentialID)
		}
		res, err := Verify(a, c, s.Policy, s.Counters[a.CredentialID], canonical)
		if err != nil {
			return nil, fmt.Errorf("assertion %d: %w", i+1, err)
		}
		if seen[res.Signer] {
			return nil, fmt.Errorf("%w: %s signed the manifest more than once", ErrDuplicateSigner, res.Signer)
		}
		seen[res.Signer] = true
		results = append(results, res)
	}

	if len(seen) < minDistinct {
		return nil, fmt.Errorf("%w: %d distinct signers, need %d",
			ErrInsufficientSigners, len(seen), minDistinct)
	}
	return results, nil
}

// Commit advances the stored counters. It runs only after a decision to
// accept, so a refused bundle cannot burn a counter and lock out the real
// signer.
func (s *Store) Commit(results []Result, assertions []Assertion) {
	for i, r := range results {
		if r.CounterChecked && i < len(assertions) {
			s.Counters[assertions[i].CredentialID] = r.SignCount
		}
	}
}

// Signers lists the provisioned people, for reporting.
func (s *Store) Signers() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range s.Credentials {
		if !seen[c.Signer] {
			seen[c.Signer] = true
			out = append(out, c.Signer)
		}
	}
	sort.Strings(out)
	return out
}
