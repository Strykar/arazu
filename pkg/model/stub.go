// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// Stub is the deterministic backend every plumbing test runs against.
//
// It exists so that a test of the gate is a test of the gate. A real model
// would make the same test flaky and expensive, and worse, a stage that
// happened to work only because a capable model covered for a bug in the
// plumbing would look identical to one that was correct.
//
// It also keeps the transcript. The red-team stage claims the refuter never
// sees the generator's reasoning, and that claim is only checkable against
// what was actually sent.
type Stub struct {
	mu sync.Mutex

	// Scripted answers, keyed by request digest. Anything not scripted gets a
	// derived answer rather than an error, so a test only has to pin the
	// responses it actually cares about.
	scripted map[string]string

	// Refusals, keyed by request digest.
	refuse map[string]bool

	calls []Request
}

func NewStub() *Stub {
	return &Stub{scripted: map[string]string{}, refuse: map[string]bool{}}
}

func (s *Stub) Name() string { return "stub" }

// Digest identifies a request. Everything that could change an answer is in
// it, so a scripted response cannot be matched by a request that differs in a
// way the caller forgot about.
func Digest(r Request) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00%d\x00%v",
		r.Purpose, r.System, r.Prompt, r.MaxTokens, r.Seed, r.Temperature)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Script pins the answer to one exact request.
func (s *Stub) Script(r Request, answer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripted[Digest(r)] = answer
}

// Refuse makes one exact request come back as a refusal.
func (s *Stub) Refuse(r Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse[Digest(r)] = true
}

func (s *Stub) Complete(ctx context.Context, r Request) (Response, error) {
	if err := Validate(r); err != nil {
		return Response{}, err
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, r)

	d := Digest(r)
	if s.refuse[d] {
		return Response{}, fmt.Errorf("%w: %s", ErrRefused, r.Purpose)
	}

	text, ok := s.scripted[d]
	if !ok {
		text = "stub:" + d
	}
	return Response{
		Text: text,
		Usage: Usage{
			Purpose: r.Purpose,
			Backend: s.Name(),
			// Deterministic stand-ins. Real numbers come from a real backend;
			// these exist so the accounting plumbing is exercised, and they are
			// derived from the input so a test can assert they were recorded
			// rather than defaulted.
			InputTokens:  len(r.System) + len(r.Prompt),
			OutputTokens: len(text),
		},
	}, nil
}

// Calls returns the transcript in order.
func (s *Stub) Calls() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.calls...)
}

// CallsFor returns the transcript for one stage.
func (s *Stub) CallsFor(purpose string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, c := range s.calls {
		if c.Purpose == purpose {
			out = append(out, c)
		}
	}
	return out
}

// Reset clears the transcript but keeps the script, so a test can re-run a
// stage without re-pinning its answers.
func (s *Stub) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}
