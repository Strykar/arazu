// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func req(purpose, prompt string) Request {
	return Request{Purpose: purpose, Prompt: prompt, MaxTokens: 256}
}

// Same request in, same answer out, every time. The non-determinism control
// is meaningless if the stub the plumbing is tested against wanders.
func TestTheStubIsDeterministic(t *testing.T) {
	s := NewStub()
	ctx := context.Background()

	first, err := s.Complete(ctx, req("revert-attribute", "does reverting re-trigger?"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Complete(ctx, req("revert-attribute", "does reverting re-trigger?"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Text != second.Text {
		t.Fatalf("the stub gave two answers to one request: %q then %q", first.Text, second.Text)
	}

	other, err := s.Complete(ctx, req("revert-attribute", "a different question"))
	if err != nil {
		t.Fatal(err)
	}
	if other.Text == first.Text {
		t.Fatal("two different requests got the same answer, so the digest ignores the prompt")
	}
}

// Everything that could change an answer has to be in the digest. A knob that
// is not covered would let a scripted response match a request that differs in
// exactly the way the test was trying to vary.
func TestEveryRequestFieldChangesTheDigest(t *testing.T) {
	base := Request{
		Purpose: "red-team", System: "sys", Prompt: "p",
		MaxTokens: 100, Seed: 1, Temperature: 0,
	}
	vary := map[string]Request{
		"purpose":     {Purpose: "other", System: "sys", Prompt: "p", MaxTokens: 100, Seed: 1},
		"system":      {Purpose: "red-team", System: "other", Prompt: "p", MaxTokens: 100, Seed: 1},
		"prompt":      {Purpose: "red-team", System: "sys", Prompt: "other", MaxTokens: 100, Seed: 1},
		"max tokens":  {Purpose: "red-team", System: "sys", Prompt: "p", MaxTokens: 101, Seed: 1},
		"seed":        {Purpose: "red-team", System: "sys", Prompt: "p", MaxTokens: 100, Seed: 2},
		"temperature": {Purpose: "red-team", System: "sys", Prompt: "p", MaxTokens: 100, Seed: 1, Temperature: 0.7},
	}
	for name, r := range vary {
		if Digest(r) == Digest(base) {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}
}

func TestScriptedAndRefusedResponses(t *testing.T) {
	s := NewStub()
	ctx := context.Background()

	pinned := req("class-replay", "does the class still crash?")
	s.Script(pinned, "no")
	got, err := s.Complete(ctx, pinned)
	if err != nil || got.Text != "no" {
		t.Fatalf("scripted response not returned: %q %v", got.Text, err)
	}

	refused := req("class-replay", "something it will not answer")
	s.Refuse(refused)
	if _, err := s.Complete(ctx, refused); !errors.Is(err, ErrRefused) {
		t.Fatalf("refusal reported %v, want model-refused", err)
	}

	// A refusal is specific to the request, not sticky on the backend.
	if _, err := s.Complete(ctx, pinned); err != nil {
		t.Fatalf("a refusal leaked onto an unrelated request: %v", err)
	}
}

// The isolation property Gate M4 rests on, asserted against the transcript
// rather than against the code that builds the prompt.
//
// The refuter is meant to receive the source, the vulnerability, the claimed
// fix and the tests, and NOT the generator's reasoning. That is a robustness
// property of ours and it has to hold whatever model is behind the interface,
// so it is checked by looking at what was actually sent.
func TestTheTranscriptCanProveTheRefuterNeverSawTheGeneratorsReasoning(t *testing.T) {
	s := NewStub()
	ctx := context.Background()

	secret := "I guessed the bound was off by one and did not check the callers"
	s.Complete(ctx, Request{
		Purpose: "generate", Prompt: "propose a fix", MaxTokens: 100,
	})
	s.Complete(ctx, Request{
		Purpose: "generate", System: "you are the patch generator", Prompt: secret, MaxTokens: 100,
	})
	s.Complete(ctx, Request{
		Purpose: "red-team", System: "you are the refuter",
		Prompt: "here is the source, the vulnerability, the claimed fix and the tests", MaxTokens: 100,
	})

	for _, c := range s.CallsFor("red-team") {
		if strings.Contains(c.Prompt, secret) || strings.Contains(c.System, secret) {
			t.Fatal("the refuter was sent the generator's reasoning")
		}
	}
	if len(s.CallsFor("red-team")) != 1 || len(s.CallsFor("generate")) != 2 {
		t.Fatalf("transcript did not attribute calls by purpose: %d red-team, %d generate",
			len(s.CallsFor("red-team")), len(s.CallsFor("generate")))
	}

	// And the negative: a transcript that DOES carry the reasoning must be
	// detectable, otherwise the assertion above passes for any input and
	// proves nothing.
	s.Complete(ctx, Request{Purpose: "red-team", Prompt: "leaked: " + secret, MaxTokens: 100})
	leaked := false
	for _, c := range s.CallsFor("red-team") {
		if strings.Contains(c.Prompt, secret) {
			leaked = true
		}
	}
	if !leaked {
		t.Fatal("a transcript carrying the generator's reasoning was not detected")
	}
}

// Usage has to be recorded per call, because cost-per-trusted-patch cannot be
// reconstructed after the fact.
func TestUsageIsRecordedAndAttributed(t *testing.T) {
	s := NewStub()
	got, err := s.Complete(context.Background(), Request{
		Purpose: "sanitizer", System: "sys", Prompt: "prompt", MaxTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Usage.Purpose != "sanitizer" {
		t.Errorf("usage purpose = %q, want sanitizer", got.Usage.Purpose)
	}
	if got.Usage.Backend != "stub" {
		t.Errorf("usage backend = %q, want stub", got.Usage.Backend)
	}
	if got.Usage.InputTokens == 0 || got.Usage.OutputTokens == 0 {
		t.Errorf("usage not recorded: %+v", got.Usage)
	}
}

// A request the gate should never have built is refused at the interface, so
// the failure surfaces where it happened rather than as an unattributable
// entry in a cost report much later.
func TestMalformedRequestsAreRefused(t *testing.T) {
	s := NewStub()
	ctx := context.Background()

	if _, err := s.Complete(ctx, req("revert-attribute", "fine")); err != nil {
		t.Fatalf("a well-formed request was refused: %v", err)
	}

	bad := map[string]Request{
		"no purpose":    {Prompt: "p", MaxTokens: 10},
		"no prompt":     {Purpose: "x", MaxTokens: 10},
		"no budget":     {Purpose: "x", Prompt: "p"},
		"negative temp": {Purpose: "x", Prompt: "p", MaxTokens: 10, Temperature: -1},
	}
	for name, r := range bad {
		if _, err := s.Complete(ctx, r); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestACancelledContextStopsTheCall(t *testing.T) {
	s := NewStub()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Complete(ctx, req("generate", "anything")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context reported %v, want context.Canceled", err)
	}
}
