// SPDX-License-Identifier: Apache-2.0

// Package model is the one reasoning interface the gate talks to.
//
// Everything below this interface is byte-identical whether the backend is a
// frontier API in connected mode or local weights in the air gap. That is the
// air-gap thesis stated as a type: a weaker in-boundary model means fewer
// candidates and more regeneration, but the acceptance bar does not live in
// the model, so it does not move when the model gets weaker.
//
// Two things here are load-bearing rather than bookkeeping. Usage is recorded
// per call because cost-per-trusted-patch is a headline number and cannot be
// reconstructed afterwards. And every request is recorded by the stub, because
// the red-team stage has to prove the refuter never saw the generator's
// reasoning, and the only way to assert that is to look at what was actually
// sent.
package model

import (
	"context"
	"errors"
	"fmt"
)

// ErrRefused is what a backend returns when it declines to answer. It is not
// an error in the plumbing, and it must not be retried into a different
// answer, so it is a sentinel rather than a generic failure.
var ErrRefused = errors.New("model-refused")

// Request is one turn. There is no conversation history on purpose: every
// stage of the gate constructs its own prompt from scratch, so that what a
// stage saw is exactly what is in the request and nothing leaks in from a
// previous call.
type Request struct {
	// Purpose names the stage making the call. It is recorded with the usage
	// so per-stage cost is attributable, and it is what the isolation test
	// filters on.
	Purpose string

	System string
	Prompt string

	MaxTokens int

	// Seed and Temperature exist so a run can be repeated. The
	// non-determinism control generates K candidates and accepts only those
	// that pass R repeats, which is only meaningful if the knobs that make a
	// run repeatable are under our control rather than the backend's default.
	Seed        int64
	Temperature float64
}

// Usage is what a call cost. Reported per call rather than summed, so a
// report can separate what each stage spent.
type Usage struct {
	Purpose      string `json:"purpose"`
	Backend      string `json:"backend"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

type Response struct {
	Text  string `json:"text"`
	Usage Usage  `json:"usage"`
}

// Model is the whole surface. Keeping it to one method is what makes the
// backends interchangeable and the stub honest: there is nothing a real
// backend can do here that the stub cannot.
type Model interface {
	Name() string
	Complete(ctx context.Context, r Request) (Response, error)
}

// Validate refuses a request the gate should never have built.
//
// A zero temperature is the intended default rather than an unset field, so
// it is not an error, but an unnamed purpose is: an unattributed call breaks
// both the cost report and the isolation assertion, and neither failure would
// be visible at the time it happened.
func Validate(r Request) error {
	if r.Purpose == "" {
		return fmt.Errorf("request has no purpose, so its cost and isolation cannot be attributed")
	}
	if r.Prompt == "" {
		return fmt.Errorf("%s: request has no prompt", r.Purpose)
	}
	if r.MaxTokens <= 0 {
		return fmt.Errorf("%s: request has no token budget", r.Purpose)
	}
	if r.Temperature < 0 {
		return fmt.Errorf("%s: temperature %v is negative", r.Purpose, r.Temperature)
	}
	return nil
}
