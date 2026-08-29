// SPDX-License-Identifier: Apache-2.0

// Package model is the one reasoning interface the gate talks to.
//
// The interface is identical whether the backend is a frontier API or local
// weights in the air gap: the acceptance bar does not live in the model, so a
// weaker model costs candidates, not standards. Usage is per call because
// cost-per-trusted-patch cannot be reconstructed afterwards; the stub records
// every request because what was sent is the only evidence the refuter never
// saw the generator's reasoning.
package model

import (
	"context"
	"errors"
	"fmt"
)

// ErrRefused is a backend declining to answer. A sentinel rather than a
// generic failure, because it must not be retried into a different answer.
var ErrRefused = errors.New("model-refused")

// Request is one turn. No conversation history: every stage builds its own
// prompt, so what a stage saw is exactly what is in the request.
type Request struct {
	// Purpose names the calling stage. Cost and the isolation test key on it.
	Purpose string

	System string
	Prompt string

	MaxTokens int

	// Seed and Temperature make a run repeatable, which the K-candidates,
	// R-repeats non-determinism control depends on.
	Seed        int64
	Temperature float64
}

// Usage is what one call cost. Per call, not summed, so spend splits by stage.
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

// Model is the whole surface. One method keeps the backends interchangeable
// and leaves the stub nothing a real backend can do that it cannot.
type Model interface {
	Name() string
	Complete(ctx context.Context, r Request) (Response, error)
}

// Validate refuses a request the gate should never have built. An unnamed
// purpose is fatal: an unattributed call breaks the cost report and the
// isolation assertion, and neither failure shows at the time. Zero temperature
// is the intended default, not an unset field.
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
