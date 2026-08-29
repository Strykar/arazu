// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os/exec"
)

// runHost runs the probe on the host with no containment at all. This is the
// control: if it does not reach the network, nothing the contained runs show
// is meaningful.
func runHost(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/env", "bash", script)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb

	err := cmd.Run()
	if _, ok := err.(*exec.ExitError); ok {
		err = nil
	}
	return out.Bytes(), err
}
