// SPDX-License-Identifier: Apache-2.0

// Command arazu-env prints the host capability matrix and exits non-zero
// when a required capability is missing.
package main

import (
	"fmt"
	"os"

	"arazu/pkg/hostcap"
)

func main() {
	r := hostcap.Probe()

	fmt.Fprint(os.Stderr, r.Text())

	b, err := r.JSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot render report: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(b))

	if !r.OK {
		fmt.Fprintln(os.Stderr, "\nrefusing to proceed: a required capability is missing")
		os.Exit(1)
	}
}
