// SPDX-License-Identifier: Apache-2.0

// Command log-verify recomputes an audit log's hash chain.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"arazu/pkg/auditlog"
)

type decision struct {
	Decision string `json:"decision"`
	Entries  int    `json:"entries"`
	Reason   string `json:"reason,omitempty"`
}

func main() {
	path := flag.String("log", "", "path to the audit log")
	flag.Parse()

	if *path == "" {
		emit(decision{Decision: "ERROR", Reason: "no -log given"}, 2)
	}

	n, err := auditlog.Verify(*path)
	if err != nil {
		emit(decision{Decision: "BROKEN", Entries: n, Reason: err.Error()}, 1)
	}
	emit(decision{Decision: "CLEAN", Entries: n}, 0)
}

func emit(d decision, code int) {
	b, _ := json.Marshal(d)
	fmt.Println(string(b))
	if d.Reason != "" {
		fmt.Fprintf(os.Stderr, "%s: %s\n", d.Decision, d.Reason)
	}
	os.Exit(code)
}
