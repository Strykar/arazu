// SPDX-License-Identifier: Apache-2.0

// Package auditlog is an append-only, hash-chained event log.
//
// Each entry carries the hash of the previous one, so editing a field or
// removing an entry from the middle breaks every link after it and Verify
// reports where.
//
// Tail truncation is a different matter. Dropping entries from the end
// leaves a shorter, self-consistent chain, and no amount of internal
// hashing can detect that. Catching it needs a head hash or an expected
// length held somewhere the attacker cannot reach. SCOPE.md says so rather
// than letting the chain imply a property it does not have.
package auditlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// GenesisPrev is the prev_hash of the first entry in a chain.
const GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// Event names used across the spike.
const (
	EvIngressAccept = "INGRESS_ACCEPT"
	EvIngressReject = "INGRESS_REJECT"
	EvRunStart      = "RUN_START"
	EvRunEnd        = "RUN_END"
	EvEgressRequest = "EGRESS_REQUEST"
	EvEgressDeny    = "EGRESS_DENY"
	EvSeal          = "SEAL"
	// The gate reaching a verdict. Without these the log records an envelope
	// with no evidence a decision was ever made, and log-verify passes over it,
	// because a hash chain over an incomplete record is still self-consistent.
	EvGateAccept  = "GATE_ACCEPT"
	EvGateReject  = "GATE_REJECT"
	EvGateError   = "GATE_ERROR"
	EvSign        = "SIGN"
	EvSignRefused = "SIGN_REFUSED"
	// A CRS run that gave the gate nothing to grade. Not a gate event: no
	// candidate was verified, so recording it as GATE_REJECT would say the CRS
	// produced a bad patch when it produced none.
	EvDriveDecline = "DRIVE_DECLINE"
)

// Entry is one logged event. Field order here defines the canonical form
// that entry_hash is taken over, so do not reorder it.
type Entry struct {
	Seq       uint64 `json:"seq"`
	TS        string `json:"ts"`
	Event     string `json:"event"`
	Detail    string `json:"detail"`
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
}

func (e Entry) hash() (string, error) {
	c := e
	c.EntryHash = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log appends to a chain.
type Log struct {
	f        *os.File
	lastSeq  uint64
	lastHash string
}

// Open opens path for appending, verifying any existing chain first.
//
// Refusing to extend a broken chain matters: without it, an attacker who
// edits an old entry gets a log that keeps growing normally and only fails
// verification later, at a time of nobody's choosing.
func Open(path string) (*Log, error) {
	l := &Log{lastHash: GenesisPrev}

	if f, err := os.Open(path); err == nil {
		n, last, verr := scan(f)
		f.Close()
		if verr != nil {
			return nil, fmt.Errorf("refusing to append to a broken chain: %w", verr)
		}
		if n > 0 {
			l.lastSeq, l.lastHash = last.Seq, last.EntryHash
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

// Append writes one entry and returns it.
func (l *Log) Append(event, detail string) (Entry, error) {
	e := Entry{
		Seq:      l.lastSeq + 1,
		TS:       time.Now().UTC().Format(time.RFC3339Nano),
		Event:    event,
		Detail:   detail,
		PrevHash: l.lastHash,
	}
	h, err := e.hash()
	if err != nil {
		return Entry{}, err
	}
	e.EntryHash = h

	b, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return Entry{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, err
	}

	l.lastSeq, l.lastHash = e.Seq, e.EntryHash
	return e, nil
}

func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

func scan(f *os.File) (int, Entry, error) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	prev := GenesisPrev
	var wantSeq uint64 = 1
	var last Entry
	n := 0

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return n, last, fmt.Errorf("seq %d: malformed entry: %w", wantSeq, err)
		}
		if e.Seq != wantSeq {
			return n, last, fmt.Errorf("seq %d: out of order or missing entry, found seq %d", wantSeq, e.Seq)
		}
		if e.PrevHash != prev {
			return n, last, fmt.Errorf("seq %d: prev_hash does not chain to the previous entry", e.Seq)
		}
		want, err := e.hash()
		if err != nil {
			return n, last, err
		}
		if want != e.EntryHash {
			return n, last, fmt.Errorf("seq %d: entry_hash does not match the entry contents", e.Seq)
		}
		prev, last, n, wantSeq = e.EntryHash, e, n+1, wantSeq+1
	}
	if err := sc.Err(); err != nil {
		return n, last, err
	}
	return n, last, nil
}

// Verify recomputes the whole chain and reports how many entries verified.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, _, err := scan(f)
	return n, err
}
