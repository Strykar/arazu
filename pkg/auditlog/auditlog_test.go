// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeChain(t *testing.T, n int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append(EvRunStart, "detail"); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	l.Close()
	return p
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lines(t *testing.T, p string) []string {
	t.Helper()
	return strings.Split(strings.TrimSpace(mustRead(t, p)), "\n")
}

func TestCleanChainVerifies(t *testing.T) {
	p := writeChain(t, 5)
	n, err := Verify(p)
	if err != nil {
		t.Fatalf("clean chain failed to verify: %v", err)
	}
	if n != 5 {
		t.Fatalf("verified %d entries, want 5", n)
	}
}

func TestGenesisPrevHashIsZeros(t *testing.T) {
	p := writeChain(t, 1)
	if !strings.Contains(mustRead(t, p), GenesisPrev) {
		t.Fatal("genesis entry does not carry an all-zero prev_hash")
	}
}

func TestEditedFieldBreaksChain(t *testing.T) {
	p := writeChain(t, 5)
	before := mustRead(t, p)
	edited := strings.Replace(before, `"detail":"detail"`, `"detail":"EVIL!!"`, 1)
	if edited == before {
		t.Fatal("test setup failed: no substitution was made")
	}
	os.WriteFile(p, []byte(edited), 0o600)

	_, err := Verify(p)
	if err == nil {
		t.Fatal("edited entry verified clean")
	}
	if !strings.Contains(err.Error(), "seq 1") {
		t.Fatalf("error does not name the breaking seq: %v", err)
	}
}

// Editing the last entry must also be caught. An implementation that only
// checked prev_hash links would miss it, since nothing chains from the tail.
func TestEditedLastEntryBreaksChain(t *testing.T) {
	p := writeChain(t, 5)
	ls := lines(t, p)
	ls[4] = strings.Replace(ls[4], `"detail":"detail"`, `"detail":"EVIL!!"`, 1)
	os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o600)

	_, err := Verify(p)
	if err == nil {
		t.Fatal("edited final entry verified clean")
	}
	if !strings.Contains(err.Error(), "seq 5") {
		t.Fatalf("error does not name the breaking seq: %v", err)
	}
}

// The realistic attacker edits an entry and recomputes its entry_hash so
// the entry is internally consistent. Only the chain link catches that: the
// forged hash no longer matches what the next entry recorded as its
// prev_hash.
//
// Without this test the prev_hash field is unevidenced. Disabling the chain
// check in Verify made no other test fail.
func TestEditedEntryWithRecomputedHashBreaksChain(t *testing.T) {
	p := writeChain(t, 5)
	ls := lines(t, p)

	var forged Entry
	if err := json.Unmarshal([]byte(ls[2]), &forged); err != nil {
		t.Fatal(err)
	}
	forged.Detail = "EVIL!!"
	h, err := forged.hash()
	if err != nil {
		t.Fatal(err)
	}
	forged.EntryHash = h
	b, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	ls[2] = string(b)
	os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o600)

	// The forged entry verifies on its own terms.
	if got, _ := forged.hash(); got != forged.EntryHash {
		t.Fatal("test setup failed: the forged entry is not self-consistent")
	}

	_, err = Verify(p)
	if err == nil {
		t.Fatal("an entry edited with a recomputed hash verified clean")
	}
	if !strings.Contains(err.Error(), "seq 4") {
		t.Fatalf("break should surface at the following entry, got: %v", err)
	}
}

func TestDeletedEntryBreaksChain(t *testing.T) {
	p := writeChain(t, 5)
	ls := lines(t, p)
	kept := append(append([]string{}, ls[:2]...), ls[3:]...)
	os.WriteFile(p, []byte(strings.Join(kept, "\n")+"\n"), 0o600)

	if _, err := Verify(p); err == nil {
		t.Fatal("chain with a deleted entry verified clean")
	}
}

// Tail truncation leaves a self-consistent prefix. Pin the documented
// behaviour so the limit stays visible instead of being assumed away.
func TestTruncatedTailVerifiesAsShorterChain(t *testing.T) {
	p := writeChain(t, 5)
	ls := lines(t, p)
	os.WriteFile(p, []byte(strings.Join(ls[:3], "\n")+"\n"), 0o600)

	n, err := Verify(p)
	if err != nil {
		t.Fatalf("prefix should verify as a shorter clean chain: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d, want 3", n)
	}
}

func TestOpenRefusesToExtendABrokenChain(t *testing.T) {
	p := writeChain(t, 3)
	before := mustRead(t, p)
	os.WriteFile(p, []byte(strings.Replace(before, `"detail":"detail"`, `"detail":"EVIL!!"`, 1)), 0o600)

	if _, err := Open(p); err == nil {
		t.Fatal("Open accepted a broken chain, so tampering would be hidden behind new entries")
	}
}

func TestAppendResumesAnExistingChain(t *testing.T) {
	p := writeChain(t, 3)
	l, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	e, err := l.Append(EvSign, "more")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	if e.Seq != 4 {
		t.Fatalf("resumed at seq %d, want 4", e.Seq)
	}
	n, err := Verify(p)
	if err != nil || n != 4 {
		t.Fatalf("resumed chain: n=%d err=%v", n, err)
	}
}

func TestReorderedEntriesBreakChain(t *testing.T) {
	p := writeChain(t, 5)
	ls := lines(t, p)
	ls[1], ls[2] = ls[2], ls[1]
	os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o600)

	if _, err := Verify(p); err == nil {
		t.Fatal("reordered chain verified clean")
	}
}
