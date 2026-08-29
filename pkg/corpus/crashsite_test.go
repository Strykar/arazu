// SPDX-License-Identifier: Apache-2.0

package corpus

import "testing"

// The real declaration normalise-nginx.sh writes for cpv2.
const declaredCPV2 = "ngx_decode_base64_internal /src/harnesses/bld/src/core/ngx_string.c:1330:14"

func TestParseDeclaredSiteDropsWhatTheToolchainVaries(t *testing.T) {
	got := ParseDeclaredSite(declaredCPV2)
	want := CrashSite{File: "ngx_string.c", Function: "ngx_decode_base64_internal"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestMatchSite(t *testing.T) {
	d := ParseDeclaredSite(declaredCPV2)

	// Verbatim from a real run of the unpatched tree.
	same := `==31==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x55 in ngx_decode_base64_internal /src/harnesses/bld/src/core/ngx_string.c:1330:14
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/core/ngx_string.c:1330:14 in ngx_decode_base64_internal`

	// The line moved because -fsanitize-recover let execution continue. Same
	// bug; a file:line matcher would call this different.
	movedLine := `SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/core/ngx_string.c:1328:14 in ngx_decode_base64_internal`

	// cpv2-boundary-off-by-one: the original overflow is gone and a different
	// one appears in another file and function.
	different := `SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/http/ngx_http_core_module.c:1999:25 in ngx_http_auth_basic_user`

	// The declared function was inlined into its caller, so the report names
	// the caller. Same file. Must NOT read as a new bug.
	inlined := `SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/core/ngx_string.c:1330:14 in ngx_decode_base64`

	// Inlined, but the declared function still appears in a stack frame.
	inlinedButFramed := `    #0 0x55 in ngx_decode_base64_internal /src/harnesses/bld/src/core/ngx_string.c:1330:14
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/core/ngx_string.c:1330:14 in ngx_decode_base64`

	for _, tc := range []struct {
		name   string
		report string
		want   SiteMatch
	}{
		{"identical site", same, SiteSame},
		{"line moved by instrumentation", movedLine, SiteSame},
		{"different file and function", different, SiteDiffer},
		{"inlined into caller, same file", inlined, SiteUndetermined},
		{"inlined but named in a frame", inlinedButFramed, SiteSame},
		{"empty report", "", SiteUndetermined},
		{"report with no parseable site", "ERROR: something happened", SiteUndetermined},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchSite(d, tc.report); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// An unparseable declaration must not make every report look like a new bug.
func TestUnparseableDeclarationIsUndetermined(t *testing.T) {
	got := MatchSite(ParseDeclaredSite("nonsense without a location"),
		`SUMMARY: AddressSanitizer: heap-buffer-overflow /a/b.c:1:1 in f`)
	if got != SiteUndetermined {
		t.Errorf("got %q, want undetermined", got)
	}
}
