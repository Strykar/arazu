#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Cold bring-up of the whole project on a machine with no installed OS.
#
# The self-check proves the KERNEL claims. This proves the PROJECT claims: that
# the repository builds, tests, stages its corpus and grades a patch on a
# machine that has never seen it. It runs from the UKI, so nothing is installed
# and nothing survives except what is written to the USB.
#
# WRITING TO THE USB. The stick is someone's Windows installer with real data on
# it. This creates ONE new timestamped directory and writes only inside it. It
# never formats, never repartitions, never touches an existing path.
#
# WHY THE CONTAINER STORE GOES IN RAM. The stick is vfat or exfat, neither of
# which has POSIX permissions or xattrs, so podman's overlay driver cannot use
# it. tmpfs can.
set -uo pipefail

RESULTS=""
WORK=/run/arazu-cold
PAYLOAD=""                                  # /mnt/usb/arazu once a stick is found
REPO_URL="${ARAZU_REPO_URL:-https://github.com/strykar/arazu}"

# A systemd service inherits no HOME, and `git config --global` refuses without
# one: the first cold boot printed "fatal: $HOME not set" and set up no mirror
# redirect at all. Everything this script writes lives under $WORK or the stick,
# so pointing HOME at the tmpfs root costs nothing.
export HOME="${HOME:-/root}"

log() { printf '  %s\n' "$*"; [ -n "$RESULTS" ] && printf '%s\n' "$*" >> "$RESULTS/transcript.txt"; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; [ -n "$RESULTS" ] && printf '\n== %s ==\n' "$1" >> "$RESULTS/transcript.txt"; }

# One screen at the end, because the progress above scrolls off and a photograph
# of the middle of a run says nothing. Each section records a row here; the last
# thing this script does is clear the screen and print them.
ROWS=()
NFAIL=0
row() {   # row <name> <OK|FAIL|SKIP> <detail>
    ROWS+=("$1|$2|$3")
    [ "$2" = "FAIL" ] && NFAIL=$((NFAIL+1))
    return 0
}

# ONE SCREEN, and it is the last thing on the console. Everything above this
# scrolls off on a real boot, so photographing the middle of a run says nothing.
# A trap runs it on every exit path, including the early one where no source was
# found: a run that dies at step one should still leave a screen saying so.
summary() {
    rc=$?          # FIRST line: any command below overwrites it
    printf '\033[H\033[2J\033[3J'
    printf '\033[1m================================================================\033[0m\n'
    printf '\033[1m  ARAZU COLD RUN   %s   kernel %s\033[0m\n' "$(date -u '+%Y-%m-%d %H:%M UTC')" "$(uname -r)"
    printf '\033[1m================================================================\033[0m\n\n'
    # Print in the order a reader expects, not the order the tiers happened to
    # record them. ENVIRONMENT comes from the self-check, which runs as tier 2,
    # so insertion order put the machine's own capabilities third.
    for want in ENVIRONMENT BUILD SUITE CONTAINMENT "LOOPBACK RAW" CORPUS IMAGES; do
        for r in ${ROWS[@]+"${ROWS[@]}"}; do
            name=${r%%|*}; [ "$name" = "$want" ] || continue
            rest=${r#*|}; stat=${rest%%|*}; detail=${rest#*|}
            case "$stat" in
                OK)   colour='\033[32m' ;;
                FAIL) colour='\033[31m' ;;
                *)    colour='\033[33m' ;;
            esac
            printf '  %-14s '"$colour"'%-5s\033[0m %s\n' "$name" "$stat" "$detail"
        done
    done
    [ "${#ROWS[@]}" -eq 0 ] && printf '  the run ended before any check completed\n'
    printf '\n\033[1m================================================================\033[0m\n'
    # A run that executed nothing is INCOMPLETE, never ALL OK. The first version
    # of this block printed "ALL OK   0 checks" when the script died at step one,
    # because zero failures out of zero checks satisfies NFAIL -eq 0. That is the
    # same defect the mutation harness had: a result indistinguishable from
    # success on a run where nothing was tested. rc catches the other half, a
    # non-zero exit with rows already recorded.
    if [ "${#ROWS[@]}" -eq 0 ]; then
        printf '\033[1;31m  RESULT: INCOMPLETE\033[0m   nothing ran (exit %d)\n' "$rc"
    elif [ "$NFAIL" -eq 0 ] && [ "$rc" -eq 0 ]; then
        printf '\033[1;32m  RESULT: ALL OK\033[0m   %d checks\n' "${#ROWS[@]}"
    elif [ "$NFAIL" -eq 0 ]; then
        printf '\033[1;31m  RESULT: INCOMPLETE\033[0m   %d checks passed, then exit %d\n' "${#ROWS[@]}" "$rc"
    else
        printf '\033[1;31m  RESULT: %d FAILED\033[0m of %d checks\n' "$NFAIL" "${#ROWS[@]}"
    fi
    [ -n "$RESULTS" ] && printf '  full transcript: %s\n' "$RESULTS"
    printf '\033[1m================================================================\033[0m\n'
    printf '\n  photograph this screen, then power off and remove the stick.\n'
}

# Every exit path, so a run that dies at step one still leaves a screen.
trap summary EXIT

# The self-check writes colour. Strip it before matching, or every pattern
# fails against escape codes that are invisible in the log.
sc_row() {  # sc_row <label substring> -> "OK"/"FAIL"/"SKIP" and the detail
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/selfcheck.txt" 2>/dev/null \
      | grep -F "$1" | head -1 \
      | sed -E "s/.*$(printf '%s' "$1" | sed 's/[]\/$*.^[]/\\&/g')[[:space:]]*//"
}

# --- somewhere to put the answers --------------------------------------------
step "results volume"
# OPT-IN, not first-vfat-wins. The earlier version took the first labelled vfat
# volume, which is just as likely to be the ESP this image booted from — or, on
# a developer box, somebody's Windows installer stick. A volume is only written
# to if it carries a marker file placed there deliberately:
#
#     touch /run/media/you/YOURSTICK/ARAZU-RESULTS
#
# Nothing else on the volume is read, moved or removed.
#
# exfat as well as vfat: Ventoy formats its data partition exfat, and a stick
# big enough to carry the container images is over the 32GB where exfat becomes
# the default anyway. Both drivers are modules on Arch and both are now named in
# mkosi.conf; without them this loop simply finds nothing.
usb=""
for cand in $(lsblk -o NAME,FSTYPE -pnr 2>/dev/null | awk '$2=="vfat"||$2=="exfat"{print $1}'); do
    mkdir -p /mnt/usbprobe 2>/dev/null || continue
    if mount -o ro "$cand" /mnt/usbprobe 2>/dev/null; then
        [ -e /mnt/usbprobe/ARAZU-RESULTS ] && usb="$cand"
        umount /mnt/usbprobe 2>/dev/null
    fi
    [ -n "$usb" ] && break
done
[ -z "$usb" ] && log "no volume carries an ARAZU-RESULTS marker; results stay on screen only"
if [ -n "$usb" ]; then
    mkdir -p /mnt/usb
    if mount -o rw,uid=0,gid=0 "$usb" /mnt/usb 2>/dev/null; then
        RESULTS="/mnt/usb/arazu-coldrun-$(date -u +%Y%m%d-%H%M%S)"
        mkdir -p "$RESULTS"
        [ -d /mnt/usb/arazu ] && PAYLOAD=/mnt/usb/arazu
        log "writing to $RESULTS on $usb"
        log "existing contents untouched: $(ls /mnt/usb | wc -l) entries present"
        log "payload: ${PAYLOAD:-none staged, this run needs the network}"
    else
        log "found $usb but could not mount it; results stay on screen only"
    fi
fi

# --- the code ------------------------------------------------------------------
step "acquire the repository"
mkdir -p "$WORK" && cd "$WORK" || { log "cannot enter $WORK"; exit 1; }
tarball=$(ls "${PAYLOAD:-/nonexistent}"/arazu-*.tar.gz /mnt/usb/arazu-*.tar.gz 2>/dev/null | head -1)
if [ -n "$tarball" ]; then
    tar xzf "$tarball" && log "unpacked $(basename "$tarball")"
    src=$(find "$WORK" -maxdepth 2 -name go.mod -printf '%h\n' | head -1)
elif command -v git >/dev/null && git clone --depth 1 "$REPO_URL" "$WORK/arazu" 2>/dev/null; then
    src="$WORK/arazu"; log "cloned $REPO_URL"
else
    log "NO SOURCE: put an arazu-*.tar.gz on the stick, or set ARAZU_REPO_URL"; exit 1
fi
cd "$src" && log "source at $src ($(git rev-parse --short HEAD 2>/dev/null || echo 'tarball'))"

# --- tier 1: it builds and its own tests pass ---------------------------------
step "tier 1 — build and test"
export GOMODCACHE="$WORK/gocache" GOCACHE="$WORK/gobuild" GOFLAGS=-mod=vendor GOPROXY=off
if make build >"$WORK/build.log" 2>&1; then
    log "build OK — $(ls bin | wc -l) binaries, no network, no module cache"
    row BUILD OK "$(ls bin | wc -l) binaries, offline"
else
    log "BUILD FAILED"; tail -5 "$WORK/build.log" | sed 's/^/    /'
    row BUILD FAIL "$(grep -m1 -E 'cannot|error|No such' "$WORK/build.log" | cut -c1-46)"
fi
make fixtures >>"$WORK/build.log" 2>&1 && log "fixtures OK"
if go test ./... -count=1 >"$WORK/test.log" 2>&1; then
    log "suite OK — $(grep -c '^ok' "$WORK/test.log") packages"
    row SUITE OK "$(grep -c '^ok' "$WORK/test.log") packages"
else
    log "SUITE FAILED: $(grep -c '^FAIL' "$WORK/test.log") packages"
    grep -E '^(FAIL|\s+---)' "$WORK/test.log" | head -5 | sed 's/^/    /'
    row SUITE FAIL "$(grep -m1 '^FAIL\s' "$WORK/test.log" | awk '{print $2}')"
fi

# --- tier 2: the containment claim, on this metal -----------------------------
step "tier 2 — containment"
if [ -x /usr/local/bin/arazu-selfcheck ]; then
    /usr/local/bin/arazu-selfcheck > "$WORK/selfcheck.txt" 2>&1
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/selfcheck.txt" \
      | grep -E 'RESULT|control reaches|netns-only|contained denies|loopback raw|counters' \
      | sed 's/^ */  /' | tee -a "${RESULTS:-/dev/null}/transcript.txt" 2>/dev/null || true
    [ -n "$RESULTS" ] && cp "$WORK/selfcheck.txt" "$RESULTS/"

    envfail=$(sed 's/\x1b\[[0-9;]*m//g' "$WORK/selfcheck.txt" | awk '
        /^ *(bpf LSM active|bpffs mounted|BTF available|TPM 2\.0 device)/ && /FAIL/ {
            sub(/ +(OK|FAIL).*/,""); gsub(/^ +/,""); printf "%s ", $0 }')
    if [ -n "$envfail" ]; then row ENVIRONMENT FAIL "${envfail% }"
    else row ENVIRONMENT OK "bpf LSM, bpffs, BTF, TPM"; fi

    # The three-run table is the claim. Each arm has to say the right thing, not
    # merely say something, so match the expected verdict rather than "OK".
    ctrl=$(sc_row "control reaches network"); nsonly=$(sc_row "netns-only denies")
    cont=$(sc_row "contained denies");        loop=$(sc_row "loopback raw denied")
    case "$ctrl$nsonly$cont" in
        *REACHED*ENETUNREACH*EPERM*) row CONTAINMENT OK "REACHED / ENETUNREACH / EPERM" ;;
        *) row CONTAINMENT FAIL "$(printf '%s' "${ctrl:-no control row}" | cut -c1-40)" ;;
    esac
    case "$loop" in
        *"attributable to bpf only"*) row "LOOPBACK RAW" OK "EPERM, bpf alone" ;;
        "")  row "LOOPBACK RAW" FAIL "row absent from the self-check" ;;
        *)   row "LOOPBACK RAW" FAIL "$(printf '%s' "$loop" | cut -c1-40)" ;;
    esac
else
    log "self-check not in image"
    row CONTAINMENT SKIP "self-check binary not in image"
fi

# --- tier 3: stage the corpus and grade a patch -------------------------------
step "tier 3 — corpus and grading"
#
# OFFLINE FIRST. The earlier version skipped this tier outright without DNS,
# which made the interesting half of a cold run depend on the one thing a cold
# machine is least likely to have. Everything the cases pin can be carried on
# the stick instead, and the redirect below is what makes that invisible to
# stage-corpus.sh: it still clones the https URL the case file names, git just
# resolves it against the mirror. No script learns a second source of truth.
#
# WHY THIS TIER REPORTS SO MUCH. It is the one that fails for boring
# environmental reasons — a missing mirror, a pin the mirror does not carry, a
# tmpfs too small for the images — and the first version said only "staging
# incomplete" plus one arbitrary line of tail. That names a symptom and hides
# the cause, on the tier furthest from the developer's machine.
if ! command -v podman >/dev/null; then
    log "SKIP: podman not in image"
    row CORPUS SKIP "podman not in image"
else
    # The container store must be on a POSIX filesystem. The stick is not one.
    export KAVACH_CORPUS="$WORK/corpus" ARAZU_CORPUS="$WORK/corpus"
    mkdir -p "$WORK/corpus/shim" "$WORK/store"

    # The store needs its OWN tmpfs. Inheriting /run means inheriting systemd's
    # default of 10% of RAM, which on a 62GB machine is 6.2GB against an image
    # set of 6.7GB: the pre-flight below would refuse, correctly, and skip the
    # one thing the stick was loaded up to carry. size= is a ceiling and not a
    # reservation, so asking for 70% costs nothing until something is written.
    if mount -t tmpfs -o size=70%,mode=0700 arazu-store "$WORK/store" 2>/dev/null; then
        log "container store: private tmpfs, $(df -h --output=size "$WORK/store" | tail -1 | tr -d ' ') ceiling"
    else
        log "container store: could not mount a private tmpfs, using $WORK on /run"
    fi
    printf '#!/usr/bin/env bash\nexec podman --root %s/store --runroot /run/arazu-runroot "$@"\n' "$WORK" \
        > "$WORK/corpus/shim/docker"
    chmod +x "$WORK/corpus/shim/docker"
    export KAVACH_SHIM="$WORK/corpus/shim/docker"

    offline=0
    if [ -n "$PAYLOAD" ] && [ -d "$PAYLOAD/git" ]; then
        # A mirror is root-owned on a filesystem with no ownership, which recent
        # git calls "dubious" and refuses to read. It is our own stick.
        git config --global --add safe.directory '*' 2>/dev/null
        git config --global url."file://$PAYLOAD/git/".insteadOf "https://github.com/"
        offline=1
        log "using staged mirrors in $PAYLOAD/git ($(ls "$PAYLOAD/git" | wc -l) orgs)"
        # Name what is actually there. A mirror set missing the repo a case
        # pins fails later as an opaque clone error, and the operator has no
        # way to see that the stick simply does not carry it.
        find "$PAYLOAD/git" -maxdepth 2 -mindepth 2 2>/dev/null \
          | sed "s|$PAYLOAD/git/|    mirror: |" | while read -r m; do log "$m"; done
    elif ! getent hosts github.com >/dev/null 2>&1; then
        log "SKIP: nothing staged on the stick and no DNS"
        row CORPUS SKIP "no mirrors on the stick, no DNS"
    fi

    if [ "$offline" -eq 1 ] || getent hosts github.com >/dev/null 2>&1; then
        if ./scripts/stage-corpus.sh >"$WORK/stage.log" 2>&1; then
            npin=$(grep -c 'pin verified' "$WORK/stage.log")
            log "staged: $npin pins verified"
            row CORPUS OK "$npin pins verified${offline:+, offline}"
        else
            # stage-corpus.sh already prints a specific reason per repository.
            # Surface those lines rather than the tail, which is usually just
            # the closing "STAGING INCOMPLETE" banner.
            log "STAGING INCOMPLETE — the reasons it gave:"
            why=$(grep -E 'REFUSING|CLONE FAILED|PIN MISMATCH|CANNOT CHECK OUT|not an https' \
                    "$WORK/stage.log" | head -6)
            if [ -n "$why" ]; then
                printf '%s\n' "$why" | while read -r l; do log "    $l"; done
            else
                log "    no per-repository error; last lines of stage.log:"
                tail -4 "$WORK/stage.log" | while read -r l; do log "    $l"; done
            fi
            npin=$(grep -c 'pin verified' "$WORK/stage.log")
            first=$(printf '%s' "$why" | head -1 | cut -c1-40)
            row CORPUS FAIL "${first:-see stage.log} ($npin ok)"
        fi

        # Images are what turn a staged checkout into something that can build
        # and run a harness. Loading is minutes of untarring, so it is reported
        # rather than silent.
        if [ -n "$PAYLOAD" ] && [ -d "$PAYLOAD/images" ]; then
            # The store is tmpfs, so "disk full" here means RAM. Say so BEFORE
            # spending twenty minutes untarring into a volume that cannot hold
            # it: a half-loaded store fails later as a missing-image error that
            # looks nothing like the memory ceiling that caused it.
            need_k=$(du -sk "$PAYLOAD"/images 2>/dev/null | awk '{print $1}')
            # Compare against MemAvailable, not the tmpfs ceiling. df on a tmpfs
            # reports its size= cap, which says nothing about whether the RAM
            # behind it exists; the store's cap is now 70% of RAM by design.
            mem_k=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
            free_k=$(df -k --output=avail "$WORK/store" 2>/dev/null | tail -1)
            [ "${mem_k:-0}" -lt "${free_k:-0}" ] && free_k=$mem_k
            log "images need $((need_k/1024))MB, usable $((free_k/1024))MB (RAM-backed store)"
            if [ "${need_k:-0}" -gt "${free_k:-0}" ]; then
                log "SKIPPING IMAGES: they do not fit. This machine needs more RAM,"
                log "  or remove tarballs from ${PAYLOAD}/images. Tiers 1 and 2 above stand."
                row IMAGES SKIP "need $((need_k/1024))MB, have $((free_k/1024))MB"
            else
                n=0; nbad=0
                for img in "$PAYLOAD"/images/*.tar; do
                    [ -e "$img" ] || continue
                    if "$KAVACH_SHIM" load -i "$img" >>"$WORK/images.log" 2>&1; then
                        n=$((n+1)); log "loaded $(basename "$img" .tar)"
                    else
                        nbad=$((nbad+1))
                        log "FAILED to load $(basename "$img") — podman said:"
                        tail -3 "$WORK/images.log" | while read -r l; do log "    $l"; done
                    fi
                done
                log "$n container images available to the corpus store"
                if [ "$nbad" -eq 0 ]; then row IMAGES OK "$n loaded"
                else row IMAGES FAIL "$nbad of $((n+nbad)) failed to load"; fi
            fi
        else
            row IMAGES SKIP "none staged on the stick"
        fi
    fi
fi

# --- what it all came to -------------------------------------------------------
step "result"
if [ -n "$RESULTS" ]; then
    cp -a "$WORK"/*.log "$RESULTS/" 2>/dev/null
    sync
    log "transcript and logs written to $RESULTS"
else
    log "nothing was written: no volume carried an ARAZU-RESULTS marker"
fi
