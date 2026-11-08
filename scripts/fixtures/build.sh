#!/usr/bin/env bash
# Builds the test binaries into tests/fixtures/bin/ (git-ignored).
#
# Matrix (whatever the system provides; missing tools are skipped with a note):
#   C        gcc/clang x -O0/-O2 x PIE/no-PIE, stripped variants, -fcf-protection (IBT, .plt.sec),
#            static glibc, static musl (musl-gcc, only if installed)
#   C++      g++/clang++ with exceptions, -O2, PIE, plain and stripped
#   Rust     rustc -O, plain and stripped
#   Go       go build (static runtime), plain and stripped
#   asm      freestanding x86-64, no libc
#
# Idempotent: an output is rebuilt only if missing or older than its source
# or this script.  `build.sh --force` rebuilds everything, `build.sh --clean`
# removes the output directory.  `build.sh --strict` additionally fails (exit
# 1) if any variant fails or is missing - i.e. every compiler of the matrix,
# including musl-gcc, must be present (CI / wave C).
#
# Naming: <src>-<compiler>-<opt>-<pie|nopie>[-ibt][-static][-stripped]
# tests/fixtures/bin/MANIFEST lists the file names of all binaries present.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
out="$here/../../tests/fixtures/bin"
self="$here/build.sh"
force=0
strict=0

case "${1:-}" in
    --force) force=1 ;;
    --strict) strict=1 ;;
    --clean) rm -rf "$out"; echo "removed $out"; exit 0 ;;
    "" ) ;;
    *) echo "usage: $0 [--force|--clean]" >&2; exit 2 ;;
esac

mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

built=0 skipped=0 failed=0 missing=0
# Reproducible output: no absolute build paths embedded.
cflags_repro="-ffile-prefix-map=$src=src -ffile-prefix-map=$tmp=tmp"

have() { command -v "$1" >/dev/null 2>&1; }
note() { echo "[fixtures] $*"; }

# fresh <output> <source>: true if the output is up to date.
fresh() {
    [ "$force" = 0 ] && [ -f "$1" ] && [ "$1" -nt "$2" ] && [ "$1" -nt "$self" ]
}

# strip_copy <from> <to>
strip_copy() { cp "$1" "$2" && strip --strip-all "$2"; }

# build <name> <source> <command...>   (command writes to "$tmp/$name")
build() {
    local name="$1" source="$2"; shift 2
    local dest="$out/$name"
    if fresh "$dest" "$source"; then skipped=$((skipped + 1)); return 0; fi
    rm -f "$tmp/$name"
    if "$@" >"$tmp/$name.log" 2>&1 && [ -f "$tmp/$name" ]; then
        mv -f "$tmp/$name" "$dest"
        built=$((built + 1))
        note "built $name"
    else
        failed=$((failed + 1))
        note "FAILED $name (log follows)"
        sed 's/^/    /' "$tmp/$name.log" | head -20 || true
    fi
    return 0
}

# stripped <name>: derive <name>-stripped from an existing <name>.
stripped() {
    local name="$1"
    [ -f "$out/$name" ] || return 0
    local dest="$out/$name-stripped"
    if fresh "$dest" "$out/$name"; then skipped=$((skipped + 1)); return 0; fi
    if have strip && strip_copy "$out/$name" "$tmp/$name-stripped"; then
        mv -f "$tmp/$name-stripped" "$dest"
        built=$((built + 1))
        note "built $name-stripped"
    else
        failed=$((failed + 1))
        note "FAILED $name-stripped"
    fi
}

# ---- C and C++ -------------------------------------------------------------
for cc in gcc clang; do
    if ! have "$cc"; then note "skip: $cc not found"; missing=$((missing + 1)); continue; fi
    for opt in O0 O2; do
        for pie in pie nopie; do
            if [ "$pie" = pie ]; then pflags="-fPIE -pie"; else pflags="-fno-pie -no-pie"; fi
            name="hello-$cc-$opt-$pie"
            # shellcheck disable=SC2086
            build "$name" "$src/hello.c" "$cc" $cflags_repro -g0 "-$opt" $pflags -fcf-protection=none -o "$tmp/$name" "$src/hello.c"
            if [ "$opt" = O2 ]; then stripped "$name"; fi
        done
    done
    # IBT: endbr64 + .plt.sec
    for pie in pie nopie; do
        if [ "$pie" = pie ]; then pflags="-fPIE -pie"; else pflags="-fno-pie -no-pie"; fi
        name="hello-$cc-O2-$pie-ibt"
        # shellcheck disable=SC2086
        build "$name" "$src/hello.c" "$cc" $cflags_repro -g0 -O2 $pflags -fcf-protection=full -Wl,-z,ibtplt -o "$tmp/$name" "$src/hello.c"
    done
    # with debug info (DWARF subprograms)
    name="hello-$cc-O0-pie-dbg"
    build "$name" "$src/hello.c" "$cc" $cflags_repro -g -O0 -fPIE -pie -o "$tmp/$name" "$src/hello.c"
    # static glibc (only if libc.a is installed)
    name="hello-$cc-O2-nopie-static"
    build "$name" "$src/hello.c" "$cc" $cflags_repro -g0 -O2 -static -o "$tmp/$name" "$src/hello.c"
    stripped "$name"
done

for cxx in g++ clang++; do
    if ! have "$cxx"; then note "skip: $cxx not found"; missing=$((missing + 1)); continue; fi
    tag="${cxx%++}"; if [ "$tag" = g ]; then tag=gcc; fi
    name="eh-$tag-O2-pie"
    build "$name" "$src/eh.cpp" "$cxx" $cflags_repro -g0 -O2 -fPIE -pie -fexceptions -o "$tmp/$name" "$src/eh.cpp"
    stripped "$name"
done

# shared library (kind = shared_library), gcc and clang
for cc in gcc clang; do
    have "$cc" || continue
    name="libfoo-$cc.so"
    build "$name" "$src/foo.c" "$cc" $cflags_repro -g0 -O2 -fPIC -shared -o "$tmp/$name" "$src/foo.c"
done

# static musl, only if a musl toolchain is installed
if have musl-gcc; then
    name="hello-musl-O2-nopie-static"
    build "$name" "$src/hello.c" musl-gcc $cflags_repro -g0 -O2 -static -o "$tmp/$name" "$src/hello.c"
    stripped "$name"
    name="hello-musl-O2-pie-static"
    build "$name" "$src/hello.c" musl-gcc $cflags_repro -g0 -O2 -fPIE -static-pie -o "$tmp/$name" "$src/hello.c"
    stripped "$name"
else
    note "skip: musl-gcc not found (static musl fixtures not built)"
    missing=$((missing + 1))
fi

# ---- freestanding asm ------------------------------------------------------
if have gcc; then
    name="tiny-asm-nopie-static"
    build "$name" "$src/tiny.S" gcc -nostdlib -static -no-pie -o "$tmp/$name" "$src/tiny.S"
fi

# ---- Rust --------------------------------------------------------------------
if have rustc; then
    name="hello-rustc-O-pie"
    build "$name" "$src/hello.rs" rustc --remap-path-prefix "$src=src" --edition 2021 -C opt-level=2 -C debuginfo=0 -C strip=none \
        -C relocation-model=pic -o "$tmp/$name" "$src/hello.rs"
    stripped "$name"
else
    note "skip: rustc not found"; missing=$((missing + 1))
fi

# ---- Go ----------------------------------------------------------------------
if have go; then
    name="hello-go"
    # go build wants a module-less single file; keep caches out of the repo.
    build "$name" "$src/hello.go" env CGO_ENABLED=0 GOTOOLCHAIN=local \
        go build -trimpath -o "$tmp/$name" "$src/hello.go"
    stripped "$name"
else
    note "skip: go not found"; missing=$((missing + 1))
fi

# ---- manifest ----------------------------------------------------------------
{
    for f in "$out"/*; do
        [ -f "$f" ] || continue
        b="$(basename "$f")"
        [ "$b" = MANIFEST ] && continue
        printf '%s\n' "$b"
    done | sort
} >"$tmp/MANIFEST"
mv -f "$tmp/MANIFEST" "$out/MANIFEST"

note "done: built=$built up-to-date=$skipped failed=$failed skipped-tools=$missing -> $out"
# Required variants for --strict (everything the matrix promises).
required="hello-gcc-O0-pie hello-gcc-O2-nopie-ibt hello-gcc-O2-pie-stripped hello-gcc-O2-nopie-static
hello-clang-O0-pie hello-clang-O2-pie-ibt hello-clang-O2-pie-stripped hello-clang-O2-nopie-static
eh-gcc-O2-pie eh-clang-O2-pie tiny-asm-nopie-static hello-rustc-O-pie hello-go hello-go-stripped
libfoo-gcc.so libfoo-clang.so hello-musl-O2-nopie-static hello-musl-O2-pie-static-stripped"
if [ "$strict" = 1 ]; then
    bad=0
    for f in $required; do
        if [ ! -f "$out/$f" ]; then note "STRICT: required fixture missing: $f"; bad=1; fi
    done
    if [ "$failed" -ne 0 ]; then note "STRICT: $failed variant(s) failed"; bad=1; fi
    if [ "$bad" -ne 0 ]; then exit 1; fi
fi
# A failed individual variant (e.g. no libc.a for -static) must not break CI
# setup; the tests skip fixtures that are absent.  Exit 1 only if nothing exists.
if [ "$(wc -l <"$out/MANIFEST")" -eq 0 ]; then exit 1; fi
exit 0
