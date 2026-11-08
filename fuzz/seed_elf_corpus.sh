#!/usr/bin/env bash
# Seeds corpus/{elf_load,eh_frame,dwarf} from a small program built here
# (binaries are never committed). Needs gcc, objcopy and python3.
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/a.c" <<'C'
#include <stdio.h>
struct point { int x, y; };
static int add(struct point p) { return p.x + p.y; }
int main(int argc, char **argv) {
    struct point p = { argc, 2 };
    printf("%d %s\n", add(p), argv[0]);
    return 0;
}
C
mkdir -p corpus/elf_load corpus/eh_frame corpus/dwarf
for flags in "-O0 -g" "-O2 -g -gdwarf-4" "-O2 -g -gdwarf-5 -no-pie" "-O0"; do
    tag=$(echo "$flags" | tr -d ' -')
    gcc $flags -o "$work/a-$tag" "$work/a.c"
    cp "$work/a-$tag" "corpus/elf_load/seed-$tag"
    objcopy -O binary --only-section=.eh_frame "$work/a-$tag" "corpus/eh_frame/seed-$tag"
    python3 -I - "$work/a-$tag" "corpus/dwarf/seed-$tag" <<'PY'
import struct, subprocess, sys, tempfile, os
binary, out = sys.argv[1:3]
names = [".debug_abbrev", ".debug_str", ".debug_line", ".debug_line_str", ".debug_ranges",
         ".debug_rnglists", ".debug_addr", ".debug_str_offsets", ".debug_info"]
parts = []
with tempfile.TemporaryDirectory() as tmp:
    for name in names:
        path = os.path.join(tmp, "s")
        if os.path.exists(path):
            os.remove(path)
        subprocess.run(["objcopy", "--dump-section", name + "=" + path, binary, os.devnull], check=False,
                       stderr=subprocess.DEVNULL)
        parts.append(open(path, "rb").read() if os.path.exists(path) else b"")
head = b"".join(struct.pack("<H", min(len(p), 65535)) for p in parts[:-1])
open(out, "wb").write(head + b"".join(p[:65535] for p in parts[:-1]) + parts[-1])
PY
done
ls corpus/elf_load corpus/eh_frame corpus/dwarf | wc -l
