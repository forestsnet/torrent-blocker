#!/usr/bin/env bash
# Вшивает fsnt-torrent-blocker.py и btguard.nft в install.sh. Запускать после правок.
#   ./build.sh          пересобрать
#   ./build.sh --check  проверить, что install.sh собран из текущих исходников
set -euo pipefail
cd "$(dirname "$0")"
python3 - "$@" <<'PY'
import sys

def inject(inst, marker, src_file):
    src = open(src_file).read().rstrip('\n') + '\n'
    if marker in src:
        sys.exit(f'в {src_file} встречается маркер {marker} — heredoc сломается')
    start = f"cat <<'{marker}'\n"
    end = f"{marker}\n}}"
    i = inst.index(start) + len(start)
    j = inst.index(end, i)
    return inst[:i] + src + inst[j:]

inst = open('install.sh').read()
new = inject(inst, 'FTB_PAYLOAD', 'fsnt-torrent-blocker.py')
new = inject(new, 'BTG_PAYLOAD', 'btguard.nft')
if '--check' in sys.argv[1:]:
    sys.exit(0 if new == inst else 'install.sh устарел: запусти ./build.sh')
open('install.sh', 'w').write(new)
print('install.sh пересобран (детектор + btguard.nft)')
PY
