#!/usr/bin/env bash
# Вшивает fsnt-torrent-blocker.py в install.sh. Запускать после каждой правки детектора.
#   ./build.sh          пересобрать
#   ./build.sh --check  проверить, что install.sh собран из текущего .py
set -euo pipefail
cd "$(dirname "$0")"
python3 - "$@" <<'PY'
import sys
src = open('fsnt-torrent-blocker.py').read().rstrip('\n') + '\n'
inst = open('install.sh').read()
start = "cat <<'FTB_PAYLOAD'\n"
end = "FTB_PAYLOAD\n}"
i = inst.index(start) + len(start)
j = inst.index(end, i)
if 'FTB_PAYLOAD' in src:
    sys.exit('в детекторе встречается маркер FTB_PAYLOAD — heredoc сломается')
new = inst[:i] + src + inst[j:]
if '--check' in sys.argv[1:]:
    sys.exit(0 if new == inst else 'install.sh устарел: запусти ./build.sh')
open('install.sh', 'w').write(new)
print('install.sh пересобран')
PY
