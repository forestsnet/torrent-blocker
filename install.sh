#!/usr/bin/env bash
# fsnt-torrent-blocker — установка, обновление и удаление на Remnawave Node.
#
#   curl -fsSL https://raw.githubusercontent.com/forestsnet/torrent-blocker/main/install.sh | sudo bash
#   curl -fsSL …/install.sh | sudo bash -s -- --dry-run             только наблюдать, в ноду не слать
#   curl -fsSL …/install.sh | sudo bash -s -- --live                снять dry-run
#   curl -fsSL …/install.sh | sudo bash -s -- --min-hosts 30 …      задать пороги/игнор-порты (--help)
#   curl -fsSL …/install.sh | sudo bash -s -- --uninstall           удалить (--purge — вместе с настройками)
#   ssh deploy@host 'sudo bash -s' < install.sh                     то же без доступа сервера к GitHub
#
# Пороги можно задать флагами при установке и потом править в /etc/default/fsnt-torrent-blocker.
# Детектор вшит в этот файл целиком: сборка — ./build.sh из fsnt-torrent-blocker.py.

main() {
    set -euo pipefail
    local NAME=fsnt-torrent-blocker
    local BIN=/usr/local/sbin/$NAME
    local UNIT=/etc/systemd/system/$NAME.service
    local CONF=/etc/default/$NAME
    local MODE=install DRY="" PURGE=0
    local o_window="" o_hosts="" o_ports="" o_cooldown="" o_max="" o_iports=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)      DRY=1 ;;
            --live)         DRY=0 ;;
            --uninstall)    MODE=uninstall ;;
            --purge)        PURGE=1 ;;
            --window)       shift; o_window=${1-} ;;
            --window=*)     o_window=${1#*=} ;;
            --min-hosts)    shift; o_hosts=${1-} ;;
            --min-hosts=*)  o_hosts=${1#*=} ;;
            --min-ports)    shift; o_ports=${1-} ;;
            --min-ports=*)  o_ports=${1#*=} ;;
            --cooldown)     shift; o_cooldown=${1-} ;;
            --cooldown=*)   o_cooldown=${1#*=} ;;
            --max-reports)   shift; o_max=${1-} ;;
            --max-reports=*) o_max=${1#*=} ;;
            --ignore-ports)   shift; o_iports=${1-} ;;
            --ignore-ports=*) o_iports=${1#*=} ;;
            -h|--help)      usage; return 0 ;;
            *)              die "неизвестный аргумент: $1" ;;
        esac
        shift
    done

    local k
    for k in "window:$o_window" "min-hosts:$o_hosts" "min-ports:$o_ports" \
             "cooldown:$o_cooldown" "max-reports:$o_max"; do
        case "${k#*:}" in
            "")           ;;
            *[!0-9]*|0)   die "--${k%%:*} требует положительное число, получено: '${k#*:}'" ;;
        esac
    done
    case "$o_iports" in
        *[!0-9,\ ]*) die "--ignore-ports: только числа через запятую/пробел: '$o_iports'" ;;
    esac

    [ "$(id -u)" = 0 ] || die "нужен root: curl … | sudo bash"
    command -v systemctl >/dev/null || die "нужен systemd"

    if [ "$MODE" = uninstall ]; then
        systemctl disable --now "$NAME.service" >/dev/null 2>&1 || true
        rm -f "$BIN" "$UNIT"
        [ "$PURGE" = 1 ] && rm -f "$CONF"
        systemctl daemon-reload
        say "удалён$([ "$PURGE" = 1 ] && echo ' вместе с настройками' || echo "; настройки оставлены в $CONF")"
        return 0
    fi

    if ! command -v python3 >/dev/null; then
        say "ставлю python3"
        if command -v apt-get >/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal </dev/null >/dev/null
        elif command -v dnf >/dev/null; then dnf install -y -q python3 </dev/null
        elif command -v yum >/dev/null; then yum install -y -q python3 </dev/null
        else die "python3 не найден и поставить нечем"
        fi
    fi
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 6))' </dev/null || die "нужен python3 >= 3.6"

    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    payload > "$TMP/$NAME"
    python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$TMP/$NAME" </dev/null \
        || die "детектор повреждён при загрузке — повтори команду"
    install -m 0755 "$TMP/$NAME" "$BIN"

    if [ ! -f "$CONF" ]; then
        config > "$CONF"
        [ -z "$DRY" ] && DRY=0
    fi
    [ -n "$DRY" ]        && set_conf FTB_DRY_RUN             "$DRY"        "$CONF" || true
    [ -n "$o_window" ]   && set_conf FTB_WINDOW              "$o_window"   "$CONF" || true
    [ -n "$o_hosts" ]    && set_conf FTB_MIN_HOSTS           "$o_hosts"    "$CONF" || true
    [ -n "$o_ports" ]    && set_conf FTB_MIN_PORTS           "$o_ports"    "$CONF" || true
    [ -n "$o_cooldown" ] && set_conf FTB_COOLDOWN            "$o_cooldown" "$CONF" || true
    [ -n "$o_max" ]      && set_conf FTB_MAX_REPORTS_PER_MIN "$o_max"      "$CONF" || true
    [ -n "$o_iports" ]   && set_conf FTB_IGNORE_PORTS         "\"$o_iports\"" "$CONF" || true
    unit > "$UNIT"
    systemctl daemon-reload

    say "$("$BIN" --version </dev/null): проверка связи с нодой"
    if ! (set -a; . "$CONF"; set +a; "$BIN" --selftest </dev/null); then
        systemctl disable --now "$NAME.service" >/dev/null 2>&1 || true
        die "selftest не прошёл — сервис не включён. Повтор проверки: sudo $BIN --selftest"
    fi

    systemctl enable "$NAME.service" >/dev/null 2>&1
    systemctl restart "$NAME.service"
    sleep 3
    if ! systemctl is-active --quiet "$NAME.service"; then
        journalctl -u "$NAME.service" -n 20 --no-pager -o cat || true
        die "сервис не поднялся"
    fi
    journalctl -u "$NAME.service" -n 3 --no-pager -o cat || true
    if grep -q '^FTB_DRY_RUN=1' "$CONF"; then
        say "работает в DRY-RUN: находки только в журнале. Боевой режим: … | sudo bash -s -- --live"
    else
        say "работает: находки уходят в Torrent Blocker ноды → бан, бот, вебхук"
    fi
    say "журнал: journalctl -u $NAME -f    настройки: $CONF"
}

usage() {
cat <<'EOF'
fsnt-torrent-blocker — установка на Remnawave Node

  … | sudo bash                       установить или обновить (боевой режим)
  … | sudo bash -s -- --dry-run       только наблюдать, в ноду не слать
  … | sudo bash -s -- --live          снять dry-run
  … | sudo bash -s -- --uninstall     удалить (добавь --purge — вместе с настройками)

пороги (можно и потом править в /etc/default/fsnt-torrent-blocker):
  --window N        окно наблюдения, сек (по умолчанию 60)
  --min-hosts N     порог: разных адресов назначения за окно (25)
  --min-ports N     порог: разных портов назначения за окно (20)
  --cooldown N      не банить тот же IP чаще, сек (300)
  --max-reports N   предохранитель: отчётов в минуту (10)
  --ignore-ports L  доп. порты назначения через запятую, не считать веером
EOF
}

# set_conf KEY VALUE FILE — заменить строку KEY=… или дописать её; с set -e без ложного выхода
set_conf() {
    if grep -q "^$1=" "$3"; then
        sed -i "s|^$1=.*|$1=$2|" "$3"
    else
        printf '%s=%s\n' "$1" "$2" >> "$3"
    fi
}

say() { printf '\033[1m[fsnt-torrent-blocker]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[fsnt-torrent-blocker] %s\033[0m\n' "$*" >&2; exit 1; }

unit() {
cat <<'EOF'
[Unit]
Description=fsnt-torrent-blocker: torrent fan-out detector for Remnawave Node
After=docker.service network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=-/etc/default/fsnt-torrent-blocker
ExecStart=/usr/local/sbin/fsnt-torrent-blocker
Restart=always
RestartSec=15
Nice=10
CPUQuota=25%
MemoryMax=256M
SyslogIdentifier=fsnt-torrent-blocker

[Install]
WantedBy=multi-user.target
EOF
}

config() {
cat <<'EOF'
# fsnt-torrent-blocker — настройки. После правки: systemctl restart fsnt-torrent-blocker
# Бан (срок, ignoreLists по IP и userId) задаётся в панели, в конфиге плагина Torrent Blocker.

# 1 — только писать находки в журнал, в ноду не отправлять
FTB_DRY_RUN=0
# окно наблюдения, сек
FTB_WINDOW=60
# веер за окно: разных адресов И разных портов назначения
FTB_MIN_HOSTS=25
FTB_MIN_PORTS=20
# не отправлять повторный отчёт на тот же IP чаще, сек
FTB_COOLDOWN=300
# предохранитель: больше отчётов в минуту — отправка встаёт на паузу на 10 минут
FTB_MAX_REPORTS_PER_MIN=10
# доп. порты назначения, не считать веером (через запятую), сверх встроенного списка
FTB_IGNORE_PORTS=
# путь к access-логу xray; пусто — найти самому по конфигу ноды
FTB_LOG=
EOF
}

payload() {
cat <<'FTB_PAYLOAD'
#!/usr/bin/env python3
# fsnt-torrent-blocker — детектор торрент-веера для Remnawave Node
#
# Штатный Torrent Blocker видит только то, что опознал сниффер xray: plaintext-рукопожатие
# BitTorrent по TCP и uTP. Пиры под MSE/PE-шифрованием и DHT проходят мимо. Этот детектор
# ловит веер по access-логу xray — много разных адресов на разных высоких портах за короткое
# окно — и отдаёт находку во внутренний вебхук ноды, тот же, куда пишет сам xray. Дальше всё
# штатно: бан в nftables с blockDuration и ignoreLists из конфига плагина, отчёт в панель,
# уведомление в Telegram, вебхук torrent_blocker.report.

import argparse
import collections
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time

VERSION = '1.0.0'
MARK = 'fsnt-torrent-blocker'


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


AP = argparse.ArgumentParser(prog=MARK, description='детектор торрент-веера для Remnawave Node')
AP.add_argument('--window', type=int, default=env_int('FTB_WINDOW', 60),
                help='окно наблюдения, сек (FTB_WINDOW)')
AP.add_argument('--min-hosts', type=int, default=env_int('FTB_MIN_HOSTS', 25),
                help='порог: разных адресов назначения за окно (FTB_MIN_HOSTS)')
AP.add_argument('--min-ports', type=int, default=env_int('FTB_MIN_PORTS', 20),
                help='порог: разных портов назначения за окно (FTB_MIN_PORTS)')
AP.add_argument('--cooldown', type=int, default=env_int('FTB_COOLDOWN', 300),
                help='не слать повторный отчёт на тот же IP чаще, сек (FTB_COOLDOWN)')
AP.add_argument('--max-reports', type=int, default=env_int('FTB_MAX_REPORTS_PER_MIN', 10),
                help='предохранитель: отчётов в минуту, выше — пауза 10 мин (FTB_MAX_REPORTS_PER_MIN)')
AP.add_argument('--log', default=os.environ.get('FTB_LOG', ''),
                help='путь к access-логу xray; пусто — найти по конфигу ноды (FTB_LOG)')
AP.add_argument('--ignore-ports', default=os.environ.get('FTB_IGNORE_PORTS', ''),
                help='доп. порты назначения, не считать веером — через запятую (FTB_IGNORE_PORTS)')
AP.add_argument('--dry-run', action='store_true', default=os.environ.get('FTB_DRY_RUN', '0') == '1',
                help='только писать находки в журнал, в ноду не отправлять (FTB_DRY_RUN=1)')
AP.add_argument('--selftest', action='store_true', help='проверить связь с нодой без бана и выйти')
AP.add_argument('--version', action='version', version=f'{MARK} {VERSION}')
A = AP.parse_args()

# Порты, где веер к разным адресам — норма, а не торрент. Список подобран по типовому
# легальному трафику (см. README, раздел «Встроенный список портов») и расширяется через
# FTB_IGNORE_PORTS без правки кода. Осознанно НЕ включаем порты, которыми злоупотребляют
# (напр. 3333 — stratum майнинг-пулов): их веер как раз хочется видеть.
COMMON = {
    22,                             # SSH
    53,                             # DNS
    80, 8080,                       # HTTP
    443, 8443,                      # HTTPS / HTTP-over-QUIC
    123,                            # NTP
    465, 587, 993, 995,             # почта: SMTPS, submission, IMAPS, POP3S
    853,                            # DNS-over-TLS
    554,                            # RTSP — потоковое видео и IP-камеры
    1935,                           # RTMP — стриминг
    2002,                           # Roughtime — защищённая синхронизация времени
    5222, 5223, 5228,               # XMPP и push (в т.ч. Google FCM)
    7680,                           # Windows Update Delivery Optimization — P2P-раздача обновлений
}
COMMON |= set(range(3478, 3498))    # STUN/TURN — установка p2p-звонков (WebRTC, мессенджеры)
COMMON |= {5349}                    # STUN/TURN over TLS
COMMON |= set(range(16384, 16404))  # RTP — медиапотоки звонков
COMMON |= set(range(19302, 19310))  # STUN Google (Meet, Hangouts, WebRTC)

# Оператор может расширить список портов, которые не считать веером (FTB_IGNORE_PORTS или
# --ignore-ports): в замерах трафика встречались легальные P2P/сервисы на своих портах (WUDO
# и локальные «сигнатурные» порты нод) — их можно занести сюда, не трогая код.
EXTRA_PORTS = {int(x) for x in re.split(r'[,\s]+', A.ignore_ports.strip()) if x.isdigit()}
COMMON |= EXTRA_PORTS

# Источник xray пишет как "from IP:port" и как "from tcp:IP:port". Назначение берём только
# числовым адресом: пиры идут по голому IP, обычный сёрфинг резолвится в домен. Маршрут в
# скобках бывает со вложенными скобками ("[VLESS TCP REALITY [flow] -> warp-de-2]"), поэтому
# берём всё до последней "]" перед email.
IPV = r'(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:.]+\])'
LINE = re.compile(
    r'from (?:(?:tcp|udp):)?(?P<cip>' + IPV + r'):(?P<cport>\d+) '
    r'accepted (?P<net>tcp|udp):(?P<dst>' + IPV + r'):(?P<dport>\d+) '
    r'\[(?P<route>.*)\]\s*email: (?P<user>\S+)\s*$')
ROUTE_SEP = re.compile(r' (?:==>|->|>>) ')
CONFIG_ARG = re.compile(rb'^(?:@|http\+unix://)')

LOG_CANDIDATES = ['/var/log/remnanode/access/error.log', '/var/log/remnanode/access/access.log',
                  '/var/log/remnanode/access.log', '/var/log/remnanode/error.log',
                  '/var/log/xray/current']


def log(msg):
    print(time.strftime('%Y-%m-%d %H:%M:%SZ ', time.gmtime()) + msg, flush=True)


def read_argv(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            return f.read().split(b'\0')
    except OSError:
        return []


def find_xray():
    """Процесс xray ноды — тот, что берёт конфиг у ноды по unix-сокету. Имя бинаря бывает
    любым (xray, rw-core, замаскированное), поэтому ищем по аргументу -config."""
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        argv = read_argv(d)
        for i, a in enumerate(argv[:-1]):
            if a == b'-config' and CONFIG_ARG.match(argv[i + 1]):
                return int(d), argv[i + 1].decode(errors='replace')
    return None, None


def container_root(pid):
    """Корень файловой системы контейнера ноды. Берём init его pid-namespace: он живёт, пока
    живёт контейнер, а xray перезапускается при каждой смене конфига из панели."""
    try:
        ns = os.readlink(f'/proc/{pid}/ns/pid')
    except OSError:
        return f'/proc/{pid}/root'
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        try:
            if os.readlink(f'/proc/{d}/ns/pid') != ns:
                continue
            with open(f'/proc/{d}/status') as f:
                for line in f:
                    if line.startswith('NSpid:') and line.split()[-1] == '1':
                        return f'/proc/{d}/root'
        except OSError:
            continue
    return f'/proc/{pid}/root'


def endpoint(url, root):
    """Адрес внутреннего API ноды. Поколения ноды отличаются формой:
         @rwint-XXXX:/internal/...                          — абстрактный сокет
         http+unix:///run/remnawave-internal-XXXX.sock/internal/...   — файловый (конфиг)
         //run/remnawave-internal-XXXX.sock:/internal/...   — файловый (вебхук)
    Нода работает в network_mode: host, абстрактный сокет виден с хоста напрямую, а файловый —
    через корень контейнера."""
    m = re.match(r'^@([^:\s]+):(/\S+)$', url)
    if m:
        return '\0' + m.group(1), m.group(2)
    m = re.match(r'^http\+unix://(/[^\s?]*?\.sock)(/\S*)$', url)
    if m:
        return root + m.group(1), m.group(2)
    m = re.match(r'^/*(/[^:\s]+\.sock):(/\S+)$', url)
    if m:
        return root + m.group(1), m.group(2)
    return None


def http(ep, method='GET', body=None, timeout=5):
    sock_path, path = ep
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        head = f'{method} {path} HTTP/1.0\r\nHost: localhost\r\n'
        if body is not None:
            head += f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n'
        s.sendall(head.encode() + b'\r\n' + (body or b''))
        buf = b''
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    if not buf:
        return 0, b''       # неверный токен: нода молча рвёт соединение
    head, _, payload = buf.partition(b'\r\n\r\n')
    try:
        return int(head.split(b'\r\n', 1)[0].split(b' ', 2)[1]), payload
    except (IndexError, ValueError):
        return 0, b''


class Node:
    def __init__(self):
        self.refresh()

    def refresh(self):
        pid, url = find_xray()
        if not pid:
            raise RuntimeError('процесс xray ноды не найден — Remnawave Node не запущена?')
        self.xray_pid = pid
        self.root = container_root(pid)
        ep = endpoint(url, self.root)
        if not ep:
            raise RuntimeError('не разобран адрес конфига xray: ' + url.split('?')[0])
        self.kind = 'абстрактный сокет' if ep[0].startswith('\0') else 'файловый сокет'
        st, payload = http(ep)
        if st != 200:
            raise RuntimeError(f'конфиг xray у ноды не отдаётся (HTTP {st})')
        self.cfg = json.loads(payload)
        self.webhook = None
        for r in self.cfg.get('routing', {}).get('rules', []):
            url = (r.get('webhook') or {}).get('url', '')
            wep = endpoint(url, self.root) if url else None
            if wep:
                self.webhook = wep
                break

    def container_id(self):
        try:
            with open(f'/proc/{self.xray_pid}/cgroup') as f:
                m = re.search(r'[0-9a-f]{64}', f.read())
                return m.group(0) if m else None
        except OSError:
            return None

    def pick_log(self, override=''):
        if override:
            for p in (override, self.root + override):
                if os.path.isfile(p):
                    return p
            raise RuntimeError(f'лог {override} не найден ни на хосте, ни в контейнере')
        lg = self.cfg.get('log') or {}
        if lg.get('access') == 'none':
            raise RuntimeError('access-лог xray выключен (log.access = "none") — читать нечего')
        cands = [lg.get(k) for k in ('access', 'error') if (lg.get(k) or '').startswith('/')]
        cands += [p for p in LOG_CANDIDATES if p not in cands]
        existing = [self.root + p for p in cands if os.path.isfile(self.root + p)]
        for fp in existing:
            if tail_has_access(fp):
                return fp
        if existing:
            return existing[0]      # нода пока без клиентов: берём первый по приоритету
        raise RuntimeError('access-лог xray не найден: задай log.access в профиле или FTB_LOG')


def tail_has_access(path, size=512 * 1024):
    try:
        with open(path, 'rb') as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - size))
            return any(LINE.search(ln.decode('utf-8', 'replace'))
                       for ln in f.read().splitlines()[1:])
    except OSError:
        return False


def follow(node, override):
    """tail -F: s6-log и logrotate ротируют файл (переименование или усечение), а при
    перезапуске контейнера меняется путь через /proc — тогда находим лог заново."""
    path = node.pick_log(override)
    f = open(path, 'rb')
    f.seek(0, 2)
    ino, buf, idle = os.fstat(f.fileno()).st_ino, b'', 0
    log(f'лог: {path}')
    while True:
        chunk = f.read(1 << 16)
        if chunk:
            idle = 0
            buf += chunk
            *lines, buf = buf.split(b'\n')
            for ln in lines:
                yield ln.decode('utf-8', 'replace')
            continue
        time.sleep(0.25)
        idle += 1
        if idle % 8:
            continue
        try:
            st = os.stat(path)
        except OSError:
            st = None
        if st is None:
            f.close()
            for _ in range(24):
                try:
                    node.refresh()
                    path = node.pick_log(override)
                    break
                except (OSError, RuntimeError, ValueError):
                    time.sleep(5)
            else:
                sys.exit('нода не вернулась за 2 минуты')
            f = open(path, 'rb')
            f.seek(0, 2)
            ino, buf = os.fstat(f.fileno()).st_ino, b''
            log(f'нода перезапущена, лог: {path}')
        elif st.st_ino != ino or st.st_size < f.tell():
            f.close()
            f = open(path, 'rb')
            ino, buf = os.fstat(f.fileno()).st_ino, b''


def is_global(ip):
    try:
        return ipaddress.ip_address(ip.strip('[]')).is_global
    except ValueError:
        return False


def make_report(user, cip, cport, net, dst, dport, inbound, summary):
    # Все 13 ключей XrayWebhookSchema обязательны: nullable, но не optional.
    # protocol и outboundTag = MARK — по ним отчёты детектора отличаются от нативных в боте
    # ("Protocol: fsnt-torrent-blocker") и в фильтре отчётов панели.
    return {
        'email': user, 'level': 0, 'protocol': MARK, 'network': net,
        'source': f'{cip}:{cport}', 'destination': f'{dst}:{dport}',
        'routeTarget': summary, 'originalTarget': f'{net}:{dst}:{dport}',
        'inboundTag': inbound or None, 'inboundName': None, 'inboundLocal': None,
        'outboundTag': MARK, 'ts': int(time.time()),
    }


def send(node, report):
    body = json.dumps(report).encode()
    for attempt in (1, 2):
        try:
            if node.webhook:
                st, _ = http(node.webhook, 'POST', body)
                if st == 200:
                    return 'принят нодой'
        except OSError:
            pass
        if attempt == 1:
            try:
                node.refresh()      # нода могла перезапуститься с новым сокетом и токеном
            except (OSError, RuntimeError, ValueError) as e:
                return f'не доставлен: {e}'
    return 'не доставлен: вебхук ноды не отвечает' if node.webhook else \
        'не доставлен: Torrent Blocker выключен'


def selftest():
    ok = True
    try:
        node = Node()
    except (OSError, RuntimeError, ValueError) as e:
        print(f'FAIL  нода: {e}')
        return 1
    print(f'ok    xray pid {node.xray_pid}, API ноды — {node.kind}')
    if not node.webhook:
        print('FAIL  вебхука в конфиге xray нет — включи плагин Torrent Blocker на ноде')
        return 1
    print('ok    вебхук Torrent Blocker найден')
    try:
        path = node.pick_log(A.log)
        seen = tail_has_access(path)
        print(f'ok    лог {path}' + ('' if seen else ' (строк с email пока нет — клиентов нет?)'))
    except RuntimeError as e:
        print(f'FAIL  {e}')
        ok = False
    # email=null проходит схему, но обработчик выходит до бана: проверяем маршрут и токен.
    probe = make_report(None, '192.0.2.1', 1, 'udp', '192.0.2.2', 2, None, 'selftest')
    broken = dict(probe)
    broken.pop('ts')
    t0 = time.time()
    st1, _ = http(node.webhook, 'POST', json.dumps(probe).encode())
    st2, _ = http(node.webhook, 'POST', json.dumps(broken).encode())
    if st1 != 200 or st2 != 200:
        print(f'FAIL  вебхук ответил {st1}/{st2} (0 — токен не принят)')
        return 1
    print('ok    вебхук принимает отчёты (HTTP 200)')
    # Битый отчёт (без ts) нода отвергнет строкой "Invalid webhook" в своём логе. Ровно одна
    # такая строка — значит формат детектора совпадает со схемой, а обработчик живой.
    cid = node.container_id()
    if cid and subprocess.run(['sh', '-c', 'command -v docker'], capture_output=True).returncode == 0:
        time.sleep(1.5)
        since = str(int(t0) - 1)
        out = subprocess.run(['docker', 'logs', '--since', since, cid], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, errors='replace').stdout
        bad = [ln for ln in out.splitlines() if 'Invalid webhook' in ln]
        if len(bad) == 1 and '"ts"' in bad[0]:
            print('ok    обработчик ноды разбирает формат детектора')
        elif not bad:
            print('WARN  отклика обработчика в логе ноды не видно — проверь вручную: docker logs')
        else:
            print('FAIL  формат отчёта не совпал со схемой ноды:\n      ' + bad[0][:300])
            ok = False
    else:
        print('WARN  контейнер ноды не определён — разбор формата не проверен')
    print('итог: ' + ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    if A.selftest:
        sys.exit(selftest())
    try:
        node = Node()
    except (OSError, RuntimeError, ValueError) as e:
        sys.exit(f'нода: {e}')
    if not A.dry_run and not node.webhook:
        sys.exit('вебхука в конфиге xray нет — включи плагин Torrent Blocker на ноде')
    log(f'{MARK} {VERSION}: окно {A.window}с, порог {A.min_hosts} хостов / {A.min_ports} портов, '
        f'API ноды — {node.kind}'
        + (f', +{len(EXTRA_PORTS)} игнор-портов' if EXTRA_PORTS else '')
        + (', DRY-RUN: в ноду не отправляю' if A.dry_run else ''))
    ev = collections.defaultdict(collections.deque)
    last_ip = {}
    sent = collections.deque()
    paused_until = 0
    sweep = time.time()
    for ln in follow(node, A.log):
        m = LINE.search(ln)
        if not m:
            continue
        dport = int(m['dport'])
        if dport in COMMON or not is_global(m['dst']):
            continue
        now = time.time()
        q = ev[m['user']]
        inbound = ROUTE_SEP.split(m['route'])[0].strip()
        q.append((now, m['cip'], int(m['cport']), m['dst'], dport, m['net'], inbound))
        while q and q[0][0] < now - A.window:
            q.popleft()
        if now - sweep > A.window:
            for u in [u for u, d in ev.items() if not d or d[-1][0] < now - A.window]:
                del ev[u]
            sweep = now
        hosts = {x[3] for x in q}
        ports = {x[4] for x in q}
        if len(hosts) < A.min_hosts or len(ports) < A.min_ports:
            continue
        cip = collections.Counter(x[1] for x in q).most_common(1)[0][0]
        if now - last_ip.get(cip, 0) < A.cooldown:
            continue
        last_ip[cip] = now
        nets = collections.Counter(x[5] for x in q)
        ex = next(x for x in reversed(q) if x[1] == cip)
        summary = (f'fanout {len(hosts)} hosts / {len(ports)} ports / {len(q)} conns in '
                   f'{A.window}s (tcp {nets["tcp"]}, udp {nets["udp"]})')
        user = m['user']
        q.clear()
        if A.dry_run:
            log(f'[dry-run] user={user} ip={cip} {summary}')
            continue
        while sent and sent[0] < now - 60:
            sent.popleft()
        if now < paused_until:
            log(f'[пауза] user={user} ip={cip} {summary} — не отправлен')
            continue
        if len(sent) >= A.max_reports:
            paused_until = now + 600
            log(f'ПРЕДОХРАНИТЕЛЬ: {len(sent)} отчётов за минуту — отправка приостановлена на 10 минут. '
                f'Проверь пороги в /etc/default/{MARK}')
            continue
        sent.append(now)
        rep = make_report(user, cip, ex[2], nets.most_common(1)[0][0], ex[3], ex[4], ex[6], summary)
        log(f'user={user} ip={cip} {summary} -> {send(node, rep)}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
FTB_PAYLOAD
}

main "$@"
