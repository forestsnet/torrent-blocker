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
# Ежедневное авто-обновление с GitHub включается по умолчанию (--no-autoupdate отключает).
# Пороги можно задать флагами при установке и потом править в /etc/default/fsnt-torrent-blocker.
# Детектор вшит в этот файл целиком: сборка — ./build.sh из fsnt-torrent-blocker.py.

main() {
    set -euo pipefail
    local NAME=fsnt-torrent-blocker
    local BIN=/usr/local/sbin/$NAME
    local UNIT=/etc/systemd/system/$NAME.service
    local CONF=/etc/default/$NAME
    local BTG_NFT=/etc/nftables.d/btguard.nft
    local BTG_UNIT=/etc/systemd/system/btguard.service
    local UPD_BIN=/usr/local/sbin/$NAME-update
    local UPD_SVC=/etc/systemd/system/$NAME-update.service
    local UPD_TIMER=/etc/systemd/system/$NAME-update.timer
    local MODE=install DRY="" PURGE=0 BTG=1 AU=1
    local o_window="" o_hosts="" o_ports="" o_cooldown="" o_max="" o_iports="" o_inets=""

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
            --ignore-nets)    shift; o_inets=${1-} ;;
            --ignore-nets=*)  o_inets=${1#*=} ;;
            --no-btguard)   BTG=0 ;;
            --no-autoupdate) AU=0 ;;
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
        systemctl disable --now btguard.service >/dev/null 2>&1 || true
        systemctl disable --now "$NAME-update.timer" >/dev/null 2>&1 || true
        command -v nft >/dev/null && { nft delete table ip btguard 2>/dev/null; nft delete table ip6 btguard6 2>/dev/null; } || true
        rm -f "$BIN" "$UNIT" "$BTG_UNIT" "$BTG_NFT" "$UPD_BIN" "$UPD_SVC" "$UPD_TIMER"
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

    if [ "$BTG" = 1 ]; then
        if command -v nft >/dev/null; then
            install -d -m 0755 /etc/nftables.d
            btguard_nft > "$TMP/btguard.nft"
            if nft -c -f "$TMP/btguard.nft" 2>/dev/null; then
                install -m 0644 "$TMP/btguard.nft" "$BTG_NFT"
                btguard_unit > "$BTG_UNIT"
                systemctl daemon-reload
                systemctl enable btguard.service >/dev/null 2>&1
                systemctl restart btguard.service
                if nft list table ip btguard >/dev/null 2>&1; then
                    say "btguard: nft-дроп DHT/uTP/tracker активен"
                else
                    say "btguard: nft-таблица не загрузилась — детектор пойдёт без корреляции"
                fi
            else
                say "btguard: правила не прошли nft -c — пропускаю"
            fi
        else
            say "btguard: нет команды nft — пропускаю (детектор работает по вееру)"
        fi
    fi

    if [ "$AU" = 1 ] && command -v curl >/dev/null; then
        update_script > "$UPD_BIN"; chmod 0755 "$UPD_BIN"
        update_service > "$UPD_SVC"
        update_timer > "$UPD_TIMER"
        systemctl daemon-reload
        systemctl enable --now "$NAME-update.timer" >/dev/null 2>&1
        say "авто-обновление с GitHub: вкл (ежедневно). Выкл: systemctl disable --now $NAME-update.timer"
    elif [ "$AU" = 1 ]; then
        say "авто-обновление: нет curl — пропускаю"
    fi

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
    [ -n "$o_inets" ]    && set_conf FTB_IGNORE_NETS          "\"$o_inets\""  "$CONF" || true
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
        say "работает: веер + btguard → Torrent Blocker ноды → бан, бот, вебхук"
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
  --ignore-nets L   доп. сети CIDR через запятую, не считать веером (сверх игровых)
  --no-btguard      не ставить nft-дроп btguard (только веерный детект по логу)
  --no-autoupdate   не включать ежедневное авто-обновление с GitHub
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

update_script() {
cat <<'EOF'
#!/usr/bin/env bash
# Авто-обновление fsnt-torrent-blocker с GitHub. Тянет свежий install.sh, сверяет версию,
# при отличии — переустанавливает (конфиг /etc/default сохраняется). Битую загрузку и
# недоступность GitHub переживает молча (exit 0), сервис не трогает.
set -euo pipefail
RAW="https://raw.githubusercontent.com/forestsnet/torrent-blocker/main/install.sh"
BIN=/usr/local/sbin/fsnt-torrent-blocker
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
curl -fsSL --max-time 90 "$RAW" -o "$TMP" || { echo "update: GitHub недоступен"; exit 0; }
bash -n "$TMP" 2>/dev/null || { echo "update: загруженный installer невалиден — пропуск"; exit 0; }
grep -q "FTB_PAYLOAD" "$TMP" || { echo "update: installer без payload — пропуск"; exit 0; }
remote="$(grep -m1 "^VERSION = '" "$TMP" | sed "s/.*VERSION = '\([^']*\)'.*/\1/")"
local="$("$BIN" --version 2>/dev/null | awk '{print $2}')"
[ -z "$remote" ] && { echo "update: версия из installer не прочитана — пропуск"; exit 0; }
if [ "$remote" = "$local" ]; then
    echo "update: уже $local — актуально"; exit 0
fi
# обновляем ТОЛЬКО если удалённая строго новее (устаревший кэш GitHub иначе откатил бы версию)
newest="$(printf '%s\n%s\n' "$local" "$remote" | sort -V | tail -1)"
if [ "$newest" != "$remote" ]; then
    echo "update: локальная $local не старше удалённой $remote (кэш GitHub?) — пропуск"; exit 0
fi
echo "update: $local -> $remote, обновляю"
bash "$TMP"        # реинсталл; существующий конфиг сохраняется
EOF
}

update_service() {
cat <<'EOF'
[Unit]
Description=fsnt-torrent-blocker auto-update from GitHub
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fsnt-torrent-blocker-update
SyslogIdentifier=fsnt-torrent-blocker-update
EOF
}

update_timer() {
cat <<'EOF'
[Unit]
Description=Daily fsnt-torrent-blocker auto-update

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

btguard_unit() {
cat <<'EOF'
[Unit]
Description=btguard: drop torrent UDP control-plane (DHT/uTP/tracker)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/btguard.nft
ExecReload=/usr/sbin/nft -f /etc/nftables.d/btguard.nft
ExecStop=-/usr/sbin/nft delete table ip btguard
ExecStop=-/usr/sbin/nft delete table ip6 btguard6

[Install]
WantedBy=multi-user.target
EOF
}

btguard_nft() {
cat <<'BTG_PAYLOAD'
#!/usr/sbin/nft -f
# 2026-09-23 — дроп UDP-контрплана торрента по строгим сигнатурам
#
# Ловит то, что штатный сниффер xray пропускает по UDP: DHT (BEP 5), uTP-хендшейк
# (BEP 29) и connect к UDP-трекеру (BEP 15). Шифрованные MSE/PE-пиры сигнатуры не
# имеют — их добирает веерный детектор fsnt-torrent-blocker.
#
# Сигнатуры ужесточены по логике форка Jolymmiles/Xray-core (dht.go/udp_tracker.go,
# SniffUTP): строгие поля вместо префиксных матчей. На проде это критично — наивный
# uTP-матч 0x4100 ловит TURN/WebRTC-медиа (в замере 176 ложных пак/90с), строгий — 0.
# Логи rate-limited (иначе строка на пакет = флуд). Дроп только на выходе: рвём
# способность клиента искать пиров, вход не трогаем.

table ip btguard
delete table ip btguard
table ip btguard {
	counter dht     { }
	counter utp     { }
	counter tracker { }

	chain output {
		type filter hook output priority filter - 5; policy accept;

		# --- rate-limited лог (без вердикта, проваливается дальше) ---
		# DHT-запрос "d1:ad2:id20:" и ответ "d1:rd2:id20:" — словарь с 20-байтным node id
		meta l4proto udp @th,64,96 == 0x64313a6164323a696432303a \
			limit rate 30/minute burst 10 packets log prefix "btguard-dht: "
		meta l4proto udp @th,64,96 == 0x64313a7264323a696432303a \
			limit rate 30/minute burst 10 packets log prefix "btguard-dht: "
		# UDP-tracker connect (BEP 15): magic + action(байты 8-11)=0
		meta l4proto udp @th,64,64 == 0x0000041727101980 @th,128,32 == 0x00000000 \
			limit rate 30/minute burst 10 packets log prefix "btguard-tracker: "
		# uTP ST_SYN (BEP 29): 0x41, ext0, conn-id!=0, timestamp-diff=0, seq=1
		meta l4proto udp @th,64,16 == 0x4100 @th,80,16 != 0x0000 \
			@th,128,32 == 0x00000000 @th,192,16 == 0x0001 \
			limit rate 30/minute burst 10 packets log prefix "btguard-utp: "

		# --- дроп + счётчик (все совпавшие пакеты) ---
		meta l4proto udp @th,64,96 == 0x64313a6164323a696432303a counter name "dht" drop
		meta l4proto udp @th,64,96 == 0x64313a7264323a696432303a counter name "dht" drop
		meta l4proto udp @th,64,64 == 0x0000041727101980 @th,128,32 == 0x00000000 \
			counter name "tracker" drop
		meta l4proto udp @th,64,16 == 0x4100 @th,80,16 != 0x0000 \
			@th,128,32 == 0x00000000 @th,192,16 == 0x0001 counter name "utp" drop
	}
}

table ip6 btguard6
delete table ip6 btguard6
table ip6 btguard6 {
	counter dht { }
	counter utp { }
	chain output {
		type filter hook output priority filter - 5; policy accept;
		meta l4proto udp @th,64,96 == 0x64313a6164323a696432303a counter name "dht" drop
		meta l4proto udp @th,64,96 == 0x64313a7264323a696432303a counter name "dht" drop
		meta l4proto udp @th,64,16 == 0x4100 @th,80,16 != 0x0000 \
			@th,128,32 == 0x00000000 @th,192,16 == 0x0001 counter name "utp" drop
	}
}
BTG_PAYLOAD
}

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
# коррелировать дропы btguard с клиентами и репортить: auto (если таблица есть) / on / off
FTB_BTGUARD=auto
# доп. порты назначения, не считать веером (через запятую), сверх встроенного списка
FTB_IGNORE_PORTS=
# доп. сети CIDR, не считать веером (через запятую), сверх встроенных игровых (Valve/Blizzard/Riot)
FTB_IGNORE_NETS=
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
import bisect
import collections
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

VERSION = '2.2.2'
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
AP.add_argument('--min-ports', type=int, default=env_int('FTB_MIN_PORTS', 25),
                help='порог: разных портов назначения за окно (FTB_MIN_PORTS)')
AP.add_argument('--cooldown', type=int, default=env_int('FTB_COOLDOWN', 300),
                help='не слать повторный отчёт на тот же IP чаще, сек (FTB_COOLDOWN)')
AP.add_argument('--max-reports', type=int, default=env_int('FTB_MAX_REPORTS_PER_MIN', 10),
                help='предохранитель: отчётов в минуту, выше — пауза 10 мин (FTB_MAX_REPORTS_PER_MIN)')
AP.add_argument('--log', default=os.environ.get('FTB_LOG', ''),
                help='путь к access-логу xray; пусто — найти по конфигу ноды (FTB_LOG)')
AP.add_argument('--ignore-ports', default=os.environ.get('FTB_IGNORE_PORTS', ''),
                help='доп. порты назначения, не считать веером — через запятую (FTB_IGNORE_PORTS)')
AP.add_argument('--ignore-nets', default=os.environ.get('FTB_IGNORE_NETS', ''),
                help='доп. сети (CIDR через запятую), не считать веером — сверх встроенных игровых (FTB_IGNORE_NETS)')
AP.add_argument('--btguard', choices=['auto', 'on', 'off'], default=os.environ.get('FTB_BTGUARD', 'auto'),
                help='коррелировать дропы nft-таблицы btguard с клиентами и репортить (FTB_BTGUARD)')
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
COMMON |= set(range(19302, 19320))  # STUN/медиа Google (Meet, WebRTC; наблюдали 19314/19316)
COMMON |= set(range(27000, 27201))  # Steam Datagram Relay и игровые серверы Valve (Dota и др.)

# Оператор может расширить список портов, которые не считать веером (FTB_IGNORE_PORTS или
# --ignore-ports): в замерах трафика встречались легальные P2P/сервисы на своих портах (WUDO
# и локальные «сигнатурные» порты нод) — их можно занести сюда, не трогая код.
EXTRA_PORTS = {int(x) for x in re.split(r'[,\s]+', A.ignore_ports.strip()) if x.isdigit()}
COMMON |= EXTRA_PORTS


# Игровые сети (Valve/Steam, Blizzard, Riot): их UDP — релейный веер, неотличимый от
# торрента по порогу (Steam Datagram Relay бьёт по десяткам релеев на разных портах).
# Собрано из BGP-анонсов AS32590/AS57976/AS6507 (RIPEstat), схлопнуто. Расширяется через
# FTB_IGNORE_NETS. Торрент к этим сетям не ходит, так что вырезать их из счёта безопасно.
GAME_NETS = """
5.42.160.0/20
5.42.176.0/22
24.105.0.0/22
24.105.16.0/22
24.105.25.0/24
24.105.27.0/24
24.105.28.0/22
24.105.32.0/20
24.105.50.0/23
24.105.52.0/22
24.105.56.0/23
24.105.59.0/24
24.105.60.0/22
37.244.0.0/24
37.244.2.0/23
37.244.4.0/22
37.244.8.0/23
37.244.10.0/24
37.244.13.0/24
37.244.14.0/23
37.244.16.0/23
37.244.19.0/24
37.244.20.0/24
37.244.23.0/24
37.244.24.0/21
37.244.32.0/22
37.244.36.0/23
37.244.38.0/24
37.244.40.0/21
37.244.50.0/24
37.244.52.0/22
37.244.56.0/21
43.229.64.0/22
45.7.36.0/22
45.121.184.0/24
45.250.208.0/22
59.153.40.0/22
64.224.0.0/21
64.224.24.0/21
66.40.176.0/20
103.4.114.0/23
103.10.124.0/23
103.28.54.0/24
103.198.32.0/23
103.219.128.0/22
103.240.224.0/22
104.160.128.0/19
117.52.6.0/24
117.52.26.0/23
117.52.28.0/23
117.52.33.0/24
117.52.34.0/23
117.52.36.0/23
121.254.137.0/24
121.254.206.0/23
121.254.218.0/24
137.221.64.0/19
137.221.96.0/20
137.221.112.0/24
138.0.12.0/22
146.66.152.0/24
146.66.155.0/24
150.116.9.0/24
151.106.246.0/23
151.106.248.0/22
151.106.252.0/23
151.106.254.0/24
155.133.224.0/21
155.133.236.0/22
155.133.240.0/23
155.133.244.0/24
155.133.246.0/24
155.133.248.0/22
155.133.252.0/24
155.133.254.0/23
158.115.192.0/20
158.115.216.0/21
162.249.72.0/21
162.254.192.0/21
182.162.31.0/24
185.25.180.0/24
185.25.182.0/23
185.40.64.0/22
185.60.112.0/22
192.64.168.0/21
192.69.96.0/22
192.207.0.0/24
198.74.32.0/22
198.74.36.0/23
202.9.66.0/23
205.196.6.0/24
208.64.200.0/22
208.78.164.0/22
2404:3fc0::/46
2404:3fc0:8::/47
2404:3fc0:a::/48
2602:801:f000::/46
2602:801:f005::/48
2602:801:f006::/47
2602:801:f008::/46
2602:801:f00d::/48
2602:801:f00e::/48
2a01:bc80::/45
2a01:bc80:8::/46
2a01:bc80:c::/48
2a04:82c0::/29
2a04:e800:5010::/47
2a04:e800:5014::/48
2a04:e800:5016::/48
2a04:e800:5020::/48
2a04:e800:5023::/48
2a04:e800:5040::/48
2a04:e800:5407::/48
2a04:e802::/32
"""


class NetMatch:
    """Быстрая проверка принадлежности IP игнор-сетям: слитые int-диапазоны + bisect."""

    def __init__(self, cidrs):
        v4, v6 = [], []
        for c in cidrs:
            c = c.strip()
            if not c:
                continue
            try:
                n = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            (v4 if n.version == 4 else v6).append((int(n.network_address), int(n.broadcast_address)))
        self.v4 = self._merge(v4)
        self.v6 = self._merge(v6)
        self.v4s = [a for a, _ in self.v4]
        self.v6s = [a for a, _ in self.v6]

    @staticmethod
    def _merge(ranges):
        ranges.sort()
        out = []
        for a, b in ranges:
            if out and a <= out[-1][1] + 1:
                out[-1] = (out[-1][0], max(out[-1][1], b))
            else:
                out.append((a, b))
        return out

    def __contains__(self, ip):
        try:
            a = ipaddress.ip_address(ip.strip('[]'))
        except ValueError:
            return False
        arr, starts = (self.v4, self.v4s) if a.version == 4 else (self.v6, self.v6s)
        i = bisect.bisect_right(starts, int(a)) - 1
        return i >= 0 and arr[i][0] <= int(a) <= arr[i][1]

    def __len__(self):
        return len(self.v4) + len(self.v6)


IGNORE_NETS = NetMatch(GAME_NETS.split() + re.split(r'[,\s]+', A.ignore_nets.strip()))

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

# nft-таблица btguard дропает UDP-контрплан торрента (DHT/uTP/tracker) и логирует пир в
# kernel-лог. Клиента там нет (пакет уже на выходе, после SNAT), но тот же поток есть в
# access-логе как "udp:<пир>:<порт> email:<клиент>". peer_index держит эту привязку.
BTG_LINE = re.compile(r'btguard-(?P<kind>dht|utp|tracker):.*?\bDST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3})'
                      r'.*?\bDPT=(?P<dpt>\d+)')
PINDEX_TTL = 300
peer_index = {}
pindex_lock = threading.Lock()

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


class Reporter:
    """Общий бан-пайплайн для обоих сигналов (веер и btguard): кулдаун на клиента,
    предохранитель отчётов/мин и отправка в вебхук — под одним локом, потокобезопасно."""

    def __init__(self, node):
        self.node = node
        self.lock = threading.Lock()
        self.last_ip = {}
        self.sent = collections.deque()
        self.paused_until = 0

    def report(self, user, cip, cport, net, dst, dport, inbound, summary, tag, detail=''):
        now = time.time()
        with self.lock:
            if now - self.last_ip.get(cip, 0) < A.cooldown:
                return None
            self.last_ip[cip] = now
            if A.dry_run:
                log(f'[dry-run:{tag}] user={user} ip={cip} {summary}'
                    + (f' | {detail}' if detail else ''))
                return 'dry-run'
            while self.sent and self.sent[0] < now - 60:
                self.sent.popleft()
            if now < self.paused_until:
                log(f'[пауза:{tag}] user={user} ip={cip} {summary} — не отправлен')
                return None
            if len(self.sent) >= A.max_reports:
                self.paused_until = now + 600
                log(f'ПРЕДОХРАНИТЕЛЬ: {len(self.sent)} отчётов/мин — отправка на паузе 10 минут. '
                    f'Пороги в /etc/default/{MARK}')
                return None
            self.sent.append(now)
            rep = make_report(user, cip, cport, net, dst, dport, inbound, summary)
            st = send(self.node, rep)
            log(f'[{tag}] user={user} ip={cip} {summary} -> {st}'
                + (f' | {detail}' if detail else ''))
            return st


def btguard_enabled():
    if A.btguard == 'off':
        return False
    if A.btguard == 'on':
        return True
    try:
        r = subprocess.run(['nft', 'list', 'table', 'ip', 'btguard'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except OSError:
        return False


def watch_btguard(reporter):
    """Второй сигнал: kernel-лог дропов btguard -> клиент из peer_index -> тот же вебхук.
    Ловит UDP-контрплан торрента с точной привязкой к клиенту, дополняя веерный детект."""
    try:
        p = subprocess.Popen(['journalctl', '-kf', '-o', 'cat', '--no-pager', '-n', '0'],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, errors='replace')
    except OSError as e:
        log(f'btguard: journalctl недоступен ({e}) — корреляция выключена')
        return
    for ln in p.stdout:
        m = BTG_LINE.search(ln)
        if not m:
            continue
        key = (m['dst'], int(m['dpt']))
        with pindex_lock:
            hit = peer_index.get(key)
        if not hit or time.time() - hit[2] > PINDEX_TTL:
            continue                       # к клиенту не привязали — пропускаем
        reporter.report(hit[0], hit[1], 0, 'udp', m['dst'], int(m['dpt']), None,
                        f'btguard {m["kind"]} udp:{m["dst"]}:{m["dpt"]}', m['kind'])


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

    reporter = Reporter(node)
    btg = btguard_enabled()
    log(f'{MARK} {VERSION}: окно {A.window}с, порог {A.min_hosts} хостов / {A.min_ports} портов, '
        f'API ноды — {node.kind}'
        + (f', +{len(EXTRA_PORTS)} игнор-портов' if EXTRA_PORTS else '')
        + (f', {len(IGNORE_NETS)} игнор-сетей' if len(IGNORE_NETS) else '')
        + (', btguard: вкл' if btg else ', btguard: выкл')
        + (', DRY-RUN: в ноду не отправляю' if A.dry_run else ''))
    if btg:
        threading.Thread(target=watch_btguard, args=(reporter,), daemon=True).start()

    ev = collections.defaultdict(collections.deque)
    ev_gi = collections.defaultdict(collections.deque)   # игровые (игнор) соединения — для доказательства
    sweep = prune = time.time()
    for ln in follow(node, A.log):
        m = LINE.search(ln)
        if not m:
            continue
        now = time.time()
        dst, dport, net = m['dst'], int(m['dport']), m['net']
        ign = dst in IGNORE_NETS       # игровая/доверенная сеть — не считаем веером

        # индекс пир->клиент для корреляции с btguard: UDP, до фильтра COMMON, кроме игровых сетей
        if btg and net == 'udp' and not ign and is_global(dst):
            with pindex_lock:
                peer_index[(dst, dport)] = (m['user'], m['cip'], now)
                if now - prune > 60:
                    cut = now - PINDEX_TTL
                    for k in [k for k, v in peer_index.items() if v[2] < cut]:
                        del peer_index[k]
                    prune = now

        # учёт соединений в игровые сети — доказательство в отчёте (сколько срезано)
        if ign and net == 'udp':
            gq = ev_gi[m['user']]
            gq.append(now)
            while gq and gq[0] < now - A.window:
                gq.popleft()

        # веерный детект
        if ign or dport in COMMON or not is_global(dst):
            continue
        q = ev[m['user']]
        inbound = ROUTE_SEP.split(m['route'])[0].strip()
        q.append((now, m['cip'], int(m['cport']), dst, dport, net, inbound))
        while q and q[0][0] < now - A.window:
            q.popleft()
        if now - sweep > A.window:
            for u in [u for u, d in ev.items() if not d or d[-1][0] < now - A.window]:
                del ev[u]
            for u in [u for u, d in ev_gi.items() if not d or d[-1][0] < now - A.window]:
                del ev_gi[u]
            sweep = now
        hosts = {x[3] for x in q}
        ports = {x[4] for x in q}
        if len(hosts) < A.min_hosts or len(ports) < A.min_ports:
            continue
        cip = collections.Counter(x[1] for x in q).most_common(1)[0][0]
        nets = collections.Counter(x[5] for x in q)
        ex = next(x for x in reversed(q) if x[1] == cip)
        gq = ev_gi.get(m['user'])
        if gq:
            while gq and gq[0] < now - A.window:
                gq.popleft()
        gi = len(gq) if gq else 0
        sample = list(dict.fromkeys(f'{x[3]}:{x[4]}' for x in q))[:4]
        summary = (f'fanout {len(hosts)} hosts / {len(ports)} ports / {len(q)} conns in '
                   f'{A.window}s (tcp {nets["tcp"]}, udp {nets["udp"]})')
        detail = f'игр.игнор={gi} пиры: {", ".join(sample)}'
        if reporter.report(m['user'], cip, ex[2], nets.most_common(1)[0][0],
                           ex[3], ex[4], ex[6], summary, 'веер', detail) is not None:
            q.clear()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
FTB_PAYLOAD
}

main "$@"
