#!/usr/bin/env bash
# =============================================================================
#  php2shell-audit.sh  ·  v1.2 (IoC-Stand 23.10.2026)
#
#  PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
#  Verwundbarkeits- und Kompromittierungs-Check für Laravel-Forge-Server
#  (Ubuntu · Nginx · PHP-FPM · klassische Sites + Zero-Downtime-Deployments)
#
#  - erkennt alle Sites automatisch (Nginx-Configs + /home/*/*)
#  - rein lesend, verändert nichts am System
#  - führt keinen Code aus Web-Verzeichnissen als root aus
#    (git läuft als Site-Owner mit deaktivierten Hooks/fsmonitor)
#
#  Aufruf:  sudo bash php2shell-audit.sh
#  Env:     SINCE=2026-08-01    Beginn Prüfzeitraum
#           TOL_MIN=120         Toleranz (Min.) nach Composer-Lauf für Build-Schritte
#           MAXLIST=15          max. Detailzeilen je Befund
#           REPORT=/pfad.log    Report-Datei (Default: /root/php2shell-audit-<host>-<ts>.log)
#  Exit:    0 unauffällig · 1 Versuche/Prüfpunkte · 2 kritisch/verwundbar · 3 Fehler
# =============================================================================

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "Bash >= 4 erforderlich" >&2; exit 3
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Bitte als root ausführen: sudo bash $0" >&2; exit 3
fi

export LC_ALL=C GIT_TERMINAL_PROMPT=0
umask 077
renice -n 15 -p $$ >/dev/null 2>&1
ionice -c3 -p $$ >/dev/null 2>&1

SINCE_IN="${SINCE:-2026-08-01}"
SINCE_EPOCH=$(date -d "$SINCE_IN" +%s 2>/dev/null) || { echo "Ungültiges SINCE: $SINCE_IN" >&2; exit 3; }
SINCE=$(date -d "@$SINCE_EPOCH" +%F)
TOL_MIN="${TOL_MIN:-120}"
MAXLIST="${MAXLIST:-15}"
HOST="$(hostname -f 2>/dev/null || hostname)"
REPORT="${REPORT:-/root/php2shell-audit-$(hostname -s)-$(date +%Y%m%d-%H%M%S).log}"
PROV_EPOCH=0
for cand in \
  "$(head -n1 /var/log/cloud-init.log 2>/dev/null | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}' | xargs -r -I{} date -d '{}' +%s 2>/dev/null)" \
  "$(stat -c %Z /etc/ssh/ssh_host_ed25519_key 2>/dev/null)"; do
  [ -n "$cand" ] && [ "$cand" -gt 0 ] 2>/dev/null && { [ "$PROV_EPOCH" -eq 0 ] || [ "$cand" -lt "$PROV_EPOCH" ]; } && PROV_EPOCH=$cand
done
PROV_END=$(( PROV_EPOCH + 86400 ))
SINCE_ADJ=0
if [ "$PROV_EPOCH" -gt "$SINCE_EPOCH" ]; then SINCE_EPOCH=$(date -d "$(date -d "@$PROV_EPOCH" +%F)" +%s); SINCE=$(date -d "@$SINCE_EPOCH" +%F); SINCE_ADJ=1; fi
TMPD="$(mktemp -d /root/.p2s-audit.XXXXXX)" || exit 3
trap 'rm -rf "$TMPD"' EXIT
TMPREF="$TMPD/ref"

if [ -t 1 ]; then
  R=$'\e[1;31m'; Y=$'\e[1;33m'; G=$'\e[1;32m'; B=$'\e[1;34m'; C=$'\e[1;36m'; N=$'\e[0m'
else
  R=""; Y=""; G=""; B=""; C=""; N=""
fi
exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' > "$REPORT")) 2>&1

# ----------------------------------------------------------------------------
#  IoCs & Referenzwerte (Quellen: PHP-Advisories, ELLIO, AWS/MadPot, Sophos, Splunk)
# ----------------------------------------------------------------------------
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
IOC_UA='php2shell|php-session-startup-rce-poc'
IOC_SRC_IPS=(103.216.220.92 31.223.184.166 37.19.200.5 134.209.159.64 103.114.163.188 95.217.98.37
             45.198.224.169 176.65.132.128 152.233.51.47 146.70.202.189 185.5.70.233 122.97.242.167
             192.140.154.1 47.238.232.123 31.182.51.55 98.80.11.91 200.119.44.50 45.136.71.89
             34.136.122.211 77.237.246.73 146.70.184.216 38.207.136.217)
IOC_C2_IPS=(134.199.154.64 117.55.202.115 92.118.112.100 150.251.112.208 15.235.206.16)
IOC_C2_PORTS=" 50217 50341 50488 50613 50792 50904 51127 51289 51456 51603 51871 52134 52398 52645 "
IOC_HASHES=" 0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486
 7133612558a5d0f257ca6bdb4f765453af9465bc5298acdcf33b5761b8c59aac
 dd98bf48899aa385035352688357742c73ddc5e47ec4ecc7d7b74c53c2e3ca3d
 17758cf05e3376f8448dff926564e038b763b4a46668455e2ccb5ac0839e629c "
IOC_STRINGS='JACKALPOC|P2SMARK|P2SMK[A-Za-z]|PHP2SHELL_OK|godofthunder\.st|botlesscucks\.st|134\.199\.154\.64|117\.55\.202\.115|92\.118\.112\.100|150\.251\.112\.208|15\.235\.206\.16'
IOC_FILES_ALT='shell\.php|shell\.phtml|shell\.php5|shell\.php\.jpg|1\.aspx|bot\.x86_64|test_beacon'
IOC_FILES_RE="^(${IOC_FILES_ALT})$"
IOC_PROCNAMES='telnetd|udhcpc|upnpd|watchdog|syslogd|klogd|uhttpd|uchttpd'
IOC_SESSIDS='attacksessionid|leaksessionid|nuclei'

join_re() { local IFS='|'; local s="$*"; echo "${s//./\\.}"; }
SRC_IP_RE=$(join_re "${IOC_SRC_IPS[@]}")
C2_IP_RE=$(join_re "${IOC_C2_IPS[@]}")

# Webshell-Muster (PCRE) + IoC-Strings
WS_CORE='\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)\s*\(\s*@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|\$_(GET|POST|REQUEST|COOKIE|FILES))|\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\(|`\s*\$_(GET|POST|REQUEST|COOKIE)'
SCAN_RE="(?i)(${WS_CORE})|${IOC_STRINGS}"
GREP_PHP_INC=(--include='*.php' --include='*.phtml' --include='*.phar' --include='*.php[0-9]' --include='*.pht' --include='*.phps' --include='*.inc')
FIND_PHPISH=( \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' -o -iname '*.pht' -o -iname '*.phps' \) )

# Log-Marker
PARSER_RE='Input variables exceeded|Input variable nesting level exceeded|Multipart body parts limit exceeded|Maximum number of allowable file uploads|Allowed memory size of [0-9]+ bytes exhausted.*in Unknown on line 0|session id is too long or contains illegal characters|Missing boundary in multipart'
OOM_RE='Allowed memory size of [0-9]+ bytes exhausted'
CRASH_RE='upstream prematurely closed|recv\(\) failed \(104'
BODY_RE='client intended to send too large body'

# PHP-Aufrufe als root: niemals auto_prepend/auto_append ausführen
PHPSAFE=(-n -d display_errors=0)
PHPINI=(-d auto_prepend_file= -d auto_append_file= -d display_errors=0)

# ----------------------------------------------------------------------------
#  Ausgabe / Befunde
# ----------------------------------------------------------------------------
declare -a L_CRIT=() L_VULN=() L_ATT=() L_REV=() L_COV=()
declare -A LOG_DONE=()
CUR=""
crit() { L_CRIT+=("${CUR:+[$CUR] }$*"); printf '  %s[KRITISCH]%s %s\n'   "$R" "$N" "$*"; }
vuln() { L_VULN+=("${CUR:+[$CUR] }$*"); printf '  %s[VERWUNDBAR]%s %s\n' "$R" "$N" "$*"; }
att()  { L_ATT+=("${CUR:+[$CUR] }$*");  printf '  %s[VERSUCH]%s %s\n'    "$Y" "$N" "$*"; }
rev()  { L_REV+=("${CUR:+[$CUR] }$*");  printf '  %s[PRÜFEN]%s %s\n'     "$Y" "$N" "$*"; }
QUIET=0
ok()   { [ "$QUIET" = 1 ] || printf '  %s[OK]%s %s\n'   "$G" "$N" "$*"; }
info() { [ "$QUIET" = 1 ] || printf '  %s[INFO]%s %s\n' "$B" "$N" "$*"; }
sect() { printf '\n%s==== %s ====%s\n' "$C" "$*" "$N"; }
sub()  { printf '\n %s--- %s ---%s\n' "$C" "$*" "$N"; }
det()  { cut -c1-240 | awk -v m="$MAXLIST" 'NF{n++; if(n<=m) print "        " $0}
         END{if(n>m) print "        … (+" n-m " weitere – MAXLIST=1000 für alle)"}'; }
cnt()  { [ -z "$1" ] && echo 0 || printf '%s\n' "$1" | grep -c .; }
in_since() { [ -n "$1" ] && [ "$1" -ge "$SINCE_EPOCH" ]; }
is_elf() { [ "$(head -c4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }
sha() { sha256sum -- "$1" 2>/dev/null | awk '{print $1}'; }
pkg_owner() { local f=$1 o r
  for o in "$f" "${f#/usr}" "/usr$f"; do
    r=$(dpkg -S "${o//\\/\\\\}" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1); [ -n "$r" ] && { echo "$r"; return 0; }
  done; return 1; }
pkg_clean() { # 0 = Datei gehört zu einem Paket und ist unverändert
  local f=$1 pkg; pkg=$(pkg_owner "$f") || return 1; [ -n "$pkg" ] || return 1
  ! dpkg --verify "$pkg" 2>/dev/null | grep -qE " (${f}|${f#/usr}|/usr${f})$"; }
report_changed() { # $1 Titel; stdin: Pfade (optional " (Zusatz)")
  local title=$1 line f c early="" late=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    f="${line%% (*}"; c=$(stat -c %Z -- "$f" 2>/dev/null) || c=0
    line="$line · $(date -d "@$c" '+%F %T')"
    if [ "$PROV_EPOCH" -gt 0 ] && [ "$c" -ge "$PROV_EPOCH" ] && [ "$c" -lt "$PROV_END" ]; then early+="$line"$'\n'; else late+="$line"$'\n'; fi
  done
  [ -n "$late" ]  && { rev "$title:"; printf '%s' "$late" | det; }
  [ -n "$early" ] && { info "$title – während der Provisionierung:"; printf '%s' "$early" | det; }
  return 0
}
not_pkg_clean() { local f; while IFS= read -r f; do [ -n "$f" ] && ! pkg_clean "$f" && echo "$f"; done; }
ioc_hash() { local h; h=$(sha "$1"); [ -n "$h" ] && [[ "$IOC_HASHES" == *" $h"* ]]; }

# Datum je Zeile extrahieren (nginx YYYY/MM/DD, ISO, [DD-Mon-YYYY, [DD/Mon/YYYY) → Zähler je Tag ≥ SINCE
perday() {
  awk -v s="$SINCE" '
  BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",m," ");for(i=1;i<=12;i++)M[m[i]]=sprintf("%02d",i)}
  { d=""
    a=match($0,/[0-9][0-9][0-9][0-9][-\/][0-9][0-9][-\/][0-9][0-9]/); ra=RSTART
    b=match($0,/[0-9][0-9][-\/][A-Z][a-z][a-z][-\/][0-9][0-9][0-9][0-9]/); rb=RSTART
    if (a && (!b || ra<rb)) { d=substr($0,ra,10); gsub(/\//,"-",d) }
    else if (b) { t=substr($0,rb,11); d=substr(t,8,4) "-" M[substr(t,4,3)] "-" substr(t,1,2) }
    if (d!="" && d>=s) c[d]++ }
  END{ for (k in c) print k ": " c[k] }' | sort
}
sumday() { awk '{s+=$2} END{print s+0}'; }
since_lines() {
  awk -v s="$SINCE" '
  BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",m," ");for(i=1;i<=12;i++)M[m[i]]=sprintf("%02d",i)}
  { d=""
    a=match($0,/[0-9][0-9][0-9][0-9][-\/][0-9][0-9][-\/][0-9][0-9]/); ra=RSTART
    b=match($0,/[0-9][0-9][-\/][A-Z][a-z][a-z][-\/][0-9][0-9][0-9][0-9]/); rb=RSTART
    if (a && (!b || ra<rb)) { d=substr($0,ra,10); gsub(/\//,"-",d) }
    else if (b) { t=substr($0,rb,11); d=substr(t,8,4) "-" M[substr(t,4,3)] "-" substr(t,1,2) }
    if (d!="" && d>=s) print }'
}

first_date() {   # ältester Eintrag der ältesten Logdatei
  local f; f=$(ls -1tr -- "$@" 2>/dev/null | head -1); [ -z "$f" ] && return
  zcat -f -- "$f" 2>/dev/null | head -n 20 | perday_any | head -1
}
perday_any() {
  awk 'BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",m," ");for(i=1;i<=12;i++)M[m[i]]=sprintf("%02d",i)}
  { a=match($0,/[0-9][0-9][0-9][0-9][-\/][0-9][0-9][-\/][0-9][0-9]/); ra=RSTART
    b=match($0,/[0-9][0-9][-\/][A-Z][a-z][a-z][-\/][0-9][0-9][0-9][0-9]/); rb=RSTART
    if (a && (!b || ra<rb)) { d=substr($0,ra,10); gsub(/\//,"-",d); print d; exit }
    else if (b) { t=substr($0,rb,11); print substr(t,8,4) "-" M[substr(t,4,3)] "-" substr(t,1,2); exit } }'
}
note_cov() { # $1 label $2 erstes Datum
  if [ -z "$2" ]; then L_COV+=("${CUR:+[$CUR] }$1: Beginn unbekannt")
  elif [[ "$2" > "$SINCE" ]]; then L_COV+=("${CUR:+[$CUR] }$1: erst ab $2 (Lücke $SINCE – $2)")
  fi
}
expand_logs() { # Basis-Pfade → vorhandene Dateien inkl. Rotation
  local p f
  for p in "$@"; do
    [ -z "$p" ] && continue
    for f in "$p" "$p".[0-9]*; do [ -f "$f" ] && echo "$f"; done
  done | sort -u
}
mark_logs() { local p; for p in "$@"; do [ -n "$p" ] && LOG_DONE[$p]=1; done; }

# ----------------------------------------------------------------------------
#  Log-Analysen
# ----------------------------------------------------------------------------
analyze_err() { # $1 Label, Rest: Dateien
  local label=$1; shift
  [ $# -eq 0 ] && return
  local cov; cov=$(first_date "$@"); note_cov "$label" "$cov"
  info "$label: $# Datei(en), Daten ab ${cov:-?}"
  local data; data=$(zcat -f -- "$@" 2>/dev/null | grep -aE "$PARSER_RE|$OOM_RE|$CRASH_RE|$BODY_RE")
  [ -z "$data" ] && { ok "$label: keine relevanten Fehlermeldungen"; return; }
  local p o c b n
  p=$(printf '%s\n' "$data" | grep -aE "$PARSER_RE")
  n=$(printf '%s\n' "$p" | perday | sumday)
  if [ "$n" -gt 0 ]; then
    att "$label: $n PHP-Parser-/Startup-Warnungen (typisch für PHP2Shell-Payloads) – je Tag:"
    printf '%s\n' "$p" | perday | det
    printf '%s\n' "$p" | since_lines | tail -n 3 | sed 's/^/↳ /' | det
  fi
  o=$(printf '%s\n' "$data" | grep -aE "$OOM_RE" | grep -avE 'in Unknown on line 0')
  n=$(printf '%s\n' "$o" | perday | sumday)
  [ "$n" -gt 0 ] && { info "$label: $n Memory-Limit-Fehler im App-Code (meist normal) – je Tag:"; printf '%s\n' "$o" | perday | det; }
  c=$(printf '%s\n' "$data" | grep -aE "$CRASH_RE")
  n=$(printf '%s\n' "$c" | perday | sumday)
  [ "$n" -gt 0 ] && { info "$label: $n abgebrochene FPM-Antworten (Worker-Abbruch/Crash) – je Tag:"; printf '%s\n' "$c" | perday | det; }
  b=$(printf '%s\n' "$data" | grep -aE "$BODY_RE")
  n=$(printf '%s\n' "$b" | perday | sumday)
  [ "$n" -gt 0 ] && { info "$label: $n zu große Request-Bodies abgewiesen – je Tag:"; printf '%s\n' "$b" | perday | det; }
}

status_of() { awk -F'"' '{split($3,a," "); print a[1]}'; }
hits_by_status() { # $1 Label $2 Text $3 Zeilen $4 lines|ips
  [ -z "$3" ] && return
  local reached; reached=$(printf '%s\n' "$3" | awk -F'"' '{split($3,a," "); if (a[1]!="444" && a[1]!="400" && a[1]!="413") print}')
  local st; st=$(printf '%s\n' "$3" | status_of | sort | uniq -c | sort -rn | awk '{printf "%s×%s ", $1, $2}')
  if [ -z "$reached" ]; then
    info "$1: $(cnt "$3") $2 – alle von Nginx verworfen (Status: $st) → PHP nicht erreicht"
  else
    att "$1: $(cnt "$reached") von $(cnt "$3") $2 erreichten PHP (Status: $st)"
    if [ "$4" = ips ]; then printf '%s\n' "$reached" | awk '{print $1}' | sort | uniq -c | sort -rn | det
    else printf '%s\n' "$reached" | tail -n "$MAXLIST" | det; fi
  fi
}
analyze_access() { # $1 Label, $2 laravel(0/1), Rest: Dateien
  local label=$1 lara=$2; shift 2
  [ $# -eq 0 ] && return
  local cov; cov=$(first_date "$@"); note_cov "$label" "$cov"
  info "$label: $# Datei(en), Daten ab ${cov:-?}"
  local cand="$TMPD/acc"
  zcat -f -- "$@" 2>/dev/null | grep -aE "\" (500|502|413) |php2shell|php-session-startup-rce|\.ph(p[0-9]?|tml|ar)[ ?]|[?&]cmd=|^($SRC_IP_RE) " > "$cand"
  local x n
  x=$(grep -aiE "$IOC_UA" "$cand"); hits_by_status "$label" "Requests mit PHP2Shell-Scanner-User-Agent" "$x" lines
  [ -z "$x" ] && ok "$label: keine bekannten PHP2Shell-User-Agents"
  x=$(grep -aE "^($SRC_IP_RE) " "$cand"); hits_by_status "$label" "Requests von veröffentlichten PHP2Shell-Angreifer-IPs" "$x" ips
  [ -z "$x" ] && ok "$label: keine Requests von bekannten Angreifer-IPs"
  x=$(grep -aE '"POST [^"]*" 500 ' "$cand")
  n=$(printf '%s\n' "$x" | perday | sumday)
  if [ "$n" -gt 0 ]; then
    info "$label: $n POST-Requests mit HTTP 500 seit $SINCE – je Tag / Top-IPs:"
    printf '%s\n' "$x" | perday | tail -n 20 | det
    printf '%s\n' "$x" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | sed 's/^/IP /' | det
  fi
  x=$(grep -aE '" 502 ' "$cand"); n=$(printf '%s\n' "$x" | perday | sumday)
  [ "$n" -gt 0 ] && { info "$label: $n Requests mit HTTP 502 (Worker-Abbruch?) – je Tag:"; printf '%s\n' "$x" | perday | tail -n 20 | det; }
  x=$(grep -aE '" 413 ' "$cand"); n=$(printf '%s\n' "$x" | perday | sumday)
  [ "$n" -gt 0 ] && { info "$label: $n Requests mit HTTP 413 (Body zu groß) – je Tag:"; printf '%s\n' "$x" | perday | tail -n 20 | det; }
  if [ "$lara" = 1 ]; then
    x=$(grep -aE '"[A-Z]+ /[^" ]*\.ph(p[0-9]?|tml|ar)(\?[^" ]*)? HTTP/[0-9.]+" 200 ' "$cand" | grep -avE '"[A-Z]+ /index\.php[ ?/]')
    if [ -n "$x" ]; then crit "$label: $(cnt "$x") erfolgreiche (200) Aufrufe von PHP-Dateien außer index.php – Webshell-Zugriff?"; printf '%s\n' "$x" | tail -n "$MAXLIST" | det; fi
  fi
  x=$(grep -aE '[?&]cmd=[^" ]*[^"]*" 200 ' "$cand")
  [ -n "$x" ] && { rev "$label: $(cnt "$x") Requests mit Parameter cmd= und Status 200"; printf '%s\n' "$x" | tail -n "$MAXLIST" | det; }
}

# ----------------------------------------------------------------------------
#  Datei-Heuristiken
# ----------------------------------------------------------------------------
# PHP-Dateien, deren ctime nach dem letzten Composer-Lauf (+Toleranz) liegt.
# ctime lässt sich ohne root nicht fälschen (touch ändert nur mtime).
ctime_check() { # $1 Verzeichnis  $2 mit_app(0/1)  $3 Label
  local d=$1 withapp=$2 lbl=$3
  if [ ! -d "$d/vendor/composer" ]; then info "$lbl: kein vendor/composer – Zeitstempel-Heuristik übersprungen"; return; fi
  # Composer schreibt Dateien nur bei Änderung → jüngste ctime in vendor/composer = letzter wirksamer Composer-Lauf
  local cref ref
  cref=$(find "$d/vendor/composer" -maxdepth 1 -type f \( -name '*.php' -o -name '*.json' \) -printf '%C@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1)
  [ -z "$cref" ] && { info "$lbl: vendor/composer leer – Heuristik übersprungen"; return; }
  ref=$(( cref + TOL_MIN * 60 ))
  touch -d "@$ref" "$TMPREF"
  info "$lbl: letzter wirksamer Composer-Lauf $(date -d "@$cref" '+%F %T') – Prüfung auf spätere Änderungen"
  local v; v=$(find "$d/vendor" -xdev -path "$d/vendor/composer" -prune -o -type f "${FIND_PHPISH[@]}" -cnewer "$TMPREF" -print 2>/dev/null)
  if [ -n "$v" ]; then
    if [ "$(cnt "$v")" -gt 200 ]; then rev "$lbl: $(cnt "$v") vendor-Dateien nach Composer-Lauf geändert (Massenänderung, z. B. chown/chmod?) – Stichprobe:"
    else rev "$lbl: $(cnt "$v") vendor-PHP-Dateien nach Composer-Lauf geändert:"; fi
    printf '%s\n' "$v" | det
  else ok "$lbl: vendor unverändert seit Composer-Lauf"; fi
  if [ "$withapp" = 1 ]; then
    v=$(find "$d" -xdev \( -path "$d/vendor" -o -path "$d/node_modules" -o -path "$d/storage" -o -path "$d/bootstrap/cache" -o -path "$d/.git" \) -prune \
        -o -type f "${FIND_PHPISH[@]}" -cnewer "$TMPREF" -print 2>/dev/null)
    if [ -n "$v" ]; then
      if [ "$(cnt "$v")" -gt 200 ]; then rev "$lbl: $(cnt "$v") App-Dateien nach Build geändert (Massenänderung?) – Stichprobe:"
      else rev "$lbl: $(cnt "$v") App-PHP-Dateien nach dem Build geändert:"; fi
      printf '%s\n' "$v" | det
    else ok "$lbl: App-Code unverändert seit Build"; fi
  fi
}

# Muster-Scan; IoC-Treffer sind immer KRITISCH, sonst Level $1
pattern_scan() { # $1 level(crit|rev)  $2 Label  Rest: Verzeichnisse
  local lvl=$1 lbl=$2; shift 2
  local dirs=() d; for d in "$@"; do [ -d "$d" ] && dirs+=("$d"); done
  [ ${#dirs[@]} -eq 0 ] && return
  local hits ioc rest
  hits=$(grep -rlIP "${GREP_PHP_INC[@]}" --exclude-dir=node_modules --exclude-dir=.git -e "$SCAN_RE" -- "${dirs[@]}" 2>/dev/null | sort -u)
  [ -z "$hits" ] && return 0
  ioc=$(printf '%s\n' "$hits" | while IFS= read -r f; do grep -qaiE "$IOC_STRINGS" -- "$f" && echo "$f"; done)
  rest=$(printf '%s\n' "$hits" | grep -vxF -f <(printf '%s\n' "$ioc") )
  [ -n "$ioc" ] && { crit "$lbl: PHP2Shell-IoC-Strings in Dateien:"; printf '%s\n' "$ioc" | det; }
  if [ -n "$rest" ]; then
    if [ "$lvl" = crit ]; then crit "$lbl: Webshell-Muster gefunden:"; else rev "$lbl: Webshell-ähnliche Muster (False Positives möglich):"; fi
    printf '%s\n' "$rest" | while IFS= read -r f; do
      printf '%s  →  %s\n' "$f" "$(grep -aoiP -m1 "$SCAN_RE" -- "$f" | head -1 | cut -c1-80)"; done | det
  fi
}

# Webroot / Storage / Uploads
webroot_checks() { # $1 app  $2 pub  $3 stor  $4 laravel  $5 Label
  local app=$1 pub=$2 stor=$3 lara=$4 lbl=$5 x f c
  if [ -d "$pub" ] && [ "$lara" = 1 ]; then
    x=$(find "$pub" -xdev -type f -name '*.php' ! -path "$pub/index.php" 2>/dev/null)
    if [ -n "$x" ]; then
      while IFS= read -r f; do
        c=$(stat -c %Z -- "$f")
        if in_since "$c"; then crit "$lbl: ausführbare PHP-Datei im Webroot (geändert $(date -d "@$c" +%F)): $f"
        else rev "$lbl: zusätzliche PHP-Datei im Webroot (Laravel erwartet nur index.php): $f"; fi
      done <<< "$x"
    else ok "$lbl: Webroot enthält nur index.php als PHP-Datei"; fi
    x=$(find "$pub" -xdev -type f \( -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' -o -iname '*.pht' -o -iname '*.phps' \) 2>/dev/null)
    [ -n "$x" ] && { rev "$lbl: weitere PHP-artige Dateien im Webroot:"; printf '%s\n' "$x" | det; }
    x=$(find "$pub" -xdev -maxdepth 4 -type l 2>/dev/null | while IFS= read -r f; do
          t=$(readlink -f -- "$f"); case "$t" in "${S_BASE_CUR}"/*|"$stor"/*|"$app"/*) ;; *) echo "$f → $t";; esac; done)
    [ -n "$x" ] && { rev "$lbl: Symlinks im Webroot zeigen außerhalb der Site:"; printf '%s\n' "$x" | det; }
  fi
  if [ -d "$stor" ]; then
    x=$(find "$stor/app/public" -xdev -type f "${FIND_PHPISH[@]}" 2>/dev/null)
    if [ -n "$x" ]; then
      if [ -L "$pub/storage" ]; then crit "$lbl: PHP-Dateien in storage/app/public (über /storage per Web ausführbar):"
      else rev "$lbl: PHP-Dateien in storage/app/public:"; fi
      printf '%s\n' "$x" | det
    fi
    x=$(find "$stor" -xdev \( -path "$stor/framework/views" -o -path "$stor/app/public" \) -prune -o -type f "${FIND_PHPISH[@]}" ! -path "$stor/framework/cache/facade-*.php" -print 2>/dev/null)
    [ -n "$x" ] && { rev "$lbl: PHP-Dateien in storage/ (Upload-Versuch? nicht direkt per Web erreichbar):"; printf '%s\n' "$x" | det; }
    x=$(find "$stor/app" "$pub" -xdev -type f \( -iname '*.php.*' -o -iname '*.phtml.*' -o -iname '*.php[0-9].*' \) 2>/dev/null)
    [ -n "$x" ] && { att "$lbl: Uploads mit Doppel-Endung (z. B. shell.php.jpg):"; printf '%s\n' "$x" | det; }
    x=$(find "$stor/app" "$pub" -xdev \( -path "$pub/build" -o -path "$pub/vendor" -o -path "$pub/js" -o -path "$pub/css" -o -path "$pub/fonts" \) -prune \
          -o -type f -size -20M -newerct "$SINCE" ! -iname '*.php' ! -iname '*.js' ! -iname '*.mjs' ! -iname '*.css' ! -iname '*.map' ! -iname '*.json' -print0 2>/dev/null \
          | xargs -0 -r grep -laiE '<\?php' 2>/dev/null | head -n 200)
    [ -n "$x" ] && { att "$lbl: Nicht-PHP-Dateien mit PHP-Code (Polyglot-Upload?):"; printf '%s\n' "$x" | det; }
  fi
  x=$(find "$app" "$pub" "$stor" -xdev \( -name node_modules -o -name vendor -o -name .git \) -prune -o -type f \( -name '.user.ini' -o -name 'php.ini' \) -print 2>/dev/null | sort -u)
  if [ -n "$x" ]; then
    while IFS= read -r f; do
      if grep -qiE '^\s*auto_(prepend|append)_file\s*=\s*\S' -- "$f"; then crit "$lbl: $f setzt auto_prepend/append_file (klassische Persistenz)"
      else rev "$lbl: PHP-INI im Site-Verzeichnis: $f"; fi
    done <<< "$x"
  fi
  x=$(find "$app" "$pub" "$stor" -xdev \( -name node_modules -o -name .git -o -name vendor \) -prune -o -type f -regextype posix-extended -regex ".*/(${IOC_FILES_ALT})" -print 2>/dev/null | sort -u)
  [ -n "$x" ] && { crit "$lbl: Dateinamen aus PHP2Shell-Kampagnen:"; printf '%s\n' "$x" | det; }
}

# ============================================================================
sect "PHP2Shell-Audit · $HOST · $(date '+%F %T %Z')"
OSNAME=$(grep -s '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"')
info "System: ${OSNAME:-?} · Kernel $(uname -r) · Boot: $(uptime -s 2>/dev/null)"
[ "$PROV_EPOCH" -gt 0 ] && info "Server provisioniert: $(date -d "@$PROV_EPOCH" '+%F %T') (Änderungen in den ersten 24 h werden als Provisionierung gewertet)"
[ "$SINCE_ADJ" = 1 ] && info "Prüfzeitraum auf Provisionierungsdatum angepasst"
info "Prüfzeitraum ab $SINCE · Report: $REPORT"
info "Hinweis: rein lesend. Fehlende Treffer sind kein Beweis – Request-Bodies werden i. d. R. nicht geloggt."

# ============================================================================
sect "1 · Verwundbarkeit (PHP-Versionen, laufende Prozesse, Mitigations)"
CUR="PHP"
mapfile -t PHPVERS < <(ls -1 /usr/bin/php[0-9]*.[0-9]* /usr/sbin/php-fpm[0-9]*.[0-9]* 2>/dev/null | grep -oE '[0-9]+\.[0-9]+$' | sort -uV)
declare -A FPM_VER=()
SESS_PATHS=("/var/lib/php/sessions")
PHP_ERRLOGS=()
[ ${#PHPVERS[@]} -eq 0 ] && info "Keine System-PHP-Installation gefunden"
for v in "${PHPVERS[@]}"; do
  sub "PHP $v"
  cli=""; fpm=""
  [ -x "/usr/bin/php$v" ]      && cli=$("/usr/bin/php$v" "${PHPSAFE[@]}" -r 'echo PHP_VERSION;' 2>/dev/null | cut -d- -f1)
  [ -x "/usr/sbin/php-fpm$v" ] && fpm=$("/usr/sbin/php-fpm$v" -n -v 2>/dev/null | awk 'NR==1{print $2}' | cut -d- -f1)
  FPM_VER[$v]="$fpm"
  info "CLI: ${cli:-–} · FPM: ${fpm:-nicht installiert}"
  fixed="${FIXED[$v]:-}"
  backport=0
  for cl in /usr/share/doc/php$v-fpm/changelog.Debian.gz /usr/share/doc/php$v-common/changelog.Debian.gz; do
    [ -f "$cl" ] && zgrep -qE 'CVE-2026-10961[89]' "$cl" 2>/dev/null && backport=1
  done
  served="${fpm:-$cli}"; isvuln=0
  if [ -z "$served" ]; then info "Version nicht ermittelbar"
  elif [ -z "$fixed" ]; then
    if dpkg --compare-versions "$v" lt 8.2; then
      if [ -n "$fpm" ]; then vuln "PHP-FPM $fpm ist EOL – es gibt keinen Fix für PHP2Shell (nur Upgrade auf ≥ 8.2)"; isvuln=1
      else info "PHP $cli (EOL) nur als CLI – nicht über Web erreichbar, trotzdem entfernen/upgraden"; fi
    else info "PHP $v: keine Referenzversion hinterlegt – manuell prüfen"; fi
  elif [ "$backport" = 1 ]; then ok "Distribution-Changelog enthält CVE-Fix (Backport)"
  elif dpkg --compare-versions "$served" lt "$fixed"; then
    if [ -n "$fpm" ]; then vuln "PHP-FPM $fpm < $fixed"; isvuln=1; else info "CLI $cli < $fixed (nicht über Web erreichbar, trotzdem patchen)"; fi
  else ok "Version $served ≥ $fixed (gepatcht)"; fi

  # laufende FPM-Master: noch alte (gelöschte) Binary geladen?
  for pid in $(pgrep -f "php-fpm: master process \(/etc/php/$v/" 2>/dev/null); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    started=$(ps -o lstart= -p "$pid" 2>/dev/null)
    if [[ "$exe" == *"(deleted)"* ]] || grep -qE 'php.*\(deleted\)' "/proc/$pid/maps" 2>/dev/null; then
      vuln "FPM-Master PID $pid (Start: $started) nutzt noch die alte, gelöschte Binary – 'systemctl restart php$v-fpm' nötig"
    else ok "FPM-Master PID $pid läuft mit aktueller Binary (Start: $started)"; fi
  done

  # Mitigations / ini (nur Info, da Patch maßgeblich)
  if [ -f "/etc/php/$v/fpm/php.ini" ] && [ -x "/usr/bin/php$v" ]; then
    iniget() { PHP_INI_SCAN_DIR="/etc/php/$v/fpm/conf.d" "/usr/bin/php$v" -c "/etc/php/$v/fpm/php.ini" "${PHPINI[@]}" \
               -r "\$x=ini_get('$1'); echo \$x===false?'n/a':(\$x===''?'leer':\$x);" 2>/dev/null; }
    upe=$(iniget session.upload_progress.enabled); ml=$(iniget memory_limit); feb=$(iniget fatal_error_backtraces)
    sp=$(iniget session.save_path); el=$(iniget error_log)
    case "$upe" in leer|0) upe="0 (aus – Mitigation aktiv)";; 1) upe="1 (an)";; esac
    info "FPM-ini: session.upload_progress.enabled=${upe} · memory_limit=${ml} · fatal_error_backtraces=${feb}"
    if [ "$isvuln" = 1 ]; then
      gaps=""
      [ "$ml" != "-1" ] && gaps+="CVE-2026-109618 offen (memory_limit≠-1) · "
      [[ "$upe" == 1* ]] && gaps+="CVE-2026-109619 offen (upload_progress an) · "
      [ "$v" = 8.5 ] && [ "$feb" = 1 ] && gaps+="CVE-2026-109619 (8.5-Backtrace-Pfad) offen (fatal_error_backtraces=1) · "
      [ -n "$gaps" ] && vuln "Mitigation unvollständig: ${gaps% · }"
    fi
    [ -n "$sp" ] && [ "$sp" != leer ] && [ "$sp" != n/a ] && SESS_PATHS+=("${sp##*;}")
    [ -n "$el" ] && [ "$el" != leer ] && [ "$el" != n/a ] && [ "$el" != syslog ] && PHP_ERRLOGS+=("$el")
  fi
  ap=$(grep -hsE '^\s*auto_(prepend|append)_file\s*=\s*\S' /etc/php/$v/fpm/php.ini /etc/php/$v/fpm/conf.d/*.ini 2>/dev/null)
  ap+=$(grep -hsE 'php_(admin_)?value\[auto_(prepend|append)_file\]\s*=\s*\S' /etc/php/$v/fpm/pool.d/*.conf 2>/dev/null)
  [ -n "$ap" ] && { rev "auto_prepend/append_file in FPM-Konfiguration gesetzt:"; printf '%s\n' "$ap" | det; }
  ov=$(grep -HsE '^\s*php_(admin_)?(value|flag)\[(session\.upload_progress\.enabled|memory_limit|fatal_error_backtraces)\]' /etc/php/$v/fpm/pool.d/*.conf 2>/dev/null)
  [ -n "$ov" ] && { info "Pool-Overrides:"; printf '%s\n' "$ov" | det; }
done

# FrankenPHP (Octane) bringt eigenes PHP mit – nur als Owner ausführen
FP_BINS=$( { for p in $(pgrep -x frankenphp 2>/dev/null); do readlink -f "/proc/$p/exe"; done
             find /home -xdev -maxdepth 4 -type f -name frankenphp -perm /111 2>/dev/null; } | sed 's/ (deleted)$//' | sort -u)
if [ -n "$FP_BINS" ]; then
  sub "FrankenPHP (eigenes, eingebettetes PHP)"
  while IFS= read -r b; do
    [ -f "$b" ] || continue
    own=$(stat -c %U -- "$b"); [ "$own" = root ] && own=nobody
    out=$(runuser -u "$own" -- timeout 5 "$b" version 2>/dev/null | head -1)
    pv=$(grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' <<< "$out" | awk '{print $2}')
    mm=$(grep -oE '^[0-9]+\.[0-9]+' <<< "$pv")
    if [ -z "$pv" ]; then rev "FrankenPHP $b: PHP-Version nicht ermittelbar"
    elif [ -n "${FIXED[$mm]:-}" ] && dpkg --compare-versions "$pv" lt "${FIXED[$mm]}"; then vuln "FrankenPHP $b bettet PHP $pv ein (< ${FIXED[$mm]}) – Binary aktualisieren"
    elif [ -z "${FIXED[$mm]:-}" ] && dpkg --compare-versions "$pv" lt 8.2; then vuln "FrankenPHP $b bettet EOL-PHP $pv ein"
    else ok "FrankenPHP $b: PHP $pv"; fi
  done <<< "$FP_BINS"
fi
if command -v apache2ctl >/dev/null 2>&1 && pgrep -x apache2 >/dev/null 2>&1; then
  apache2ctl -M 2>/dev/null | grep -qi php && info "Apache mit mod_php aktiv (höchstes Risiko laut Advisory) – Version oben maßgeblich"
fi
if pgrep -x dockerd >/dev/null 2>&1; then info "Docker läuft – PHP in Containern wird von diesem Skript NICHT geprüft"; fi

# ============================================================================
sect "2 · Sites"
declare -A S_BASE=() S_ZDT=() S_WEBROOT=() S_PUB=() S_CONF=() S_PHP=() S_ALOG=() S_ELOG=() S_OWNER=()
SITES=()
add_site() { # app base zdt webroot pub conf
  [ -n "${S_BASE[$1]:-}" ] && return 1
  SITES+=("$1"); S_BASE[$1]="$2"; S_ZDT[$1]="$3"; S_WEBROOT[$1]="$4"; S_PUB[$1]="$5"; S_CONF[$1]="$6"
  S_OWNER[$1]=$(stat -c %U -- "$1" 2>/dev/null)
}
resolve_root() { # Webroot → R_APP R_BASE R_ZDT R_PUB
  local wr="${1%/}" rel
  R_ZDT=0
  if [[ "$wr" == */current/* || "$wr" == */current ]]; then
    if [[ "$wr" == */current ]]; then R_BASE="${wr%/current}"; rel=""; else R_BASE="${wr%/current/*}"; rel="/${wr##*/current/}"; fi
    R_ZDT=1; R_APP=$(readlink -f -- "$R_BASE/current"); R_PUB="$R_APP$rel"
  else
    if [[ "$wr" == */public ]]; then R_BASE="${wr%/public}"; else R_BASE="$wr"; fi
    R_APP=$(readlink -f -- "$R_BASE"); R_PUB=$(readlink -f -- "$wr")
  fi
}
nginx_conf_files() { # $1 Datei → Datei + Includes (rekursiv, Tiefe 3)
  local f=$1 depth=${2:-0} inc g
  echo "$f"; [ "$depth" -ge 3 ] && return
  grep -hsE '^\s*include\s+' "$f" | sed -E 's/^\s*include\s+//; s/;.*$//; s/["'\'']//g' | while IFS= read -r inc; do
    [[ "$inc" != /* ]] && inc="/etc/nginx/$inc"
    for g in $inc; do [ -f "$g" ] && nginx_conf_files "$g" $((depth + 1)); done
  done
}
for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
  [ -f "$conf" ] || continue
  name=$(basename "$conf")
  mapfile -t files < <( { nginx_conf_files "$conf"; [ -d "/etc/nginx/forge-conf/$name" ] && find "/etc/nginx/forge-conf/$name" -type f; } 2>/dev/null | grep -vE '/(mime\.types|fastcgi_params|fastcgi\.conf|forge_fastcgi_defaults|snippets/fastcgi-php\.conf)$' | sort -u)
  roots=$(grep -hsE '^\s*root\s+' "${files[@]}" | sed -E 's/^\s*root\s+//; s/;.*$//; s/["'\'']//g' | grep -v '\$' | sort -u)
  [ -z "$roots" ] && continue
  sock=$(grep -hsoE 'php[0-9]+\.[0-9]+-fpm[^ ;]*\.sock' "${files[@]}" | head -1)
  alog=$(grep -hsE '^\s*access_log\s+' "${files[@]}" | sed -E 's/^\s*access_log\s+//; s/[ ;].*$//' | sort -u | tr '\n' ' ')
  elog=$(grep -hsE '^\s*error_log\s+' "${files[@]}" | sed -E 's/^\s*error_log\s+//; s/[ ;].*$//' | sort -u | tr '\n' ' ')
  while IFS= read -r wr; do
    [ -z "$wr" ] && continue
    [[ "$wr" == /usr/share/nginx/* ]] && continue   # Distributions-Defaultseite
    resolve_root "$wr"
    [ -n "$R_APP" ] && [ -d "$R_APP" ] || continue
    add_site "$R_APP" "$R_BASE" "$R_ZDT" "$wr" "$R_PUB" "$conf" || continue
    S_PHP[$R_APP]="$sock"; S_ALOG[$R_APP]="$alog"; S_ELOG[$R_APP]="$elog"
  done <<< "$roots"
done
for d in /home/*/*/; do
  d="${d%/}"
  if [ -L "$d/current" ]; then app=$(readlink -f -- "$d/current"); z=1
  elif [ -f "$d/artisan" ]; then app=$(readlink -f -- "$d"); z=0
  else continue; fi
  [ -d "$app" ] || continue
  known=0; for s in "${SITES[@]}"; do [ "${S_BASE[$s]}" = "$d" ] && known=1; done
  [ "$known" = 1 ] && continue
  add_site "$app" "$d" "$z" "-" "$app/public" "-"
done
info "${#SITES[@]} Site(s) gefunden"
WEBUSERS="forge"
for s in "${SITES[@]}"; do
  printf '        %-45s %s\n' "${S_BASE[$s]}" "$([ "${S_ZDT[$s]}" = 1 ] && echo "ZDT → ${s##*/}" || echo klassisch) · Owner ${S_OWNER[$s]} · ${S_PHP[$s]:-PHP ?}$([ "${S_CONF[$s]}" = - ] && echo ' · NICHT in Nginx aktiv')"
  [[ " $WEBUSERS " == *" ${S_OWNER[$s]} "* ]] || WEBUSERS+=" ${S_OWNER[$s]}"
done

for app in "${SITES[@]}"; do
  base="${S_BASE[$app]}"; pub="${S_PUB[$app]}"; owner="${S_OWNER[$app]}"
  S_BASE_CUR="$base"
  CUR="$(basename "$base")"
  sub "Site $CUR"
  lara=0; [ -f "$app/artisan" ] && lara=1
  stor=$(readlink -f -- "$app/storage" 2>/dev/null); [ -d "$stor" ] || stor=""
  info "aktiv: $app · public: $pub · storage: ${stor:-–} · Laravel: $([ $lara = 1 ] && echo ja || echo nein)"

  # Zero-Downtime: Symlink + alle Releases
  RELS=()
  if [ "${S_ZDT[$app]}" = 1 ]; then
    case "$app" in
      "$base"/releases/*) ok "current → releases/${app##*/}" ;;
      *) crit "Symlink current zeigt außerhalb von releases/: $app" ;;
    esac
    mapfile -t RELS < <(find "$base/releases" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    info "${#RELS[@]} Release(s) – alle werden geprüft (inaktive = Spurensicherung)"
  fi

  # Code-Integrität aktive Version
  if [ -d "$app/.git" ]; then
    gown=$(stat -c %U -- "$app/.git")
    gs=$(runuser -u "$gown" -- git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.untrackedCache=false \
         -C "$app" status --porcelain --untracked-files=all 2>/dev/null); grc=$?
    if [ $grc -ne 0 ]; then info "git status fehlgeschlagen (rc=$grc)"
    elif [ -z "$gs" ]; then ok "Git: Arbeitsverzeichnis entspricht dem Commit"
    else
      gphp=$(printf '%s\n' "$gs" | grep -aE '\.(php[0-9]?|phtml|phar|pht|inc)"?$|\.user\.ini"?$')
      [ -n "$gphp" ] && { rev "Git: geänderte/unversionierte PHP-Dateien:"; printf '%s\n' "$gphp" | det; }
      gother=$(( $(cnt "$gs") - $(cnt "$gphp") ))
      [ "$gother" -gt 0 ] && info "Git: $gother weitere Abweichung(en) ohne PHP-Bezug"
    fi
    ctime_check "$app" 0 "aktiv"
  else
    ctime_check "$app" 1 "aktiv"
  fi

  # Webroot/Storage/Uploads
  webroot_checks "$app" "$pub" "$stor" "$lara" "aktiv"

  # Muster-Scans
  pattern_scan crit "Webroot"          "$pub"
  [ -n "$stor" ] && pattern_scan crit "storage" "$stor"
  pattern_scan crit "bootstrap/cache"  "$app/bootstrap/cache"
  appdirs=(); for d in "$app"/*/; do d="${d%/}"; case "${d##*/}" in vendor|node_modules|storage|public|bootstrap) ;; *) appdirs+=("$d");; esac; done
  pattern_scan rev "App-Code" "${appdirs[@]}"
  [ -d "$app/vendor" ] && pattern_scan rev "vendor" "$app/vendor"

  # Inaktive Releases
  for rel in "${RELS[@]}"; do
    [ "$rel" = "$app" ] && continue
    rn="release ${rel##*/}"
    QUIET=1
    ctime_check "$rel" 1 "$rn"
    webroot_checks "$rel" "$rel/public" "" "$lara" "$rn"
    pattern_scan crit "$rn/public" "$rel/public"
    rdirs=(); for d in "$rel"/*/; do d="${d%/}"; case "${d##*/}" in vendor|node_modules|storage|public) ;; *) rdirs+=("$d");; esac; done
    pattern_scan rev "$rn" "${rdirs[@]}"
    QUIET=0
  done

  # .env
  if [ -f "$base/.env" ] || [ -f "$app/.env" ]; then
    ef=$(readlink -f -- "$app/.env" 2>/dev/null || echo "$base/.env")
    info ".env zuletzt geändert: $(date -d "@$(stat -c %Y -- "$ef" 2>/dev/null || echo 0)" +%F) – Secrets rotieren, falls Server im Zeitraum verwundbar war (Memory-Disclosure)"
  fi

  # Logs der Site
  al=(); for a in ${S_ALOG[$app]:-}; do [ "$a" = off ] && continue; al+=("$a"); done
  if [ -n "${S_ALOG[$app]:-}" ] && [ ${#al[@]} -eq 0 ]; then
    info "Access-Log in Nginx deaktiviert (access_log off) – HTTP-Indizien für diese Site nicht prüfbar"
    L_COV+=("[$CUR] Access-Log deaktiviert – Site-Traffic nicht prüfbar (globales access.log enthält nur den Catch-All)")
  fi
  if [ -z "${S_ALOG[$app]:-}" ] && [ "${S_CONF[$app]}" != - ]; then info "kein eigenes Access-Log – ggf. im globalen access.log (Abschnitt 3)"; fi
  if [ ${#al[@]} -gt 0 ]; then mark_logs "${al[@]}"; mapfile -t lf < <(expand_logs "${al[@]}"); analyze_access "Access-Log" "$lara" "${lf[@]}"; fi
  el=(); for e in ${S_ELOG[$app]:-}; do el+=("$e"); done
  if [ ${#el[@]} -gt 0 ]; then mark_logs "${el[@]}"; mapfile -t lf < <(expand_logs "${el[@]}"); analyze_err "Error-Log" "${lf[@]}"; fi
done
CUR=""

# ============================================================================
sect "3 · Globale Logs"
CUR="Logs"
mapfile -t gl < <(ls -1 /var/log/nginx/*.log 2>/dev/null)
for f in "${gl[@]}"; do
  [ -n "${LOG_DONE[$f]:-}" ] && continue
  mark_logs "$f"; mapfile -t lf < <(expand_logs "$f")
  case "$f" in *error*) analyze_err "nginx $(basename "$f")" "${lf[@]}" ;; *) analyze_access "nginx $(basename "$f")" 0 "${lf[@]}" ;; esac
done
for e in $(printf '%s\n' "${PHP_ERRLOGS[@]}" | sort -u); do
  mapfile -t lf < <(expand_logs "$e"); [ ${#lf[@]} -gt 0 ] && analyze_err "PHP error_log $e" "${lf[@]}"
done

sub "PHP-FPM-Logs (Worker-Abstürze)"
mapfile -t fl < <(ls -1 /var/log/php*-fpm.log* 2>/dev/null)
if [ ${#fl[@]} -gt 0 ]; then
  cov=$(first_date "${fl[@]}"); note_cov "PHP-FPM-Log" "$cov"; info "PHP-FPM-Log: ${#fl[@]} Datei(en), Daten ab ${cov:-?}"
  x=$(zcat -f -- "${fl[@]}" 2>/dev/null | grep -aE 'exited on signal (11|7|6|4)\b')
  n=$(printf '%s\n' "$x" | perday | sumday)
  if [ "$n" -gt 0 ]; then att "$n FPM-Worker-Abstürze (SIGSEGV/SIGBUS/SIGABRT/SIGILL) – Speicherkorruption – je Tag:"; printf '%s\n' "$x" | perday | det
  else ok "keine FPM-Worker-Abstürze seit $SINCE"; fi
  x=$(zcat -f -- "${fl[@]}" 2>/dev/null | grep -aE 'exited on signal 9\b|server reached (pm\.)?max_children')
  n=$(printf '%s\n' "$x" | perday | sumday)
  [ "$n" -gt 0 ] && { info "$n Worker-Kills (SIGKILL) / max_children-Warnungen – je Tag:"; printf '%s\n' "$x" | perday | det; }
else info "keine PHP-FPM-Logdateien gefunden"; fi

sub "Kernel (Segfaults / OOM-Killer)"
KRE='php[^ ]*\[[0-9]+\]: segfault|segfault at .*php|Killed process [0-9]+ \((php|frankenphp)'
k=$(journalctl _TRANSPORT=kernel -q --no-pager -o short-iso --since "$SINCE" 2>/dev/null | grep -aE "$KRE")
[ -z "$k" ] && k=$(zcat -f /var/log/kern.log* 2>/dev/null | grep -aE "$KRE")
n=$(printf '%s\n' "$k" | grep -a segfault | perday | sumday)
if [ "$n" -gt 0 ]; then att "$n PHP-Segfaults im Kernel-Log – je Tag:"; printf '%s\n' "$k" | grep -a segfault | perday | det
else ok "keine PHP-Segfaults im Kernel-Log"; fi
n=$(printf '%s\n' "$k" | grep -a 'Killed process' | perday | sumday)
[ "$n" -gt 0 ] && info "$n PHP-Prozesse vom OOM-Killer beendet"

ms=$(ls -1 /var/log/modsec_audit.log* /var/log/apache2/modsec_audit.log* /var/log/nginx/modsec_audit.log* 2>/dev/null)
if [ -n "$ms" ]; then
  sub "ModSecurity-Audit-Log (Request-Bodies)"
  x=$(printf '%s\n' "$ms" | xargs zcat -f 2>/dev/null | grep -aE 'PHP_SESSION_UPLOAD_PROGRESS|----p2s|nucleiBoundary|------atk|'"$IOC_STRINGS")
  [ -n "$x" ] && { att "$(cnt "$x") Treffer auf Upload-Progress-Feld/Exploit-Boundaries:"; printf '%s\n' "$x" | tail -n "$MAXLIST" | det; } || ok "keine Treffer"
else
  info "Kein WAF/ModSecurity-Body-Log – Kernmerkmal (Feld PHP_SESSION_UPLOAD_PROGRESS im Body) nicht prüfbar"
fi

# ============================================================================
sect "4 · Native PHP-Sessions (Upload-Progress-Pfad)"
CUR="Sessions"
for sd in $(printf '%s\n' "${SESS_PATHS[@]}" | sort -u); do
  [ -d "$sd" ] || continue
  mapfile -t sf < <(find "$sd" -maxdepth 3 -type f -name 'sess_*' 2>/dev/null)
  info "$sd: ${#sf[@]} Session-Datei(en) (Laravel nutzt keine nativen Sessions; Ubuntu löscht sie nach ~24 Min.)"
  [ ${#sf[@]} -eq 0 ] && continue
  x=$(printf '%s\n' "${sf[@]}" | grep -aiE "/sess_($IOC_SESSIDS)")
  [ -n "$x" ] && { att "Session-IDs bekannter Exploit-Tools:"; printf '%s\n' "$x" | det; }
  x=$(printf '%s\n' "${sf[@]}" | xargs -r grep -laiE '<\?php|<\?=|system\(|base64_decode|shell_exec|passthru' 2>/dev/null)
  [ -n "$x" ] && { att "Session-Dateien mit PHP-Code (Session-File-Inclusion-Technik):"; printf '%s\n' "$x" | det; }
  x=$(printf '%s\n' "${sf[@]}" | xargs -r grep -laE "upload_progress_|$IOC_STRINGS|pwn" 2>/dev/null)
  [ -n "$x" ] && { att "Session-Dateien mit Upload-Progress-Daten/Exploit-Canaries:"; printf '%s\n' "$x" | det; }
done

# ============================================================================
sect "5 · Prozesse & Netzwerk"
CUR="Prozesse"
ps -eo pid=,ppid=,etimes=,user=,comm=,args= > "$TMPD/ps" 2>/dev/null
desc=$(awk '{p=$1; pp[p]=$2; et[p]=$3; u[p]=$4; c[p]=$5; $1=$2=$3=$4=$5=""; a[p]=substr($0,6)}
  END{ for (p in c) { if (c[p] ~ /^(php-fpm|apache2|httpd)/) continue
         q=pp[p]; n=0
         while (q>1 && n<64) { if (c[q] ~ /^(php-fpm|apache2|httpd)/) { print p "\t" et[p] "\t" u[p] "\t" c[p] "\t" a[p]; break } q=pp[q]; n++ } } }' "$TMPD/ps")
if [ -n "$desc" ]; then
  while IFS=$'\t' read -r pid et usr comm args; do
    line="PID $pid · $usr · seit ${et}s · $comm · $args"
    if [[ "$comm" =~ ^(nc|ncat|netcat|socat|telnet|busybox|perl|python[0-9.]*|ruby|lua)$ ]] || \
       { [[ "$comm" =~ ^(sh|bash|dash|zsh|ksh)$ ]] && [ "$et" -gt 300 ]; }; then
      crit "Webserver/PHP-Worker startete verdächtigen Prozess: $line"
    else rev "Kindprozess eines PHP-Workers: $line"; fi
  done <<< "$desc"
else ok "keine Kindprozesse von PHP-FPM-Workern"; fi

pc=""; pr=""; pn=""; pw=""
for p in /proc/[0-9]*; do
  pid=${p##*/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  comm=$(cat "$p/comm" 2>/dev/null); usr=$(stat -c %U "$p" 2>/dev/null)
  case "$exe" in
    /memfd:*)                              pc+="PID $pid · $usr · $comm · $exe (dateilos im RAM)"$'\n' ;;
    /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*) pc+="PID $pid · $usr · $comm · $exe"$'\n' ;;
    *" (deleted)")
      path="${exe% (deleted)}"
      case "$path" in /usr/*|/lib/*|/lib64/*|/bin/*|/sbin/*|/opt/*|/snap/*) pr+="$comm · $path"$'\n' ;;
                      *) pc+="PID $pid · $usr · $comm · $exe (Binary gelöscht)"$'\n' ;; esac ;;
    /home/*/storage/*|/home/*/public/*) pc+="PID $pid · $usr · $comm · $exe (Binary in Web-Verzeichnis)"$'\n' ;;
  esac
  if [[ "$comm" =~ ^($IOC_PROCNAMES)$ ]]; then
    bn=$(basename "${exe% (deleted)}"); [ "$bn" != "$comm" ] && pn+="PID $pid · $usr · tarnt sich als '$comm' · echte Binary: $exe"$'\n'
  fi
  if [[ " $WEBUSERS " == *" $usr "* ]]; then
    case "$exe" in /usr/*|/bin/*|/sbin/*|/lib/*|/opt/*|/snap/*|/memfd:*|/tmp/*|/var/tmp/*|/dev/shm/*) ;;
      */vendor/*|*/node_modules/*|*/frankenphp|*/rr|*/.nvm/*|*/.bun/*|*/.volta/*) ;;
      *) pw+="PID $pid · $usr · $comm · $exe"$'\n' ;; esac
  fi
done
[ -n "$pc" ] && { crit "Prozesse aus Temp-/Web-Verzeichnissen, RAM oder mit gelöschter Binary:"; printf '%s' "$pc" | det; }
[ -n "$pn" ] && { crit "Getarnte Prozesse (Mirai-Variante aus PHP2Shell-Kampagne):"; printf '%s' "$pn" | det; }
[ -n "$pw" ] && { rev "Prozesse von Web-Usern mit Binary außerhalb der System-Pfade:"; printf '%s' "$pw" | det; }
[ -z "$pc$pn$pw" ] && ok "keine verdächtigen Prozess-Binaries"
[ -n "$pr" ] && { info "Prozesse mit aktualisierter Binary (Neustart empfohlen):"; printf '%s' "$pr" | sort | uniq -c | det; }

CUR="Netzwerk"
if command -v ss >/dev/null 2>&1; then
  est=$(ss -Htanp state established 2>/dev/null)
  x=$(printf '%s\n' "$est" | grep -aE "($C2_IP_RE)[]:]")
  [ -n "$x" ] && { crit "Aktive Verbindung zu bekannter PHP2Shell-C2-/Malware-Infrastruktur:"; printf '%s\n' "$x" | det; }
  x=$(printf '%s\n' "$est" | awk -v ports="$IOC_C2_PORTS" '{l=$3; r=$4; sub(/.*:/,"",l); sub(/.*:/,"",r); if (l+0>=32768 && index(ports," " r " ")) print}')
  [ -n "$x" ] && { rev "Ausgehende Verbindungen auf Ports der Mirai-C2-Konfiguration:"; printf '%s\n' "$x" | det; }
  x=$(printf '%s\n' "$est" | grep -aE 'users:\(\("(sh|bash|dash|nc|ncat|netcat|socat|perl|python[0-9.]*|ruby|busybox|telnet)"')
  [ -n "$x" ] && { crit "Netzwerkverbindungen von Shells/Interpretern (Reverse Shell?):"; printf '%s\n' "$x" | det; }
  lst=$(ss -Htlnup 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|::1|\[::ffff:127\.)/' \
        | grep -avE 'users:\(\("(nginx|sshd|systemd|systemd-network|dhclient|mysqld|mariadbd|postgres|redis-server|redis-check|memcached|php-fpm[0-9.]*|php[0-9.]*|systemd-resolve|chronyd|ntpd|master|exim4|node|meilisearch|frankenphp|rr|supervisord|beanstalkd|docker-proxy|soketi|typesense-serve|minio)"')
  [ -n "$lst" ] && { rev "Öffentliche Listener unbekannter Prozesse:"; printf '%s\n' "$lst" | det; }
  dns=$(ss -Hunp state established 2>/dev/null | awk '$4 ~ /:53$/ && $4 !~ /^(127\.|\[::1\])/' | grep -avE 'systemd-resolve|named|unbound|dnsmasq')
  [ -n "$dns" ] && { rev "Direkte DNS-Abfragen an externe Resolver (Malware nutzt fest kodierte Resolver):"; printf '%s\n' "$dns" | det; }
  [ -z "$(printf '%s\n' "$est" | grep -aE "($C2_IP_RE)[]:]")" ] && ok "keine Verbindungen zu bekannter C2-Infrastruktur"
else info "ss nicht verfügbar – Netzwerkprüfung übersprungen"; fi

# ============================================================================
sect "6 · Persistenz, Systemintegrität, Temp-Verzeichnisse"
CUR="System"
if [ -s /etc/ld.so.preload ]; then crit "/etc/ld.so.preload ist gesetzt (Rootkit-Technik):"; det < /etc/ld.so.preload; else ok "/etc/ld.so.preload leer/nicht vorhanden"; fi
x=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
[ -n "$x" ] && { crit "weitere Accounts mit UID 0:"; printf '%s\n' "$x" | det; }
find /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d -type f -newerct "$SINCE" 2>/dev/null | not_pkg_clean \
  | report_changed "Account-/sudo-Dateien seit $SINCE geändert (Forge legt z. B. isolierte User an)"

x=""
for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do
  [ -f "$f" ] || continue
  c=$(stat -c %Z -- "$f")
  in_since "$c" && x+="$f ($(grep -cvE '^\s*(#|$)' "$f") Keys: $(awk '!/^\s*#/ && NF{print $NF}' "$f" | tr '\n' ' '))"$'\n'
done
if [ -n "$x" ]; then printf '%s' "$x" | report_changed "authorized_keys seit $SINCE geändert – Keys abgleichen"
else ok "authorized_keys seit $SINCE unverändert"; fi

CRONF=(/etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*)
find "${CRONF[@]}" -maxdepth 0 -type f -newerct "$SINCE" 2>/dev/null | not_pkg_clean | report_changed "Cron-Dateien seit $SINCE geändert"
x=$(grep -HnaE '(curl|wget)[^|;#]*\|\s*(ba|z|da)?sh|base64\s+(-d|--decode)|/(tmp|dev/shm|var/tmp)/|bash\s+-i|\bnc(at)?\b.*\s-e\s|python[0-9.]*\s+-c|perl\s+-e|/storage/[^ ]*\.(sh|bin|elf)' "${CRONF[@]}" 2>/dev/null | grep -avE ':[0-9]+:\s*#')
[ -n "$x" ] && { crit "verdächtige Cron-Einträge:"; printf '%s\n' "$x" | det; } || ok "keine verdächtigen Cron-Einträge"
ls /var/spool/cron/atjobs/* >/dev/null 2>&1 && rev "at-Jobs vorhanden: $(ls /var/spool/cron/atjobs | tr '\n' ' ')"

x=$(find /etc/systemd/system /root/.config/systemd /home/*/.config/systemd -type f -newerct "$SINCE" ! -name 'snap-*.mount' ! -name 'snap.*' 2>/dev/null)
x+=$'\n'$(find /lib/systemd/system /usr/lib/systemd/system -type f -newerct "$SINCE" -print0 2>/dev/null | xargs -0 -r readlink -f | sort -u | while IFS= read -r f; do pkg_owner "$f" >/dev/null || echo "$f (keinem Paket zugeordnet)"; done)
printf '%s\n' "$x" | report_changed "systemd-Units seit $SINCE neu/geändert"
x=$(grep -rlaE '^\s*Exec(Start|StartPre|StartPost|Reload)\s*=.*(/tmp/|/dev/shm/|/var/tmp/|/storage/)' /etc/systemd /lib/systemd/system /usr/lib/systemd/system /home/*/.config/systemd /root/.config/systemd 2>/dev/null \
    | xargs -r -d '\n' readlink -f | sort -u | not_pkg_clean)
[ -n "$x" ] && { crit "systemd-Units starten Programme aus Temp-/Storage-Verzeichnissen:"; printf '%s\n' "$x" | det; }
x=$(find /etc/supervisor -type f -newerct "$SINCE" 2>/dev/null)
[ -n "$x" ] && { info "Supervisor-Configs geändert (Forge-Daemons/Queues – abgleichen):"; printf '%s\n' "$x" | det; }

RCF=(/etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/* /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_login /home/*/.zshrc)
find "${RCF[@]}" -maxdepth 0 -type f -newerct "$SINCE" 2>/dev/null | not_pkg_clean | report_changed "Shell-Startdateien seit $SINCE geändert"
x=$(grep -HnaE 'LD_PRELOAD|(curl|wget)[^|]*\|\s*(ba)?sh|/dev/(tcp|udp)/|base64\s+(-d|--decode)|/(tmp|dev/shm)/[^ ]*\s*&' "${RCF[@]}" 2>/dev/null)
[ -n "$x" ] && { crit "verdächtige Einträge in Shell-Startdateien:"; printf '%s\n' "$x" | det; }

x=$(find /etc/php/*/fpm/php.ini /etc/php/*/fpm/pool.d /etc/php/*/fpm/conf.d /etc/php/*/cli/php.ini -type f -newerct "$SINCE" 2>/dev/null)
[ -n "$x" ] && { info "PHP-Konfiguration seit $SINCE geändert (Forge-Panel/Updates – abgleichen):"; printf '%s\n' "$x" | det; }
x=$(find /etc/nginx -type f -newerct "$SINCE" 2>/dev/null)
[ -n "$x" ] && { info "Nginx-Konfiguration seit $SINCE geändert:"; printf '%s\n' "$x" | det; }

sub "Paket-Integrität (dpkg --verify)"
pk=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*' 'nginx*' openssh-server sudo coreutils procps iproute2 util-linux login passwd bash cron findutils grep 2>/dev/null | awk '$1=="ii"{print $2}')
if [ -n "$pk" ]; then
  x=$(dpkg --verify $pk 2>/dev/null | awk '$2!="c" && $1 ~ /^..5/ {print $NF}')
  xb=$(printf '%s\n' "$x" | grep -E '^/(usr/)?(s?bin|lib(64)?|libexec)/|\.so(\.[0-9.]+)?$' | grep -vE '\.(conf|cnf|ini|rules|service|timer|socket|txt)$')
  xo=$(printf '%s\n' "$x" | grep -v '^$' | grep -vxF -f <(printf '%s\n' "$xb"))
  [ -n "$xb" ] && { crit "System-Binaries/Libraries weichen vom Paket ab (Manipulation?):"; printf '%s\n' "$xb" | det; }
  [ -n "$xo" ] && printf '%s\n' "$xo" | report_changed "Paket-Konfigurationsdateien lokal angepasst (kein Binary)"
  [ -z "$xb" ] && ok "Binaries/Libraries von PHP, Nginx, SSH, sudo, coreutils u. a. unverändert"
fi

sub "Temp-Verzeichnisse (/tmp, /var/tmp, /dev/shm)"
te=""; tk=""; tr_=""; tl=""
while IFS=$'\t' read -r f u s m; do
  bn="${f##*/}"
  if [[ "$bn" =~ $IOC_FILES_RE ]] || [ "$f" = /dev/shm/.cache.so ] || [[ "$f" =~ ^/(tmp|var/tmp|dev/shm)/nfs$ ]]; then tk+="$f ($u)"$'\n'; fi
  if [ "$s" -ge 512 ] && is_elf "$f"; then
    if ioc_hash "$f"; then tk+="$f ($u) – SHA-256 bekannter PHP2Shell-Malware"$'\n'
    elif [[ " $WEBUSERS www-data " == *" $u "* ]]; then te+="$f ($u, ${s} B, sha256 $(sha "$f" | cut -c1-16)…)"$'\n'
    else tr_+="ELF $f ($u)"$'\n'; fi
  elif [[ " $WEBUSERS www-data " == *" $u "* ]] && { [[ "$bn" == .* ]] || [ $((8#$m & 8#111)) -ne 0 ]; }; then
    tr_+="$f ($u, Modus $m)"$'\n'
  fi
  if [[ "$bn" =~ ^php[A-Za-z0-9]{6}$ ]] && [ -n "$(find "$f" -mmin +60 2>/dev/null)" ]; then tl+="$f"$'\n'; fi
done < <(find /tmp /var/tmp /dev/shm -xdev -type f -printf '%p\t%u\t%s\t%m\n' 2>/dev/null)
[ -n "$tk" ] && { crit "Bekannte PHP2Shell-Malware/Dateinamen:"; printf '%s' "$tk" | det; }
[ -n "$te" ] && { crit "ELF-Binaries von Web-Usern in Temp-Verzeichnissen:"; printf '%s' "$te" | det; }
[ -n "$tr_" ] && { rev "Auffällige Dateien in Temp-Verzeichnissen (versteckt/ausführbar/ELF):"; printf '%s' "$tr_" | det; }
if [ -n "$tl" ]; then
  att "$(cnt "$tl") verwaiste PHP-Upload-Tempdateien (> 60 Min.) – Indiz für abgebrochene Requests:"
  printf '%s' "$tl" | det
  x=$(printf '%s' "$tl" | xargs -r grep -laE "$IOC_STRINGS|<\?php|system\(" 2>/dev/null)
  [ -n "$x" ] && { att "…davon mit Exploit-Inhalten:"; printf '%s\n' "$x" | det; }
fi
[ -z "$tk$te$tr_$tl" ] && ok "Temp-Verzeichnisse unauffällig"

sub "Neue ELF-Binaries in /home seit $SINCE"
x=$(find /home -xdev \( -name node_modules -o -name .git -o -name vendor -o -name .npm -o -name .nvm -o -name .cache -o -name .composer -o -name .bun -o -name .volta \) -prune \
      -o -type f -perm /111 -newerct "$SINCE" -size -60M -print 2>/dev/null | while IFS= read -r f; do is_elf "$f" && echo "$f"; done)
if [ -n "$x" ]; then
  h=$(printf '%s\n' "$x" | while IFS= read -r f; do ioc_hash "$f" && echo "$f"; done)
  [ -n "$h" ] && { crit "Bekannte PHP2Shell-Malware (SHA-256-Treffer):"; printf '%s\n' "$h" | det; }
  rev "Neue/geänderte ELF-Binaries unter /home (z. B. FrankenPHP/RoadRunner legitim):"; printf '%s\n' "$x" | det
else ok "keine neuen ELF-Binaries unter /home"; fi

# ============================================================================
sect "7 · SSH-Logins"
CUR="SSH"
if ls /var/log/auth.log* >/dev/null 2>&1; then src=$(zcat -f /var/log/auth.log* 2>/dev/null | tr -d '\000'); lbl="auth.log"
else src=$(journalctl -q --no-pager --since "$SINCE" -t sshd -t sshd-session 2>/dev/null); lbl="journal"; fi
FORGE_IPS=" 159.203.150.232 159.203.150.216 45.55.124.124 165.227.248.218 "
lg=$(printf '%s\n' "$src" | grep -aoE 'Accepted [a-z-]+ for [^ ]+ from [0-9a-fA-F:.]+' | sed 's/Accepted //' | sort | uniq -c | sort -rn \
     | awk -v f="$FORGE_IPS" '{ip=$NF; t=""; if (index(f," " ip " ")) t="  (Laravel Forge)"; else if (ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) t="  (privates Netz)"; print $0 t}')
if [ -n "$lg" ]; then
  info "Erfolgreiche Logins ($lbl, verfügbarer Zeitraum) – mit Firewall-Whitelist abgleichen:"; printf '%s\n' "$lg" | det
  pw=$(printf '%s\n' "$lg" | grep -aE ' (password|keyboard-interactive) ')
  [ -n "$pw" ] && { rev "Passwort-Logins (Forge deaktiviert Passwort-Auth normalerweise):"; printf '%s\n' "$pw" | det; }
else info "keine SSH-Logins in $lbl gefunden"; fi

# ============================================================================
CUR=""
sect "ZUSAMMENFASSUNG · $HOST"
printf '  Prüfzeitraum ab %s · %d Site(s) · PHP: %s\n' "$SINCE" "${#SITES[@]}" "$(for v in "${PHPVERS[@]}"; do printf '%s ' "${FPM_VER[$v]:-$v(cli)}"; done)"
printf '\n  %-18s %s\n' "Verwundbar:"        "$([ ${#L_VULN[@]} -gt 0 ] && echo "${R}JA (${#L_VULN[@]})${N}" || echo "${G}nein${N}")"
printf '  %-18s %s\n'   "Kritische Indizien:" "$([ ${#L_CRIT[@]} -gt 0 ] && echo "${R}${#L_CRIT[@]}${N}" || echo "${G}0${N}")"
printf '  %-18s %s\n'   "Angriffsversuche:"   "$([ ${#L_ATT[@]} -gt 0 ] && echo "${Y}${#L_ATT[@]}${N}" || echo "${G}0${N}")"
printf '  %-18s %s\n'   "Zu prüfen:"          "$([ ${#L_REV[@]} -gt 0 ] && echo "${Y}${#L_REV[@]}${N}" || echo "${G}0${N}")"
if [ ${#L_VULN[@]} -gt 0 ]; then printf '\n  %sVERWUNDBAR%s\n' "$R" "$N"; printf '   - %s\n' "${L_VULN[@]}"; fi
if [ ${#L_CRIT[@]} -gt 0 ]; then printf '\n  %sKRITISCH%s\n' "$R" "$N";   printf '   - %s\n' "${L_CRIT[@]}"; fi
if [ ${#L_ATT[@]} -gt 0 ];  then printf '\n  %sVERSUCHE%s\n' "$Y" "$N";   printf '   - %s\n' "${L_ATT[@]}"; fi
if [ ${#L_REV[@]} -gt 0 ];  then printf '\n  %sPRÜFEN%s\n' "$Y" "$N";     printf '   - %s\n' "${L_REV[@]}"; fi
if [ ${#L_COV[@]} -gt 0 ];  then printf '\n  %sLOG-ABDECKUNG (Aussagekraft eingeschränkt)%s\n' "$B" "$N"; printf '   - %s\n' "${L_COV[@]}"; fi

printf '\n  %sURTEIL:%s ' "$C" "$N"
if [ ${#L_CRIT[@]} -gt 0 ]; then
  echo "${R}Kompromittierung möglich.${N} Server vom Netz nehmen, Logs/Report sichern, Befunde forensisch prüfen; im Zweifel neu aufsetzen und ALLE Secrets rotieren."
elif [ ${#L_VULN[@]} -gt 0 ]; then
  echo "${R}Server verwundbar.${N} Sofort patchen bzw. PHP-FPM neu starten, danach Skript erneut ausführen."
elif [ ${#L_ATT[@]} -gt 0 ]; then
  echo "${Y}Angriffsversuche, aber keine Kompromittierungsindizien.${N} War der Server im Zeitraum ungepatcht: Secrets rotieren (Memory-Disclosure ist ohne Spuren möglich)."
elif [ ${#L_REV[@]} -gt 0 ]; then
  echo "${Y}Keine eindeutigen Indizien – Prüfpunkte manuell bewerten.${N}"
else
  echo "${G}Keine Indizien gefunden.${N} (Begrenzt durch Log-Abdeckung; Secret-Rotation bleibt empfehlenswert, falls vor dem Patch exponiert.)"
fi
printf '  Report: %s\n\n' "$REPORT"

rc=0
[ ${#L_ATT[@]} -gt 0 ] || [ ${#L_REV[@]} -gt 0 ] && rc=1
[ ${#L_CRIT[@]} -gt 0 ] || [ ${#L_VULN[@]} -gt 0 ] && rc=2
sleep 1
exit $rc
