#!/usr/bin/env bash
###############################################################################
# setup-target-server.sh
# Stands up benign "victim" services on your Linux box (e.g. 170.187.158.212)
# so the EAL demo attacks reach REAL listeners and produce complete sessions:
#   - HTTP  :80    request logger (accepts web-exploit / exfil / beacon traffic)
#   - FTP   :21    anonymous login enabled (case 4/5 initial access)
#   - SSH   :2201-2203  same host key on 3 ports (case 5 "same host key")
#   - SMB   :445   guest-writable share "share" (case 5 exfil)  [best effort]
# ICMP needs no service.
#
# SAFE: nothing here is exploitable - these just accept connections and log.
# Run as root:   sudo bash setup-target-server.sh          (start everything)
#                sudo bash setup-target-server.sh stop      (stop everything)
###############################################################################
set -u
ACTION="${1:-start}"
WORK=/opt/eal-target
LOG=$WORK/logs
mkdir -p "$WORK" "$LOG"

have() { command -v "$1" >/dev/null 2>&1; }
PKG=""
have apt-get && PKG=apt
have dnf && PKG=dnf
have yum && PKG=${PKG:-yum}

pkg_install() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 ;;
    dnf) dnf install -y "$@" >/dev/null 2>&1 ;;
    yum) yum install -y "$@" >/dev/null 2>&1 ;;
  esac
}

stop_all() {
  echo "[*] Stopping EAL target services..."
  for f in http ftp smb socat; do
    [ -f "$WORK/$f.pid" ] && kill "$(cat "$WORK/$f.pid")" 2>/dev/null && rm -f "$WORK/$f.pid"
  done
  pkill -f 'eal_http_server.py' 2>/dev/null
  pkill -f 'pyftpdlib' 2>/dev/null
  pkill -f 'socat TCP-LISTEN:220' 2>/dev/null
  echo "[*] Stopped."
}

if [ "$ACTION" = "stop" ]; then stop_all; exit 0; fi

echo "[*] Installing prerequisites (pkg mgr: ${PKG:-unknown})..."
pkg_install python3 python3-pip socat
python3 -m pip install --quiet --disable-pip-version-check pyftpdlib >/dev/null 2>&1 || pkg_install python3-pyftpdlib

###########################################################################
# 1) HTTP request logger on :80
###########################################################################
cat > "$WORK/eal_http_server.py" <<'PY'
import http.server, socketserver, datetime, sys
class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        with open('/opt/eal-target/logs/http.log','a') as f:
            f.write(f"{datetime.datetime.now().isoformat()} {self.client_address[0]} {self.command} {self.path} UA={self.headers.get('User-Agent','')}\n")
    def _resp(self, code=200):
        self._log(); self.send_response(code)
        self.send_header('Content-Type','text/plain'); self.end_headers()
        try: self.wfile.write(b'ok\n')
        except Exception: pass
    def do_GET(self): self._resp(200)
    def do_POST(self):
        try:
            n=int(self.headers.get('Content-Length',0) or 0)
            if n: self.rfile.read(n)
        except Exception: pass
        self._resp(200)
    do_PUT=do_POST; do_PATCH=do_POST; do_DELETE=do_GET; do_HEAD=do_GET
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
port=int(sys.argv[1]) if len(sys.argv)>1 else 80
with socketserver.ThreadingTCPServer(('0.0.0.0',port),H) as s:
    s.serve_forever()
PY
nohup python3 "$WORK/eal_http_server.py" 80 >"$LOG/http.out" 2>&1 &
echo $! > "$WORK/http.pid"
echo "[+] HTTP logger on :80  (log: $LOG/http.log)"

###########################################################################
# 2) Anonymous FTP on :21
###########################################################################
mkdir -p "$WORK/ftproot"
nohup python3 -m pyftpdlib -p 21 -d "$WORK/ftproot" -w >"$LOG/ftp.out" 2>&1 &
echo $! > "$WORK/ftp.pid"
echo "[+] Anonymous FTP on :21  (root: $WORK/ftproot)"

###########################################################################
# 3) SSH on 2201-2203 (same host key as :22 via socat forward)
###########################################################################
for p in 2201 2202 2203; do
  nohup socat TCP-LISTEN:$p,fork,reuseaddr TCP:127.0.0.1:22 >"$LOG/ssh_$p.out" 2>&1 &
  echo "[+] SSH (same host key) on :$p -> 127.0.0.1:22"
done

###########################################################################
# 4) SMB guest share (best effort)
###########################################################################
if [ "$PKG" = "apt" ]; then
  pkg_install samba
  if have smbd; then
    mkdir -p "$WORK/smbshare"; chmod 0777 "$WORK/smbshare"
    grep -q '\[share\]' /etc/samba/smb.conf 2>/dev/null || cat >> /etc/samba/smb.conf <<SMB

[share]
   path = /opt/eal-target/smbshare
   browseable = yes
   read only = no
   guest ok = yes
   force user = nobody
SMB
    systemctl restart smbd 2>/dev/null || service smbd restart 2>/dev/null
    echo "[+] SMB guest share //<ip>/share"
  fi
else
  echo "[!] SMB share auto-setup only wired for apt distros - skip (case5 stage6)"
fi

###########################################################################
# 5) Open host firewall for these ports (if ufw present)
###########################################################################
if have ufw; then
  for pp in 21 80 445 2201 2202 2203; do ufw allow "$pp"/tcp >/dev/null 2>&1; done
  echo "[*] ufw rules added for 21,80,445,2201-2203"
fi

echo
echo "[✓] EAL target services are up. Verify from the attacker host:"
echo "    curl http://<ip>/  ;  ftp anonymous ; ssh -p 2201 <ip>"
echo "    Cloud provider firewall/security-group must also allow inbound 21/80/445/2201-2203."
echo "    Logs: $LOG/  |  Stop: sudo bash setup-target-server.sh stop"
