#!/usr/bin/env bash
###############################################################################
# attacker-setup.sh   (run on the KALI attacker box, e.g. 170.187.158.212)
# Stands up the attacker's infrastructure so the victim's lifecycle is real:
#   - HTTP :80   phishing page (invoice.html) + payload (update.exe) + C2/exfil
#                receiver (logs every beacon/upload)
#   - FTP  :21   anonymous  (exfil drop / staging)
#   - SSH  :2201-2203  same host key on 3 ports (case 5 "same host key")
#   - SMB  :445  guest share "share" (exfil)                    [Debian/Kali]
#   - tools: curl, hydra, nmap, dnsutils, socat  (for attack-*.sh)
# ICMP needs no service.
#
# Everything here is BENIGN - listeners + dummy files only. Run as root:
#   bash attacker-setup.sh            # start
#   bash attacker-setup.sh stop       # stop
###############################################################################
set -u
ACTION="${1:-start}"
WORK=/opt/eal-attacker
DOCROOT=$WORK/www
LOG=$WORK/logs
mkdir -p "$WORK" "$DOCROOT" "$LOG" "$WORK/ftproot" "$WORK/smbshare"

have(){ command -v "$1" >/dev/null 2>&1; }
PKG=""; have apt-get && PKG=apt; have dnf && PKG=${PKG:-dnf}; have yum && PKG=${PKG:-yum}
pkg_install(){ case "$PKG" in
  apt) DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1;;
  dnf) dnf install -y "$@" >/dev/null 2>&1;; yum) yum install -y "$@" >/dev/null 2>&1;; esac; }

stop_all(){
  echo "[*] Stopping attacker services..."
  pkill -f 'eal_c2_server.py' 2>/dev/null
  pkill -f 'pyftpdlib' 2>/dev/null
  pkill -f 'socat TCP-LISTEN:220' 2>/dev/null
  echo "[*] Stopped."
}
[ "$ACTION" = "stop" ] && { stop_all; exit 0; }

echo "[*] Installing attacker tooling (pkg: ${PKG:-?})..."
pkg_install python3 python3-pip socat curl hydra nmap dnsutils samba
python3 -m pip install --quiet --disable-pip-version-check pyftpdlib >/dev/null 2>&1 \
  || python3 -m pip install --quiet --break-system-packages pyftpdlib >/dev/null 2>&1 \
  || pkg_install python3-pyftpdlib

# ---- phishing page + dummy payload ------------------------------------------
cat > "$DOCROOT/invoice.html" <<'HTML'
<!doctype html><title>Invoice 426137677</title>
<h2>Your invoice is ready</h2>
<p>Please <a href="/update.exe">download the secure viewer</a> to open it.</p>
HTML
# benign dummy "payload" (NOT malware - just a marker file)
printf 'MZ EAL-DEMO benign payload marker - not an executable\n' > "$DOCROOT/update.exe"

# ---- HTTP C2 / phishing / exfil receiver on :80 -----------------------------
cat > "$WORK/eal_c2_server.py" <<'PY'
import http.server, socketserver, datetime, os, sys
DOC='/opt/eal-attacker/www'; LOG='/opt/eal-attacker/logs/c2.log'
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self,*a,**k): super().__init__(*a,directory=DOC,**k)
    def _log(self,extra=''):
        open(LOG,'a').write(f"{datetime.datetime.now().isoformat()} {self.client_address[0]} {self.command} {self.path} {extra}\n")
    def do_GET(self):
        self._log()
        if self.path=='/' or self.path.startswith('/beacon'):
            self.send_response(200); self.send_header('Content-Type','text/plain'); self.end_headers()
            try:self.wfile.write(b'ok\n')
            except: pass
            return
        return super().do_GET()
    def _read(self):
        try:
            n=int(self.headers.get('Content-Length',0) or 0)
            if n: self.rfile.read(n)
            return n
        except: return 0
    def do_POST(self): n=self._read(); self._log(f'bytes={n}'); self.send_response(200); self.end_headers();
    do_PUT=do_POST; do_PATCH=do_POST
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
with socketserver.ThreadingTCPServer(('0.0.0.0',80),H) as s: s.serve_forever()
PY
nohup python3 "$WORK/eal_c2_server.py" >"$LOG/c2.out" 2>&1 &
echo "[+] HTTP phishing/C2/exfil on :80  (docroot $DOCROOT, log $LOG/c2.log)"

# ---- anonymous FTP :21 -------------------------------------------------------
nohup python3 -m pyftpdlib -p 21 -d "$WORK/ftproot" -w >"$LOG/ftp.out" 2>&1 &
echo "[+] Anonymous FTP on :21"

# ---- SSH same host key on 2201-2203 -----------------------------------------
for p in 2201 2202 2203; do
  nohup socat TCP-LISTEN:$p,fork,reuseaddr TCP:127.0.0.1:22 >"$LOG/ssh_$p.out" 2>&1 &
  echo "[+] SSH (same host key) on :$p"
done

# ---- SMB guest share (Debian/Kali) ------------------------------------------
if have smbd || [ "$PKG" = "apt" ]; then
  chmod 0777 "$WORK/smbshare"
  grep -q '\[share\]' /etc/samba/smb.conf 2>/dev/null || cat >> /etc/samba/smb.conf <<SMB

[share]
   path = /opt/eal-attacker/smbshare
   browseable = yes
   read only = no
   guest ok = yes
   force user = nobody
SMB
  systemctl restart smbd 2>/dev/null || service smbd restart 2>/dev/null
  echo "[+] SMB guest share //<ip>/share"
fi

# ---- open host firewall ------------------------------------------------------
if have ufw; then for pp in 21 80 445 2201 2202 2203; do ufw allow "$pp"/tcp >/dev/null 2>&1; done; echo "[*] ufw opened 21,80,445,2201-3"; fi

echo
echo "[OK] Attacker infra up. Tools: curl hydra nmap dig socat (see attack-*.sh)."
echo "     Cloud security group must also allow inbound 21/80/445/2201-2203."
echo "     Beacon/exfil log: $LOG/c2.log   |  Stop: bash attacker-setup.sh stop"
