#!/usr/bin/env python3
"""
snapshot-proxy.py ADDR PORT TIMESTAMP LOG [NAME UPSTREAM] -- the only thing a
golden-set guest can reach while it installs. Ubuntu: GET /<run>/ubuntu/<path>
is fetched from https://snapshot.ubuntu.com/ubuntu/<TIMESTAMP>/<path>, i.e. the
archive (and its -security/-updates pockets) frozen at one moment; apt checks
the signed Release files as usual, so the proxy needs no trust. With NAME and
UPSTREAM, GET /<run>/NAME/<path> is fetched from UPSTREAM<path> instead (a
tree that never changes, such as a Fedora release; TIMESTAMP is then -).
Every fetch goes to LOG: time, run, path, status, bytes. Nothing else is
served.

    snapshot-proxy.py 192.168.150.1 3142 20261015T000000Z snapshot.log
    snapshot-proxy.py 192.168.150.1 3143 - fedora-44.log fedora \
        https://dl.fedoraproject.org/pub/fedora/linux/releases/44/
"""
import http.server
import shutil
import socketserver
import sys
import time
import urllib.error
import urllib.request

ADDR, PORT, TS, LOG = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
if len(sys.argv) > 6:
    NAME, UPSTREAM = sys.argv[5], sys.argv[6]
else:
    NAME, UPSTREAM = 'ubuntu', f'https://snapshot.ubuntu.com/ubuntu/{TS}/'


class Handler(http.server.BaseHTTPRequestHandler):
    def _log(self, run, path, status, n):
        with open(LOG, 'a') as f:
            f.write(f'{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}\t{run}\t{path}\t{status}\t{n}\n')

    def _serve(self, body):
        parts = self.path.lstrip('/').split('/', 2)
        if len(parts) < 3 or parts[1] != NAME or '..' in parts[2]:
            self.send_error(404)
            self._log('-', self.path, 404, 0)
            return
        run, path = parts[0], parts[2]
        try:
            r = urllib.request.urlopen(urllib.request.Request(UPSTREAM + path, method=self.command), timeout=120)
        except urllib.error.HTTPError as e:
            self.send_error(e.code)
            self._log(run, path, e.code, 0)
            return
        except Exception:
            self.send_error(502)
            self._log(run, path, 502, 0)
            return
        self.send_response(r.status)
        for h in ('Content-Type', 'Content-Length', 'Last-Modified'):
            if r.headers.get(h):
                self.send_header(h, r.headers[h])
        self.end_headers()
        n = 0
        if body:
            n = r.headers.get('Content-Length') or 0
            shutil.copyfileobj(r, self.wfile)
        self._log(run, path, r.status, n)

    def do_GET(self):
        self._serve(True)

    def do_HEAD(self):
        self._serve(False)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


Server((ADDR, PORT), Handler).serve_forever()
