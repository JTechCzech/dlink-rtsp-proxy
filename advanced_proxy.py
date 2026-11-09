#!/usr/bin/env python3
"""
Local RTSP proxy for a mydlink camera, configured only by account + mydlink_id.

    python3 advanced_proxy.py --user you@example.com --password '...' --mydlink_id 12345678
    ffplay -rtsp_transport tcp rtsp://127.0.0.1:8555/live/profile.0

Everything else is discovered automatically:
  - access_token   via mydlink OAuth login (/oauth/authorize2)
  - camera LAN IP, MAC (device_id), cloud device_token  via /me/device/info
  - our own LAN IP  via the OS routing table (UDP connect towards the camera)

Password can also come from env MYDLINK_PASSWORD or an interactive prompt
(keeps it out of shell history / ps). Without --mydlink_id it lists devices.
The camera protocol itself lives in rtsp_proxy.py (CameraSession, handle_client).
"""
import argparse
import getpass
import hashlib
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import rtsp_proxy

API = "https://api.auto.mydlink.com"
OAUTH_CLIENT_ID = "mydlinkuapandroid"
OAUTH_SECRET = "5259311fa8cab90f09f2dc1e09d2d8ee"
UC_ID = "bd36a6c011f1287e"
APP_HEADERS = {
    "x-md-os-type": "android",
    "x-md-os-ver": "7.0",
    "x-md-app-ver": "02.12.02.496",
    "x-md-lang": "en",
    "User-Agent": "okhttp/4.8.0",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def md5_hex(s):
    return hashlib.md5(s.encode()).hexdigest()


def login(email, password):
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": "https://mydlink.com",
        "user_name": email,
        "password": md5_hex(password),
        "response_type": "token",
        "timestamp": str(int(time.time())),
        "uc_id": UC_ID,
        "uc_name": "rtsp_proxy",
    }
    query = f"/oauth/authorize2?{urllib.parse.urlencode(params)}"
    url = f"{API}{query}&sig={md5_hex(query + OAUTH_SECRET)}"
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(urllib.request.Request(url, headers=APP_HEADERS), timeout=15)
        location, body = resp.headers.get("Location"), resp.read()[:300]
    except urllib.error.HTTPError as e:  # 3xx lands here because redirects are disabled
        location, body = e.headers.get("Location"), e.read()[:300]
    if location:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        frag = urllib.parse.parse_qs(urllib.parse.urlparse(location).fragment)
        token = (qs.get("access_token") or frag.get("access_token") or [None])[0]
        if token:
            return token
    raise SystemExit(f"[login] failed (Location={location!r}, body={body!r})")


def api_call(path, access_token, body=None):
    url = f"{API}{path}?access_token={access_token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={**APP_HEADERS, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


class Auth:
    """Holds the access_token; on 'Invalid access token' (HTTP 400, error
    code 14) or 401/403 it logs in again with the stored credentials."""

    def __init__(self, user, password, token=None):
        self.user, self.password, self.token = user, password, token
        self.lock = threading.Lock()

    def relogin(self):
        if not (self.user and self.password):
            raise SystemExit("[auth] access_token rejected and no --user/--password to log in again")
        self.token = login(self.user, self.password)
        rtsp_proxy.ACCESS_TOKEN = self.token
        print("[auth] logged in, new access_token obtained")

    def call(self, path, body=None):
        with self.lock:
            if not self.token:
                self.relogin()
            token = self.token
        try:
            return api_call(path, token, body)
        except urllib.error.HTTPError as e:
            txt = e.read().decode(errors="replace")
            compact = txt.replace(" ", "")
            expired = e.code in (401, 403) or (
                e.code == 400 and ('"code":14' in compact or "access token" in txt.lower()))
            if not expired:
                raise RuntimeError(f"{path}: HTTP {e.code} {txt}") from None
            print(f"[auth] access_token rejected ({txt.strip()}) -> re-login")
            with self.lock:
                if self.token == token:  # nobody refreshed it meanwhile
                    self.relogin()
                token = self.token
            return api_call(path, token, body)


def local_ip_towards(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9))  # no packet is sent for UDP connect
        return s.getsockname()[0]
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="mydlink camera -> local RTSP proxy")
    ap.add_argument("--user", help="mydlink account e-mail")
    ap.add_argument("--password", help="mydlink password (or env MYDLINK_PASSWORD / prompt)")
    ap.add_argument("--mydlink_id", help="camera mydlink_id; omit to list devices")
    ap.add_argument("--access-token", help="skip login and use this access_token")
    ap.add_argument("--port", type=int, default=8555, help="local RTSP port (default 8555)")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="RTSP listen address (default 127.0.0.1)")
    ap.add_argument("--expose", action="store_true",
                    help="listen on 0.0.0.0 (stream reachable from the whole LAN)")
    ap.add_argument("--camera-ip", help="override camera LAN IP (default: from cloud)")
    ap.add_argument("--local-ip", help="override our LAN IP (default: auto)")
    a = ap.parse_args()
    if a.expose:
        a.bind = "0.0.0.0"

    if not a.access_token and not a.user:
        ap.error("--user is required (or --access-token)")
    pw = None
    if a.user:  # ask now, so a later automatic re-login never blocks on a prompt
        pw = a.password or os.environ.get("MYDLINK_PASSWORD") or getpass.getpass("mydlink password: ")
    auth = Auth(a.user, pw, a.access_token)

    devices = auth.call("/me/device/list").get("data", [])
    if not a.mydlink_id:
        print(f"{'mydlink_id':<12} {'model':<14} {'mac':<14} {'online':<7} name")
        for d in devices:
            print(f"{d['mydlink_id']:<12} {d['device_model']:<14} {d['mac']:<14} "
                  f"{str(d.get('online')):<7} {d['device_name']}")
        print("\nPick a camera and rerun with --mydlink_id <id>")
        return
    dev = next((d for d in devices if str(d["mydlink_id"]) == str(a.mydlink_id)), None)
    if dev is None:
        raise SystemExit(f"mydlink_id {a.mydlink_id} not found on this account "
                         f"(have: {', '.join(d['mydlink_id'] for d in devices)})")
    if not dev.get("online"):
        print(f"[warn] {dev['device_name']} reports offline in cloud, trying anyway")

    info_body = {"data": [{"mydlink_id": str(a.mydlink_id)}]}
    info = auth.call("/me/device/info", info_body)["data"][0]
    cam_ip = a.camera_ip or info.get("private_ip")
    if not cam_ip:
        raise SystemExit("cloud did not return camera private_ip, use --camera-ip")
    my_ip = a.local_ip or local_ip_towards(cam_ip)

    # Configure the protocol module (it reads these globals at call time).
    rtsp_proxy.ACCESS_TOKEN = auth.token
    # Every (re)connect fetches a fresh cloud device_token through Auth, so an
    # expired access_token is renewed transparently.
    rtsp_proxy.fetch_cloud_device_token = lambda: auth.call("/me/device/info", info_body)["data"][0]["device_token"]
    rtsp_proxy.MYDLINK_ID = str(a.mydlink_id)
    rtsp_proxy.DEVICE_ID = dev["mac"].upper()
    rtsp_proxy.CAMERA_HOST = cam_ip
    rtsp_proxy.MY_LAN_IP = my_ip
    rtsp_proxy.LISTEN_PORT = a.port
    print(f"[cfg] {info.get('device_model')} '{info.get('device_name')}' mac={dev['mac']} "
          f"cam={cam_ip} fw={info.get('fw_ver')} | local_ip={my_ip}")

    state = {"cam": None}
    cam_lock = threading.Lock()

    def get_session():
        """Return a live CameraSession, reconnecting if the old one died."""
        with cam_lock:
            cam = state["cam"]
            if cam is not None and not cam.dead:
                return cam
            if cam is not None:
                print("[cam] session dead -> reconnecting")
                cam.close()
                state["cam"] = None
            new = rtsp_proxy.CameraSession()
            try:
                new.connect()
            except Exception:
                new.close()
                raise
            state["cam"] = new
            return new

    def watchdog():
        backoff = 5
        while True:
            time.sleep(5)
            cam = state["cam"]
            if cam is not None and not cam.dead:
                continue
            try:
                get_session()
                backoff = 5
            except Exception as e:
                print(f"[cam] reconnect failed: {e}; retry in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)

    get_session()
    threading.Thread(target=watchdog, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port))
    srv.listen(5)
    shown = my_ip if a.bind == "0.0.0.0" else a.bind
    print(f"[rtsp] ready: rtsp://{shown}:{a.port}{rtsp_proxy.STREAM_PATH}")
    print(f"[rtsp] try:   ffplay -rtsp_transport tcp rtsp://{shown}:{a.port}{rtsp_proxy.STREAM_PATH}")
    try:
        while True:
            conn, addr = srv.accept()
            try:
                cam = get_session()
            except Exception as e:
                print(f"[rtsp] camera unavailable ({e}), dropping client {addr}")
                conn.close()
                continue
            threading.Thread(target=rtsp_proxy.handle_client, args=(conn, addr, cam), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        if state["cam"]:
            state["cam"].close()


if __name__ == "__main__":
    main()
