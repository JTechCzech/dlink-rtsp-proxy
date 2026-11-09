#!/usr/bin/env python3
"""
Local RTSP proxy for a DCS-P6000LH camera on the LAN.

Speaks the camera's real protocol internally (WSS control channel on :8080,
SA "conn_init"/"conn_add_candidate" handshake, RTSP-over-JSON tunnel via
"rtsp_command", raw RTP/RTCP demuxed from the SA UDP channel's $-framing),
and exposes a completely standard RTSP server locally that any player can
connect to:

    ffplay -rtsp_transport tcp rtsp://127.0.0.1:8554/live/profile.0
    vlc --rtsp-tcp rtsp://127.0.0.1:8554/live/profile.0

Protocol notes (reverse-engineered from a real tcpdump + decompiled app):
  - Control: wss://<cam>:8080/SwitchCamera, JSON commands, sequence_id required
    on every message or the device silently drops it.
  - device_token = device_id + "-" + sha1(cloud_device_token + salt), where
    cloud_device_token comes from the mydlink cloud API (rotates - refetch
    each run) and salt comes from sign_in's reply.
  - SA tunnel: conn_init -> conn_add_candidate -> rtsp_command (raw RTSP text
    tunneled as JSON) all ride over the SAME authenticated WSS connection.
  - Actual media arrives as plain UDP on the port we announce in conn_init,
    framed exactly like RTSP-interleaved-over-TCP: 0x24, channel, len(2B BE),
    payload. Channels: 0x20=video RTP (H264, PT96), 0x21=video RTCP,
    0x22=audio RTP (Opus, PT97), 0x23=audio RTCP, 0xFF=SA control.
  - 0xFF control = connectivity check (from libsa.so sa_util_create_ctrl_data /
    sa_util_verify_peer_msg). Payload: type(1) + nonce(4B BE) + MD5(nonce as
    LE uint32 bytes + tokA + tokB), tokens are the hex strings from conn_init
    device_info. Camera signs (device_token, client_token), client signs
    (client_token, device_token). Types: 0 = check (peer not yet verified),
    1 = client check after it verified the camera, 2 = camera check after it
    verified the client. Camera starts sending media once it gets a valid
    type 1. Type 5 (1-byte payload) = keepalive, camera echoes it.
  - Media is SRTP/SRTCP AES_CM_128_HMAC_SHA1_80 (RTP header in clear), key
    MD5(device_token+client_token)||MD5(client_token+device_token) using the
    hex tokens from conn_init device_info (see sa_srtp.py).
  - The client MUST send RTCP Receiver Reports back (same framing, channel
    0x21/0x23) or the camera appears to stop pushing real video (only pings).
"""
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request

import websocket

from sa_srtp import SrtpContext, master_from_tokens

# Standalone use: set these via environment variables. advanced_proxy.py
# fills them in automatically (login + cloud lookup), which is the
# recommended way to run the proxy.
CAMERA_HOST = os.environ.get("DLINK_CAMERA_HOST", "")    # camera LAN IP
DEVICE_ID = os.environ.get("DLINK_DEVICE_ID", "")        # camera MAC, upper-case hex, no colons
ACCESS_TOKEN = os.environ.get("DLINK_ACCESS_TOKEN", "")  # mydlink cloud access_token
MYDLINK_ID = os.environ.get("DLINK_MYDLINK_ID", "")
MY_LAN_IP = os.environ.get("DLINK_LOCAL_IP", "")         # this machine's LAN IP
LISTEN_PORT = 8555
STREAM_PATH = "/live/profile.0"
STUN_HOST = "mp-eu-sas.auto.mydlink.com"
STUN_PORT = 3478

# Fixed local ports facing the real RTSP player (ffplay/vlc) for plain UDP
# transport - lets the player's own, standards-correct RTP/RTCP stack
# (automatic Receiver Reports etc.) handle the media, instead of our
# hand-rolled minimal RTCP.
RELAY_PORTS = {
    "video_rtp": 16000, "video_rtcp": 16001,
    "audio_rtp": 16002, "audio_rtcp": 16003,
}


def stun_query(sock, stun_host=STUN_HOST, stun_port=STUN_PORT, timeout=5):
    """Minimal RFC 5389 STUN Binding Request. Returns (ip, port) as seen by
    the STUN server, using the given already-bound UDP socket, or None."""
    magic_cookie = 0x2112A442
    txn_id = bytes(random.randint(0, 255) for _ in range(12))
    req = struct.pack(">HHI", 0x0001, 0, magic_cookie) + txn_id
    dest = (socket.gethostbyname(stun_host), stun_port)
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        sock.sendto(req, dest)
        while True:
            data, addr = sock.recvfrom(2048)
            if len(data) < 20:
                continue
            msg_type, msg_len, cookie = struct.unpack(">HHI", data[:8])
            if cookie != magic_cookie or data[8:20] != txn_id:
                continue  # not our STUN response (could be camera SA traffic)
            if msg_type != 0x0101:
                return None  # error response
            body = data[20:20 + msg_len]
            off = 0
            mapped = None
            while off + 4 <= len(body):
                attr_type, attr_len = struct.unpack(">HH", body[off:off + 4])
                val = body[off + 4:off + 4 + attr_len]
                if attr_type == 0x0020 and len(val) >= 8:  # XOR-MAPPED-ADDRESS
                    family = val[1]
                    xport = struct.unpack(">H", val[2:4])[0]
                    port = xport ^ (magic_cookie >> 16)
                    if family == 0x01:
                        xaddr = struct.unpack(">I", val[4:8])[0]
                        addr_int = xaddr ^ magic_cookie
                        mapped = (socket.inet_ntoa(struct.pack(">I", addr_int)), port)
                elif attr_type == 0x0001 and len(val) >= 8:  # MAPPED-ADDRESS
                    family = val[1]
                    port = struct.unpack(">H", val[2:4])[0]
                    if family == 0x01:
                        mapped = (socket.inet_ntoa(val[4:8]), port)
                off += 4 + attr_len + (attr_len % 4 and 4 - attr_len % 4 or 0)
            return mapped
    except socket.timeout:
        return None
    finally:
        sock.settimeout(old_timeout)

# Media channels come in groups of 4 (video RTP/RTCP, audio RTP/RTCP); the
# base varies per session (0x20 in one capture, 0x40 live), so we learn it
# from the first media packet and map by offset.
CHANNEL_OFFSETS = {0: "video_rtp", 1: "video_rtcp", 2: "audio_rtp", 3: "audio_rtcp"}
NAME_TO_OFFSET = {v: k for k, v in CHANNEL_OFFSETS.items()}


def fetch_cloud_device_token():
    body = json.dumps({"data": [{"mydlink_id": MYDLINK_ID}]}).encode()
    req = urllib.request.Request(
        f"https://api.auto.mydlink.com/me/device/info?access_token={ACCESS_TOKEN}",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.loads(r.read())
    return d["data"][0]["device_token"]


def new_client_id():
    # matches the real app's format exactly: <7-digit>-<uuid 8-4-4-4-12>
    rc = lambda n: "".join(random.choices("0123456789abcdef", k=n))
    return f"{random.randint(1000000, 9999999)}-{rc(8)}-{rc(4)}-{rc(4)}-{rc(4)}-{rc(12)}"


def rtsp_framing_pack(channel, payload):
    return bytes([0x24, channel]) + struct.pack(">H", len(payload)) + payload


def sa_ctrl_sign(nonce, tok_a, tok_b):
    return hashlib.md5(struct.pack("<I", nonce) + tok_a.encode() + tok_b.encode()).digest()


def sa_ctrl_build(msg_type, dev_tok, cli_tok):
    """Client-side connectivity check packet (types 0/1)."""
    nonce = random.getrandbits(32)
    body = bytes([msg_type]) + struct.pack(">I", nonce) + sa_ctrl_sign(nonce, cli_tok, dev_tok)
    return rtsp_framing_pack(0xFF, body)


def sa_ctrl_verify_cam(payload, dev_tok, cli_tok):
    """Verify a camera-sent check (types 0/2)."""
    if len(payload) < 21:
        return False
    nonce = struct.unpack(">I", payload[1:5])[0]
    return payload[5:21] == sa_ctrl_sign(nonce, dev_tok, cli_tok)


def build_rtcp_rr(reporter_ssrc):
    # Minimal valid RTCP Receiver Report, RC=0 (no report blocks).
    return bytes([0x80, 0xC9, 0x00, 0x01]) + struct.pack(">I", reporter_ssrc)


class CameraSession:
    def __init__(self):
        self.seq = 2000
        self.ws = None
        self.local_cid = None
        self.token = None
        self.conn_id = None
        self.cam_addr = None
        self.client_id = None
        self.udp_sock = None
        self.ws_lock = threading.Lock()
        self.reporter_ssrc = random.randint(1, 0x7FFFFFFF)
        self.sdp = None
        self.cam_rtsp_session = None
        self.active_client = None  # (sock, {name: channel}) for the current TCP-interleaved client
        self.client_lock = threading.Lock()
        self.running = True
        self.dead = False            # set when the WSS control channel fails -> caller reconnects
        self.udp_relay_socks = {}    # name -> bound local UDP socket facing the real player
        self.udp_relay_client = {}   # name -> (ip, port) of the real player, for output
        self.chan_base = None        # learned media channel base (0x20, 0x40, ...)

    def next_seq(self):
        self.seq += 1
        return self.seq

    def _send(self, obj):
        try:
            self.ws.send(json.dumps(obj))
        except Exception:
            self.dead = True
            raise

    def _recv(self, timeout=8):
        try:
            self.ws.settimeout(timeout)
            return json.loads(self.ws.recv())
        except Exception:
            self.dead = True
            raise

    def close(self):
        """Stop all threads and release sockets/ports so a new session can start."""
        self.running = False
        self.dead = True
        socks = [self.udp_sock, *self.udp_relay_socks.values()]
        if self.active_client:
            socks.append(self.active_client[0])
        for sock in socks:
            if not sock:
                continue
            # shutdown() first: on Linux a plain close() does not wake a thread
            # blocked in recvfrom(), the socket then stays bound (EADDRINUSE).
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass
        self.udp_relay_socks = {}

    def connect(self):
        print("[cam] fetching fresh cloud device_token ...")
        cloud_token = fetch_cloud_device_token()

        self.ws = websocket.create_connection(
            f"wss://{CAMERA_HOST}:8080/SwitchCamera",
            sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False},
            timeout=10, header=["Pragma: no-cache", "Cache-Control: no-cache"])

        self._send({"sequence_id": self.next_seq(), "command": "sign_in", "client_id": "", "timestamp": int(time.time())})
        r = self._recv()
        salt = r["salt"]
        self.local_cid = r["local_cid"]
        self.token = DEVICE_ID + "-" + hashlib.sha1((cloud_token + salt).encode()).hexdigest()
        print(f"[cam] signed in, local_cid={self.local_cid}")

        self.client_id = new_client_id()
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind((MY_LAN_IP, 0))
        self.my_port = self.udp_sock.getsockname()[1]

        self.stun_mapped = stun_query(self.udp_sock)
        if self.stun_mapped:
            print(f"[stun] mapped address: {self.stun_mapped[0]}:{self.stun_mapped[1]}")
        else:
            print("[stun] query failed, falling back to LAN address")
            self.stun_mapped = (MY_LAN_IP, self.my_port)

        # Real app behaviour (from a synced Frida+tcpdump capture): the FIRST
        # conn_init of the whole app session includes "need_stream_info":1,
        # whose reply embeds the SDP directly as "stream_info": [...] - no
        # separate DESCRIBE round-trip at all. That SAME conn_id is then used
        # directly for the fast_play PLAY (no throwaway conn). Later
        # reconnects skip need_stream_info (SDP is static/cached) and just
        # do a fresh conn_init + PLAY.
        self._new_conn(need_sdp=True)
        self.conn_used_for_play = False

        threading.Thread(target=self._keepalive_loop, daemon=True).start()
        threading.Thread(target=self._udp_ping_loop, daemon=True).start()
        threading.Thread(target=self._udp_recv_loop, daemon=True).start()

        for name, port in RELAY_PORTS.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((MY_LAN_IP, port))
            self.udp_relay_socks[name] = s
        threading.Thread(target=self._relay_rtcp_back, args=("video_rtcp",), daemon=True).start()
        threading.Thread(target=self._relay_rtcp_back, args=("audio_rtcp",), daemon=True).start()
        print(f"[relay] UDP relay ports facing the real player: {RELAY_PORTS}")

    def _relay_rtcp_back(self, name):
        """Forward the real player's own (standards-correct) RTCP packets
        back to the camera, re-wrapped in the SA $-framing."""
        sock = self.udp_relay_socks[name]
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except Exception as e:
                print(f"[relay] {name} recv error: {e}")
                continue
            self.udp_relay_client[name] = addr
            try:
                if self.chan_base is None:
                    continue
                self.udp_sock.sendto(rtsp_framing_pack(self.chan_base + NAME_TO_OFFSET[name], self.srtp.protect_rtcp(data)), self.cam_addr)
            except Exception:
                pass

    def _new_conn(self, need_sdp=False):
        """conn_init + conn_add_candidate, establishing a fresh conn_id."""
        req = {
            "client_info": {"local_port": self.my_port, "local_addr": MY_LAN_IP},
            "device_id": DEVICE_ID, "local_cid": self.local_cid, "device_token": self.token,
            "sequence_id": self.next_seq(), "sa_cmd": 1, "client_id": self.client_id,
            "command": "conn_init", "timestamp": int(time.time()),
        }
        if need_sdp:
            req["need_stream_info"] = 1
        self._send(req)
        r = self._recv()
        if r.get("code") != 0:
            raise RuntimeError(f"conn_init failed: {r}")
        self.conn_id = r["conn_id"]
        dev_info = r["device_info"]
        self.cam_addr = (dev_info["local_addr"], dev_info["local_port"])
        self.sa_dev_tok = dev_info["device_token"]
        self.sa_cli_tok = dev_info["client_token"]
        # SRTP: master = MD5(dev+cli) || MD5(cli+dev), same key both directions
        self.srtp = SrtpContext(*master_from_tokens(self.sa_dev_tok, self.sa_cli_tok))
        self.chan_base = None
        self.sa_peer_verified = False   # got a valid check from camera -> we send type 1
        self.sa_peer_confirmed = False  # got camera type 2 -> path up on both sides
        self.conn_used_for_play = False
        if need_sdp and r.get("stream_info"):
            self.sdp = r["stream_info"][0]
        print(f"[cam] conn_id={self.conn_id} cam media endpoint={self.cam_addr}, our udp port={self.my_port}")

        self._send({
            "client_info": {"remote_addr": MY_LAN_IP, "remote_port": self.my_port},
            "stun_info": {"host_port": STUN_PORT, "host_addr": STUN_HOST},
            "sa_ver": 1, "device_id": DEVICE_ID, "local_cid": self.local_cid, "device_token": self.token,
            "sequence_id": self.next_seq(), "sa_cmd": 1, "conn_id": self.conn_id, "client_id": self.client_id,
            "command": "conn_add_candidate", "timestamp": int(time.time()),
        })
        r2 = self._recv()
        print(f"[cam] conn_add_candidate reply: {r2}")

    def rtsp_command(self, rtsp_text, extra=None):
        with self.ws_lock:
            msg = {
                "device_id": DEVICE_ID, "local_cid": self.local_cid, "device_token": self.token,
                "sequence_id": self.next_seq(), "sa_cmd": 1, "conn_id": self.conn_id, "rtsp_id": 8,
                "rtsp_msg": rtsp_text, "client_id": self.client_id, "command": "rtsp_command",
                "timestamp": int(time.time()),
            }
            if extra:
                msg.update(extra)
            self._send(msg)
            r = self._recv()
            return r.get("rtsp_msg", "") if r else ""

    def _keepalive_loop(self):
        while self.running:
            time.sleep(25)
            try:
                with self.ws_lock:
                    self._send({"local_cid": self.local_cid, "device_token": self.token,
                                "sequence_id": self.next_seq(), "command": "keep_alive",
                                "client_id": "", "timestamp": int(time.time())})
                    self._recv(timeout=5)
            except Exception as e:
                if self.running:
                    print(f"[cam] keepalive error: {e} -> session marked dead")
                self.dead = True
                return

    def _udp_ping_loop(self):
        """SA connectivity check, client side (mirrors real app timing):
        type 0 every ~250ms until the camera's check verifies, then type 1
        until the camera answers with type 2, then type 5 keepalive ~15s."""
        last_ka = 0
        while self.running:
            try:
                if not self.sa_peer_confirmed:
                    t = 1 if self.sa_peer_verified else 0
                    self.udp_sock.sendto(sa_ctrl_build(t, self.sa_dev_tok, self.sa_cli_tok), self.cam_addr)
                    time.sleep(0.25)
                    continue
                if time.time() - last_ka >= 15:
                    self.udp_sock.sendto(rtsp_framing_pack(0xFF, b"\x05"), self.cam_addr)
                    last_ka = time.time()
            except Exception as e:
                print(f"[sa] ctrl send error: {e}")
            time.sleep(0.25)

    def _handle_sa_ctrl(self, payload):
        if not payload:
            return
        t = payload[0]
        if t in (0, 1, 2):
            if not sa_ctrl_verify_cam(payload, self.sa_dev_tok, self.sa_cli_tok):
                print(f"[sa] ctrl type {t} FAILED verification: {payload.hex()}")
                return
            if not self.sa_peer_verified:
                print(f"[sa] camera check verified (type {t}) -> answering with type 1")
                self.sa_peer_verified = True
                self.udp_sock.sendto(sa_ctrl_build(1, self.sa_dev_tok, self.sa_cli_tok), self.cam_addr)
            if t == 2 and not self.sa_peer_confirmed:
                print("[sa] camera confirmed our check (type 2) -> path UP")
                self.sa_peer_confirmed = True
        elif t != 5:
            print(f"[sa] unknown ctrl type {t}: {payload.hex()}")

    def _udp_recv_loop(self):
        pkt_count = 0
        chan_counts = {}
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
            except Exception as e:
                print(f"[udp] recv error: {e}")
                continue
            pkt_count += 1
            if len(data) < 4 or data[0] != 0x24:
                print(f"[udp] #{pkt_count} non-framed packet from {addr}, len={len(data)} hex={data[:16].hex()}")
                continue
            channel = data[1]
            length = struct.unpack(">H", data[2:4])[0]
            payload = data[4:4 + length]
            if channel != 0xFF and self.chan_base is None:
                self.chan_base = channel & ~0x03
                print(f"[udp] media channel base = 0x{self.chan_base:02x}")
            name = CHANNEL_OFFSETS.get(channel - self.chan_base) if self.chan_base is not None and channel != 0xFF else None
            chan_counts[channel] = chan_counts.get(channel, 0) + 1
            if pkt_count % 20 == 1:
                print(f"[udp] #{pkt_count} chan=0x{channel:02x} name={name} len={len(payload)} counts={chan_counts} active_client={self.active_client is not None}")
            if channel == 0xFF:
                self._handle_sa_ctrl(payload)
                continue
            if name is None:
                continue
            # media is SRTP (AES_CM_128_HMAC_SHA1_80) - decrypt to plain RTP/RTCP
            if name.endswith("_rtp"):
                payload = self.srtp.unprotect_rtp(payload)
            else:
                payload = self.srtp.unprotect_rtcp(payload)
            if payload is None:
                self.srtp_fail = getattr(self, "srtp_fail", 0) + 1
                if self.srtp_fail % 50 == 1:
                    print(f"[srtp] auth failed on {name} (total {self.srtp_fail})")
                continue

            # Forward to a real player on plain UDP, if one has SETUP'd via UDP
            # transport - let IT generate the real RTCP Receiver Reports
            # (handled by _relay_rtcp_back on the way back), instead of us.
            udp_client = self.udp_relay_client.get(name)
            if udp_client:
                try:
                    self.udp_relay_socks[name].sendto(payload, udp_client)
                except Exception:
                    pass
            elif name.endswith("_rtcp") and len(payload) >= 8 and (payload[1] in (200, 201)):
                # no real UDP player attached - fall back to our own minimal RR
                # (only relevant for the TCP-interleaved path)
                rr = build_rtcp_rr(self.reporter_ssrc)
                try:
                    self.udp_sock.sendto(rtsp_framing_pack(channel, self.srtp.protect_rtcp(rr)), self.cam_addr)
                except Exception:
                    pass

            with self.client_lock:
                client = self.active_client
            if client is None:
                continue
            sock, chan_map = client
            out_channel = chan_map.get(name)
            if out_channel is None:
                continue
            try:
                sock.sendall(rtsp_framing_pack(out_channel, payload))
            except Exception:
                with self.client_lock:
                    if self.active_client is client:
                        self.active_client = None

    def start_real_play(self):
        """fast_play PLAY, matching the real captured app flow exactly: PLAY
        is the first rtsp_command on a conn_id that was JUST created (either
        the startup conn_id, used once, or a fresh one for a later re-play),
        with an invented Session string and fast_play fields set."""
        if self.conn_used_for_play:
            with self.ws_lock:
                self._new_conn(need_sdp=False)
        self.conn_used_for_play = True
        session_id = "".join(random.choices("0123456789ABCDEF", k=8))
        r = self.rtsp_command(
            f"PLAY rtsp://127.0.0.1{STREAM_PATH} RTSP/1.0\r\nCSeq: 2\r\n"
            f"User-Agent: LibVLC/3.0.8 (LIVE555 Streaming Media v2014.02.26)\r\n"
            f"Session: {session_id}\r\nRange: npt=0.000-\r\n\r\n",
            extra={"fast_play_media": [1, 1, 0], "fast_play": 1, "rtsp_id": 8})
        print(f"[cam] fast_play PLAY response:\n{r}")
        self.cam_rtsp_session = session_id
        self.rtsp_cseq = 5
        print(f"[cam] fast_play PLAY issued, camera session={session_id}")
        threading.Thread(target=self._rtsp_keepalive_loop, args=(session_id,), daemon=True).start()

    def _rtsp_keepalive_loop(self, session_id):
        """The real app sends OPTIONS over the rtsp_command tunnel roughly
        every ~15s for as long as it's actually viewing - mirror that."""
        while self.running and self.cam_rtsp_session == session_id:
            time.sleep(15)
            if self.cam_rtsp_session != session_id:
                return
            self.rtsp_cseq += 1
            try:
                r = self.rtsp_command(
                    f"OPTIONS rtsp://127.0.0.1{STREAM_PATH} RTSP/1.0\r\nCSeq: {self.rtsp_cseq}\r\n"
                    f"User-Agent: LibVLC/3.0.8 (LIVE555 Streaming Media v2014.02.26)\r\n"
                    f"Session: {session_id}\r\n\r\n")
                print(f"[cam] rtsp keepalive OPTIONS -> {r.splitlines()[0] if r else '(none)'}")
            except Exception as e:
                print(f"[cam] rtsp keepalive error: {e}")
                return


def rewrite_sdp_base(sdp_text):
    return sdp_text.replace(
        "rtsp://127.0.0.1/live/profile.0",
        f"rtsp://127.0.0.1:{LISTEN_PORT}{STREAM_PATH}")


def parse_transport_interleaved(headers):
    t = headers.get("transport", "")
    for part in t.split(";"):
        if part.startswith("interleaved="):
            lo, hi = part.split("=", 1)[1].split("-")
            return int(lo), int(hi)
    return None


def parse_transport_client_port(headers):
    t = headers.get("transport", "")
    if "TCP" in t.upper():
        return None
    for part in t.split(";"):
        if part.startswith("client_port="):
            lo, hi = part.split("=", 1)[1].split("-")
            return int(lo), int(hi)
    return None


def read_rtsp_request(f):
    line = f.readline().decode("latin1")
    if not line:
        return None, None, None
    parts = line.strip().split(" ")
    if len(parts) < 3:
        return None, None, None
    method, url = parts[0], parts[1]
    headers = {}
    while True:
        hline = f.readline().decode("latin1")
        if hline in ("\r\n", "\n", ""):
            break
        if ":" in hline:
            k, v = hline.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, url, headers


def handle_client(conn, addr, cam: CameraSession):
    print(f"[rtsp] client connected: {addr}")
    f = conn.makefile("rb")
    chan_map = {}
    try:
        while True:
            method, url, headers = read_rtsp_request(f)
            if method is None:
                break
            cseq = headers.get("cseq", "1")
            print(f"[rtsp] <- {method} {url}")

            if method == "OPTIONS":
                resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                        f"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER\r\n\r\n")
                conn.sendall(resp.encode())

            elif method == "DESCRIBE":
                body = rewrite_sdp_base(cam.sdp)
                resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                        f"Content-Base: {url.rstrip('/')}/\r\n"
                        f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n{body}")
                conn.sendall(resp.encode())

            elif method == "SETUP":
                track = "video" if url.endswith("/video") else "audio" if url.endswith("/audio") else None
                interleaved = parse_transport_interleaved(headers)
                client_ports = parse_transport_client_port(headers)
                session_id = "CAFEBABE"
                if track and interleaved:
                    lo, hi = interleaved
                    chan_map[f"{track}_rtp"] = lo
                    chan_map[f"{track}_rtcp"] = hi
                    resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                            f"Transport: RTP/AVP/TCP;unicast;interleaved={lo}-{hi}\r\n"
                            f"Session: {session_id};timeout=60\r\n\r\n")
                elif track and client_ports:
                    lo, hi = client_ports
                    cam.udp_relay_client[f"{track}_rtp"] = (addr[0], lo)
                    cam.udp_relay_client[f"{track}_rtcp"] = (addr[0], hi)
                    srv_lo = RELAY_PORTS[f"{track}_rtp"]
                    srv_hi = RELAY_PORTS[f"{track}_rtcp"]
                    resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                            f"Transport: RTP/AVP;unicast;client_port={lo}-{hi};"
                            f"server_port={srv_lo}-{srv_hi}\r\n"
                            f"Session: {session_id};timeout=60\r\n\r\n")
                else:
                    resp = f"RTSP/1.0 461 Unsupported Transport\r\nCSeq: {cseq}\r\n\r\n"
                conn.sendall(resp.encode())

            elif method == "PLAY":
                with cam.client_lock:
                    cam.active_client = (conn, dict(chan_map))
                if cam.cam_rtsp_session is None:
                    cam.start_real_play()
                resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: CAFEBABE\r\n"
                        f"Range: npt=0.000-\r\n\r\n")
                conn.sendall(resp.encode())
                print(f"[rtsp] -> streaming to {addr}, channel map={chan_map}")

            elif method == "GET_PARAMETER":
                conn.sendall(f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n".encode())

            elif method == "TEARDOWN":
                conn.sendall(f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n".encode())
                break

            else:
                conn.sendall(f"RTSP/1.0 501 Not Implemented\r\nCSeq: {cseq}\r\n\r\n".encode())
    except Exception as e:
        print(f"[rtsp] client {addr} error: {e}")
    finally:
        with cam.client_lock:
            if cam.active_client and cam.active_client[0] is conn:
                cam.active_client = None
        conn.close()
        print(f"[rtsp] client disconnected: {addr}")


def main():
    missing = [n for n in ("CAMERA_HOST", "DEVICE_ID", "ACCESS_TOKEN", "MYDLINK_ID", "MY_LAN_IP")
               if not globals()[n]]
    if missing:
        sys.exit(f"missing config: {', '.join(missing)} (set DLINK_* env vars, or use advanced_proxy.py)")
    cam = CameraSession()
    cam.connect()
    print(f"[cam] ready, SDP:\n{cam.sdp}\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    print(f"[rtsp] listening on rtsp://127.0.0.1:{LISTEN_PORT}{STREAM_PATH}")
    print(f"[rtsp] try: ffplay -rtsp_transport tcp rtsp://127.0.0.1:{LISTEN_PORT}{STREAM_PATH}")

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr, cam), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        cam.running = False


if __name__ == "__main__":
    main()
