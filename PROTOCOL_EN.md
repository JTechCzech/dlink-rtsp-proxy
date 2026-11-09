# mydlink camera (DCS-P6000LH) – local live view protocol

*Česká verze: [PROTOCOL.md](PROTOCOL.md)*

A description of the complete communication needed to get live video from the
camera on the LAN, as implemented by `rtsp_proxy.py`, `sa_srtp.py` and
`advanced_proxy.py`. Sources: the decompiled mydlink app (Java), disassembly of
`libsa.so`, a Frida capture of the WSS messages, and a tcpdump capture of the
UDP traffic.

Verified with: FW 1.06.01, agent 3.5.20-b02, HW A1.

---

## 0. In plain words: how it all works

The camera has no simple "play video" link with a password. The mydlink app
instead goes through a multi-step routine. The proxy (`advanced_proxy.py`)
imitates that routine and presents itself as an ordinary RTSP camera that VLC,
ffplay or Home Assistant can understand.

### Step 1: Authenticating with D-Link (cloud)

First, the proxy logs in to D-Link's servers just like the phone app does,
with the e-mail and password of the mydlink account. In return it gets an
**access token**, a kind of temporary ticket. With it, it asks D-Link for:

- **the list of devices on the account**: the right camera is picked by `mydlink_id`,
- **the camera's address on the home network** (e.g. `192.168.0.194`),
- **the camera's cloud token**: a secret string the camera knows too. It is
  the one thing the camera and the cloud share, and it lets the camera
  recognise that whoever connects is trusted by the account owner. This token
  changes from time to time, so it is downloaded again on every connection.

The ticket (access token) eventually expires. When the cloud says "invalid
token", the proxy simply logs in again with the password. Nothing to do by hand.

**From this point on, the cloud is no longer needed.** Everything else goes
directly over the home network.

### Step 2: Negotiating with the camera (control channel)

The proxy opens an encrypted connection to the camera (WebSocket over TLS on
port 8080) and they exchange short JSON messages, like a chat:

1. **"Hi, I'm here."** (`sign_in`): the camera replies with a random "salt".
2. The proxy mixes the cloud token with the salt using SHA1, and so **proves
   it knows the token without ever sending it** over the network. From now
   on, every message is signed with this derived token.
3. **"I want video, send it to this UDP port of mine."** (`conn_init`): the
   camera replies with the port it will send from, adds a description of the
   stream (SDP: "H264 video 1280×720, Opus audio") and, most importantly,
   **two new random codes** (`device_token`, `client_token`). They are valid
   for this one connection only and serve as the keys for everything that
   follows.
4. **"My address is …"** (`conn_add_candidate`): a formality left over from
   when the app connects to the camera over the internet. On a home network
   it is enough to send your own address.
5. **"Play!"** (`rtsp_command`): inside the JSON message is a completely
   ordinary RTSP `PLAY` command, the same one VLC would send. The camera has a
   normal RTSP server inside, it just doesn't expose it to the network; it is
   reachable only through this tunnel.

To keep the camera from closing the connection, the proxy sends "still here"
(`keep_alive`) every ~30 s and an RTSP `OPTIONS` every ~15 s.

### Step 3: Handshake on the media channel (UDP)

The video itself doesn't travel over the control connection but separately
over UDP. Before the camera starts sending, though, it wants to make sure the
party on the other end really is the one it just negotiated with. So they
exchange small "passwords":

- The camera sends: *"camera here, random number X, and proof that I know our
  two codes"* (an MD5 of number X and both codes).
- The proxy recomputes the proof. Does it match? It replies: *"client here,
  I've verified you, number Y, and my proof"* (a type 1 message).
- The camera verifies the proxy and replies with a type 2 message: *"great,
  I've verified you too."*
- **At that moment the camera starts the video.** After that they just ping
  each other every ~15 s (message `05`) to show the connection is alive.

This was the missing piece for a long time: as long as the proxy didn't answer
the camera's "password", the camera kept sending challenges forever and never
started the video.

### Step 4: Decrypting the video

Video and audio arrive as standard RTP packets, but **the content is
encrypted** (SRTP, AES-128). The packet header is readable, so at first glance
it looks like normal video, but the decoder gets garbage.

Both sides compute the key on their own from the two codes from step 2. The
key itself is never sent:

```
key = MD5(device_token + client_token) and MD5(client_token + device_token), joined together
```

The proxy checks each packet (that nobody tampered with it), decrypts it and
passes it on to the player as completely ordinary RTP. The player's feedback
(RTCP: "I'm fine, I'm receiving packets") gets encrypted and sent back to the
camera; without it the camera would eventually stop transmitting.

### Step 5: An ordinary RTSP camera on the outside

To the player, the proxy is a perfectly normal RTSP server at
`rtsp://<computer>:8555/live/profile.0`. None of the above is visible to it.
With `--expose` it is reachable from the whole home network (with no password!).

When the connection to the camera drops (camera restart, Wi-Fi outage), the
proxy notices, repeats steps 1–4 and is running again within a few seconds.
The player disconnects in the meantime and usually reconnects on its own.

### Summary in one sentence

> The cloud gives us the camera's address and a shared secret → with it we
> prove ourselves to the camera and set up a stream → over UDP we exchange
> "passwords" with the camera → the camera sends encrypted video → we decrypt
> it and hand it to the player as plain RTSP.

### Glossary

| Term | What it is |
|---|---|
| **access token** | temporary ticket for the mydlink account in the cloud, expires after a while |
| **cloud device_token** | secret shared by the camera and the cloud, changes over time |
| **salt** | random string from the camera, so that the secret never has to be sent |
| **conn_id** | number of one video "session" |
| **device_token / client_token** (from `conn_init`) | one-time codes for a single connection; both the handshake signature and the encryption key are computed from them |
| **WSS** | encrypted WebSocket connection, the control "chat" with the camera |
| **RTSP** | standard protocol for controlling a stream (PLAY, TEARDOWN…) |
| **RTP / RTCP** | the actual video/audio packets / reception feedback |
| **SRTP** | RTP with encrypted content |
| **SDP** | stream description: which codecs, which tracks |

---

# Technical description

## 1. Overview

```
 Client                        mydlink cloud                    Camera (LAN)
   │  ① OAuth login ───────────────► api.auto.mydlink.com
   │  ◄──────────── access_token
   │  ② /me/device/list, /me/device/info ─►
   │  ◄── mac, private_ip, device_token (cloud, rotates)
   │
   │  ③ WSS  wss://<cam>:8080/SwitchCamera  (TLS, self-signed) ─────────────►
   │     sign_in → conn_init → conn_add_candidate → rtsp_command(PLAY)
   │     + keep_alive (~30 s), rtsp_command(OPTIONS) (~15 s)
   │
   │  ④ UDP  <my_ip>:<my_port> ◄──► <cam_ip>:<cam_port>  ($-framing) ───────►
   │     0xFF connectivity check (MD5) → then SRTP media (H264 + Opus)
```

The cloud is needed **only** to obtain the `access_token` and the current
cloud `device_token`. All signalling and media then go directly over the LAN.

---

## 2. Cloud API

Base: `https://api.auto.mydlink.com`. The app sends the headers
`x-md-os-type: android`, `x-md-os-ver`, `x-md-app-ver`, `x-md-lang`,
`User-Agent: okhttp/4.8.0`.

### 2.1 Login (OAuth implicit)

```
GET /oauth/authorize2?client_id=mydlinkuapandroid
    &redirect_uri=https://mydlink.com
    &user_name=<email>
    &password=<md5_hex(password)>
    &response_type=token
    &timestamp=<unix>
    &uc_id=<android_id>
    &uc_name=<client name>
    &sig=<md5_hex(path_and_query_without_sig + OAUTH_SECRET)>
```
- `OAUTH_SECRET = 5259311fa8cab90f09f2dc1e09d2d8ee` (from the app),
- `sig` is computed over the string `/oauth/authorize2?...` (no host, no `&sig`),
- the response is a 3xx redirect, `Location: https://mydlink.com?...access_token=<token>...`.

An invalid or expired token is answered with
`HTTP 400 {"error":{"code":14,"message":"Invalid access token."}}`.

### 2.2 Device list

```
GET /me/device/list?access_token=<token>
→ {"data":[{"mac":"AABBCCDDEEFF","mydlink_id":"12345678","device_model":"DCS-P6000LH",
            "online":true,"gen":2, ...}, ...]}
```

### 2.3 Device details

```
POST /me/device/info?access_token=<token>
Body: {"data":[{"mydlink_id":"12345678"}]}
→ {"data":[{ "device_token":"<MAC>-<uuid>",   ← cloud token, ROTATES, fetch before every session
             "auth_key":"<32 hex>",
             "private_ip":"192.168.0.194", "private_port":"8080",
             "da_url":"wss://192.168.0.194:8080/SwitchCamera",
             "local_liveview":"http://192.168.0.194:8088/live.m3u8",
             "fw_ver":"1.06.01", "features":[...], ... }]}
```

---

## 3. WSS control channel

`wss://<private_ip>:8080/SwitchCamera`, TLS with a `mydlink Device CA`
certificate (self-signed → no certificate or hostname verification). Messages
are JSON text frames.

**General rules**
- `sequence_id` is **mandatory in every message** (including `sign_in`).
  Without it the camera silently drops the message; not even an error comes
  back. Any value works, the reply mirrors it.
- `timestamp` = unix seconds.
- `client_id` = any unique string; the app uses the form
  `<7 digits>-<uuid>`; it is empty in `sign_in`/`keep_alive`.
- SA commands (`conn_*`, `rtsp_command`) carry `"sa_cmd": 1`.
- A successful reply carries `"code": 0` (+ `"message": "no error"`).

### 3.1 sign_in

```json
→ {"sequence_id":1013,"command":"sign_in","client_id":"","timestamp":1794173510}
← {"sequence_id":1013,"command":"sign_in","local_cid":37603,
   "salt":"36da575569ab9f2a9df1762447dc150e","init":1,
   "device_id":"AABBCCDDEEFF","code":0,"message":"no error"}
```

### 3.2 Local device_token

```
device_token = device_id + "-" + sha1_hex(cloud_device_token + salt)
```
Used in all subsequent messages together with `local_cid`.

### 3.3 conn_init – setting up an SA connection

The client opens a UDP socket and announces its address.

```json
→ {"client_info":{"local_port":48226,"local_addr":"192.168.0.159"},
   "need_stream_info":1,
   "device_id":"AABBCCDDEEFF","local_cid":37603,"device_token":"<local token>",
   "sequence_id":N,"sa_cmd":1,"client_id":"<cid>","command":"conn_init","timestamp":T}

← {"conn_id":177514111,"code":0,
   "device_info":{"local_addr":"192.168.0.194","local_port":43834,
                  "device_token":"c31c45ab7b86487046f81bc08baae132",
                  "client_token":"394f0694960d2ad23699f159183c79f9"},
   "stream_info":["v=0\r\n...SDP..."], ...}
```
- `device_info.local_addr/local_port` = the camera's UDP endpoint for media.
- `device_info.device_token` / `client_token` (32 hex, generated by the
  camera as an MD5 of strings + time, `sa_util_create_pair_key`) = **key
  material for both the UDP handshake and SRTP** (see 4.2, 4.3). Note: these
  are different from the WSS `device_token`.
- `need_stream_info:1` → the reply contains the SDP; no separate DESCRIBE is needed.

The camera's SDP:
```
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=640028;sprop-parameter-sets=...
a=control:video
m=audio 0 RTP/AVP 97
a=rtpmap:97 opus/16000
a=control:audio
```

### 3.4 conn_add_candidate

```json
→ {"client_info":{"remote_addr":"<ip>","remote_port":<port>},
   "stun_info":{"host_port":3478,"host_addr":"mp-eu-sas.auto.mydlink.com"},
   "sa_ver":1,"device_id":"...","local_cid":...,"device_token":"...",
   "sequence_id":N,"sa_cmd":1,"conn_id":177514111,"client_id":"<cid>",
   "command":"conn_add_candidate","timestamp":T}
← {"device_info":{"remote_addr":"<camera public IP>","remote_port":...},"code":0}
```
The app sends its STUN-mapped (public) address. On a LAN it is enough to send
your own LAN address; the camera talks via the `local_addr` from `conn_init`
anyway.

### 3.5 rtsp_command – RTSP tunnelled in JSON

The camera runs a LIVE555 RTSP server; `rtsp_msg` is raw RTSP text.

```json
→ {"fast_play_media":[1,1,0],"fast_play":1,
   "rtsp_msg":"PLAY rtsp://127.0.0.1/live/profile.0 RTSP/1.0\r\nCSeq: 5\r\nUser-Agent: LibVLC/3.0.8 (LIVE555 Streaming Media v2014.02.26)\r\nSession: 4758B1B1\r\nRange: npt=0.000-\r\n\r\n",
   "device_id":"...","local_cid":...,"device_token":"...","sequence_id":N,
   "sa_cmd":1,"conn_id":177514111,"rtsp_id":4,"client_id":"<cid>",
   "command":"rtsp_command","timestamp":T}
← {"rtsp_msg":"RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: ...\r\nRTP-Info: url=.../video;seq=...;rtptime=...,url=.../audio;...\r\n\r\n","code":0,...}
```
- `fast_play:1` + `fast_play_media:[video,audio,?]` = PLAY without a prior
  SETUP; the client makes up the `Session` (8 hex digits).
- The classic OPTIONS/DESCRIBE/SETUP/PLAY sequence through the tunnel works
  too. The `Transport:` in the SETUP reply (`127.0.0.1`,
  `server_port=6970-6971`) is an internal loopback on the camera; ignore it.
- Stream path: `/live/profile.0` (on multi-channel devices `/live/profile.0.<uid>`).

### 3.6 Keeping alive and closing

| Message | Interval | Format |
|--------|----------|--------|
| `keep_alive` | ~30 s | `{"local_cid":..,"device_token":"..","sequence_id":N,"command":"keep_alive","client_id":"","timestamp":T}` |
| `rtsp_command` OPTIONS | ~15 s | `OPTIONS rtsp://127.0.0.1/live/profile.0 RTSP/1.0` + `Session:` |
| `rtsp_command` TEARDOWN | at the end | standard RTSP TEARDOWN with `Session:` |
| `conn_close` | at the end | `{"device_id","local_cid","device_token","sequence_id","sa_cmd":1,"conn_id","client_id","command":"conn_close","timestamp"}` |

After TEARDOWN + `conn_close`, the app sets up a new `conn_init` for the next
view (this time without `need_stream_info`).

### 3.7 Other commands (not needed for streaming)

`get_setting`, `get_setup_status`, `start_viewing` / `start_viewing_hd`
(cloud/relay path and recording playback; not used for LAN live view).

---

## 4. UDP media channel

After `conn_init`, the camera communicates from
`device_info.local_addr:local_port` to the client's `client_info.local_port`.

### 4.1 Framing (same as RTSP interleaved, just inside a UDP datagram)

```
0x24 '$' | channel (1 B) | length (2 B, big-endian) | payload (length B)
```

| channel | content |
|---------|-------|
| `base+0` | video SRTP (H264, PT 96) |
| `base+1` | video SRTCP |
| `base+2` | audio SRTP (Opus, PT 97) |
| `base+3` | audio SRTCP |
| `0xFF` | SA control messages (handshake, keep-alive) |

`base` is not constant (`0x20` in one capture, `0x40` live); determine it from
the first media packet as `channel & ~3`.

### 4.2 Connectivity check (channel 0xFF) – `sa_util_create_ctrl_data`, `sa_util_verify_peer_msg`

Types 0–2 (21 B payload):
```
type (1 B) | nonce (4 B, big-endian) | MD5( nonce as little-endian uint32 ‖ tokA ‖ tokB )  (16 B)
```
- tokA/tokB = hex strings from `conn_init` `device_info` (ASCII, no NUL):
  - camera → client: `tokA = device_token`, `tokB = client_token`
  - client → camera: `tokA = client_token`, `tokB = device_token`
- the nonce is random for each packet.

| type | direction | meaning |
|------|------|--------|
| 0 | both | check: the sender has not yet verified the peer |
| 1 | client → camera | check: the client has verified the camera |
| 2 | camera → client | check: the camera has verified the client |
| 5 | both | keep-alive; payload is just `05` (len=1), the camera answers `05` + 13 zero bytes |

Sequence (from a capture of the real app):
```
camera  0 ─►            (repeats ~300 ms)
        ◄─ 0  client    (until a valid check from the camera arrives)
        ◄─ 1  client    (after verifying the camera, repeats ~250 ms)
        ════ camera starts sending media ════
camera  2 ─►            (client is verified)
        ◄─ 5  client    → camera 5     (then every ~15 s)
```
**Without a valid type 1 reply the camera never starts sending media.** It
just keeps repeating type 0.

### 4.3 SRTP – fcn.00038cfc in `libsa.so`

Profile `AES_CM_128_HMAC_SHA1_80` (libsrtp default policy, for both RTP and
RTCP), replay window 128.

```
material    = MD5(device_token ‖ client_token) ‖ MD5(client_token ‖ device_token)   (binary, 32 B)
master_key  = material[0:16]
master_salt = material[16:30]
```
(tokens = hex strings from `conn_init` `device_info`)

- The same key in both directions (verified: SRTCP from both the phone and the
  camera passes the HMAC check).
- Session keys are derived as standard per RFC 3711 (KDR = 0, labels 0–5).
- The RTP header is not encrypted → it looks like valid RTP, but the payload
  is encrypted and ends with a 10 B auth tag.
- ROC starts at 0.
- The client must send back **SRTCP** (Receiver Reports) encrypted with the
  same key on channels `base+1` / `base+3`.

After decryption: standard RTP H264 (SPS/PPS + FU-A, RFC 6184) and Opus (RFC 7587).

---

## 5. Minimal client sequence

1. Login → `access_token`; `/me/device/info` → `device_token` (cloud), `private_ip`, MAC.
2. WSS connect → `sign_in` → `salt`, `local_cid`; compute the local `device_token`.
3. Open a UDP socket, `conn_init` (`need_stream_info:1`) → `conn_id`,
   camera UDP endpoint, `device_token`/`client_token`, SDP.
4. `conn_add_candidate`.
5. UDP: answer the checks (0 → 1 once verified), wait for type 2, then keep-alive 5.
6. `rtsp_command` PLAY with `fast_play`.
7. Receive `$` frames, demux by channel, SRTP unprotect → RTP.
8. Keep alive: WSS `keep_alive` ~30 s, OPTIONS through the tunnel ~15 s,
   UDP `05` ~15 s, SRTCP RR.
9. End: TEARDOWN through the tunnel, `conn_close`.

---

## 6. Open / unverified

- How long an `access_token` stays valid.
- The cloud/relay path outside the LAN (STUN `mp-eu-sas`, `start_viewing`, cloud WSS DCD).
- Port 8081 (TLS, same certificate): purpose unknown, not needed for streaming.
- HLS on 8088 (`auth_key:device_token` Digest): auth works, but the playlist stays empty.
- The meaning of `fast_play_media[2]` and `rtsp_id`.
