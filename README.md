# dlink-rtsp-proxy

Exposes a D-Link mydlink camera on your LAN as a standard RTSP stream that
VLC, ffplay, Home Assistant and similar players can open.

Tested with the **DCS-P6000LH** (FW 1.06.01). Other mydlink cameras that use
the same local streaming protocol may work too.

For how it works, see [PROTOCOL_EN.md](PROTOCOL_EN.md) (Czech:
[PROTOCOL.md](PROTOCOL.md)).

## Requirements

- Python 3.8+
- The camera and the machine running the proxy on the same LAN
- A mydlink account that has the camera

```
pip install -r requirements.txt
```

## Usage

### 1. Find your camera's `mydlink_id`

Run the proxy without `--mydlink_id` to list the devices on your account:

```
python3 advanced_proxy.py --user you@example.com
```
```
mydlink_id   model          mac            online  name
12345678     DCS-P6000LH    AABBCCDDEEFF   True    Living room
```

### 2. Start the proxy

```
python3 advanced_proxy.py --user you@example.com --mydlink_id 12345678
```

The proxy logs in, finds the camera on the LAN and prints the stream URL:

```
[rtsp] ready: rtsp://127.0.0.1:8555/live/profile.0
```

### 3. Open the stream

```
ffplay -rtsp_transport tcp rtsp://127.0.0.1:8555/live/profile.0
vlc rtsp://127.0.0.1:8555/live/profile.0
```

The stream is H.264 video (1280×720) with Opus audio. Both TCP and UDP RTSP
transport work.

## Options

| Option | Description |
|---|---|
| `--user EMAIL` | mydlink account e-mail |
| `--password PASS` | mydlink password. If omitted, it is read from `MYDLINK_PASSWORD` or asked for interactively. |
| `--mydlink_id ID` | camera to stream. If omitted, the devices on the account are listed. |
| `--expose` | listen on `0.0.0.0` so the stream is reachable from the whole LAN |
| `--bind ADDR` | RTSP listen address (default `127.0.0.1`) |
| `--port PORT` | RTSP port (default `8555`) |
| `--access-token TOKEN` | use an existing mydlink access token instead of logging in |
| `--camera-ip IP` | override the camera's LAN IP (default: taken from the mydlink cloud) |
| `--local-ip IP` | override this machine's LAN IP (default: detected automatically) |

Prefer `MYDLINK_PASSWORD` or the interactive prompt over `--password`, so the
password doesn't end up in your shell history:

```
export MYDLINK_PASSWORD='...'
python3 advanced_proxy.py --user you@example.com --mydlink_id 12345678 --expose
```

## Behaviour

- **Expired login:** when the mydlink access token expires, the proxy logs in
  again with the given credentials. With `--access-token` alone (no `--user`)
  it stops with an error instead.
- **Camera disconnects:** if the connection to the camera drops (camera
  restart, Wi-Fi outage), the proxy reconnects automatically. Connected players
  are dropped and usually reconnect on their own.
- **Cloud use:** the mydlink cloud is only used to log in and look up the
  camera. The video itself goes directly over the LAN.

## Ports

| Port | Use |
|---|---|
| TCP `8555` | RTSP server (configurable with `--port`) |
| UDP `16000–16003` | RTP/RTCP towards players that use UDP transport |
| UDP (random) | media channel to the camera |

## Security

The RTSP server has **no authentication**. With `--expose`, anyone on your
network who can reach the port can watch the camera. Only use `--expose` on a
network you trust.

## Files

| File | Purpose |
|---|---|
| `advanced_proxy.py` | entry point: login, camera discovery, RTSP server, reconnects |
| `rtsp_proxy.py` | camera protocol (WSS signalling, UDP handshake, RTP relay) |
| `sa_srtp.py` | SRTP/SRTCP decryption and encryption |
| `PROTOCOL_EN.md` / `PROTOCOL.md` | protocol description (English / Czech) |

## Disclaimer

Unofficial project, not affiliated with D-Link. Use it only with cameras and
accounts you own.
