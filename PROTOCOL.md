# mydlink kamera (DCS-P6000LH) – protokol lokálního živého náhledu

Popis kompletní komunikace potřebné k získání živého videa z kamery v LAN,
tak jak ji implementují `rtsp_proxy.py`, `sa_srtp.py` a `advanced_proxy.py`.
Zdroje: dekompilovaná appka mydlink (Java), disassembly `libsa.so`, Frida
capture WSS zpráv (`wsscap2/`, `wss-local-capture/`) a tcpdump (`capture2.pcap`).

Ověřeno: FW 1.06.01, agent 3.5.20-b02, HW A1.

---

## 0. Lidsky: jak to celé funguje

Kamera v obýváku nemá žádný obyčejný „pusť mi video“ odkaz s heslem. Appka
mydlink místo toho dělá tanec o několika krocích. Proxy (`advanced_proxy.py`)
ten tanec napodobí a tváří se navenek jako úplně normální RTSP kamera, které
rozumí VLC, ffplay nebo Home Assistant.

### Krok 1: Ověření u D-Linku (cloud)

Nejdřív se proxy přihlásí na servery D-Linku stejně jako appka v telefonu –
e-mailem a heslem k účtu mydlink. Dostane za to **access token**, něco jako
dočasnou vstupenku. S ní si od D-Linku vyžádá:

- **seznam zařízení na účtu** – podle `mydlink_id` se vybere správná kamera,
- **adresu kamery v domácí síti** (např. `192.168.0.194`),
- **cloudový token kamery** – tajný řetězec, který kamera zná taky. Je to
  jediná věc, kterou kamera a cloud sdílejí, a díky ní kamera pozná, že se
  připojuje někdo, komu majitel účtu věří. Tento token se občas mění, proto se
  stahuje znovu při každém připojení.

Vstupenka (access token) časem vyprší. Když cloud řekne „neplatný token“,
proxy se prostě znovu přihlásí heslem – nic nemusíš dělat ručně.

**Od této chvíle už cloud není potřeba.** Všechno další jde přímo po domácí síti.

### Krok 2: Domluva s kamerou (řídicí kanál)

Proxy otevře s kamerou šifrované spojení (WebSocket přes TLS na portu 8080) a
posílají si krátké JSON zprávy – jako SMS konverzace:

1. **„Ahoj, jsem tu.“** (`sign_in`) – kamera odpoví náhodným „salt“ (sůl).
2. Proxy smíchá cloudový token se solí přes SHA1 a tím **dokáže, že token zná,
   aniž by ho poslala** po síti. Od teď se tímhle odvozeným tokenem podepisuje
   každá zpráva.
3. **„Chci video, posílej mi ho sem na tenhle UDP port.“** (`conn_init`) –
   kamera odpoví, ze kterého portu bude posílat, přidá popis streamu (SDP:
   „video H264 1280×720, zvuk Opus“) a hlavně **dva nové náhodné kódy**
   (`device_token`, `client_token`). Ty platí jen pro tohle jedno spojení a
   slouží jako klíče pro všechno další.
4. **„Moje adresa je …“** (`conn_add_candidate`) – formalita z doby, kdy appka
   připojuje kameru přes internet. V domácí síti stačí poslat vlastní adresu.
5. **„Play!“** (`rtsp_command`) – uvnitř JSON zprávy je zabalený úplně běžný
   RTSP příkaz `PLAY`, stejný, jaký by poslalo VLC. Kamera má uvnitř normální
   RTSP server, jen ho nevystrkuje ven do sítě – dá se k němu dostat jen přes
   tenhle tunel.

Aby kamera spojení neukončila, proxy každých ~30 s pošle „pořád tu jsem“
(`keep_alive`) a každých ~15 s RTSP `OPTIONS`.

### Krok 3: Podání ruky na mediálním kanálu (UDP)

Samotné video neteče přes řídicí spojení, ale zvlášť po UDP. Než ale kamera
začne posílat, chce si ověřit, že na druhé straně opravdu sedí ten, s kým se
právě domluvila. Proto si posílají malé „hesla“:

- Kamera pošle: *„tady kamera, náhodné číslo X, a důkaz, že znám naše dva kódy“*
  (MD5 z čísla X a obou kódů).
- Proxy si důkaz přepočítá. Sedí? Odpoví: *„tady klient, ověřil jsem tě, číslo Y,
  a můj důkaz“* (zprávu typu 1).
- Kamera ověří proxy a odpoví zprávou typu 2: *„super, i já tebe.“*
- **V tu chvíli kamera pustí video.** Pak už si jen každých ~15 s pípnou
  (zpráva `05`), že spojení žije.

Tohle byl dlouho chybějící dílek: dokud proxy na „heslo“ kamery neodpovídala,
kamera donekonečna posílala jen výzvy a video nikdy nepustila.

### Krok 4: Rozšifrování videa

Video a zvuk tečou jako standardní RTP pakety, ale **obsah je zašifrovaný**
(SRTP, AES-128). Hlavička paketu je čitelná, takže to na první pohled vypadá
jako normální video – dekodér ale dostane nesmysly.

Klíč si obě strany spočítají samy ze dvou kódů z kroku 2 – nikdy se neposílá:

```
klíč = MD5(device_token + client_token) a MD5(client_token + device_token), slepené za sebe
```

Proxy každý paket ověří (jestli ho nikdo nezměnil), rozšifruje a pošle dál
přehrávači jako úplně obyčejné RTP. Zpětné hlášení přehrávače (RTCP „mám se
dobře, dostávám pakety“) zase zašifruje a pošle kameře – bez toho by kamera
časem přestala vysílat.

### Krok 5: Navenek obyčejná RTSP kamera

Pro přehrávač je proxy úplně normální RTSP server na
`rtsp://<počítač>:8555/live/profile.0`. Nic z výše uvedeného nevidí.
S `--expose` je dostupný z celé domácí sítě (bez hesla!).

Když spojení s kamerou spadne (restart kamery, výpadek Wi-Fi), proxy si to
všimne, zopakuje kroky 1–4 a za pár sekund jede znovu. Přehrávač se mezitím
odpojí a obvykle se sám připojí zpátky.

### Shrnutí jednou větou

> Cloud nám dá adresu kamery a společné tajemství → s ním se kameře
> prokážeme a domluvíme si stream → na UDP si s kamerou vyměníme „hesla“
> → kamera pošle zašifrované video → my ho rozšifrujeme a podáme přehrávači
> jako obyčejné RTSP.

### Slovníček

| Pojem | Co to je |
|---|---|
| **access token** | dočasná vstupenka k účtu mydlink v cloudu, po čase vyprší |
| **cloudový device_token** | tajemství sdílené kamerou a cloudem, mění se |
| **salt / sůl** | náhodný řetězec od kamery, aby se tajemství nemuselo posílat |
| **conn_id** | číslo jednoho „sezení“ pro video |
| **device_token / client_token** (z `conn_init`) | jednorázové kódy pro jedno spojení, z nich se počítá podpis handshaku i šifrovací klíč |
| **WSS** | šifrované WebSocket spojení – řídicí „chat“ s kamerou |
| **RTSP** | standardní protokol na ovládání streamu (PLAY, TEARDOWN…) |
| **RTP / RTCP** | samotné pakety s videem/zvukem / zpětné hlášení o příjmu |
| **SRTP** | RTP se zašifrovaným obsahem |
| **SDP** | popis streamu: jaké kodeky, jaké stopy |

---

# Technický popis

## 1. Přehled

```
 Klient                        mydlink cloud                    Kamera (LAN)
   │  ① OAuth login ───────────────► api.auto.mydlink.com
   │  ◄──────────── access_token
   │  ② /me/device/list, /me/device/info ─►
   │  ◄── mac, private_ip, device_token (cloud, rotuje)
   │
   │  ③ WSS  wss://<cam>:8080/SwitchCamera  (TLS, self-signed) ─────────────►
   │     sign_in → conn_init → conn_add_candidate → rtsp_command(PLAY)
   │     + keep_alive (~30 s), rtsp_command(OPTIONS) (~15 s)
   │
   │  ④ UDP  <my_ip>:<my_port> ◄──► <cam_ip>:<cam_port>  ($-framing) ───────►
   │     0xFF connectivity check (MD5) → potom SRTP média (H264 + Opus)
```

Cloud je potřeba **jen** pro získání `access_token` a aktuálního cloudového
`device_token`. Veškerá signalizace i média pak jdou přímo v LAN.

---

## 2. Cloud API

Base: `https://api.auto.mydlink.com`. Appka posílá hlavičky
`x-md-os-type: android`, `x-md-os-ver`, `x-md-app-ver`, `x-md-lang`,
`User-Agent: okhttp/4.8.0`.

### 2.1 Login (OAuth implicit)

```
GET /oauth/authorize2?client_id=mydlinkuapandroid
    &redirect_uri=https://mydlink.com
    &user_name=<email>
    &password=<md5_hex(heslo)>
    &response_type=token
    &timestamp=<unix>
    &uc_id=<android_id>
    &uc_name=<název klienta>
    &sig=<md5_hex(path_a_query_bez_sig + OAUTH_SECRET)>
```
- `OAUTH_SECRET = 5259311fa8cab90f09f2dc1e09d2d8ee` (z appky),
- `sig` se počítá z řetězce `/oauth/authorize2?...` (bez hostu, bez `&sig`),
- odpověď je redirect 3xx, `Location: https://mydlink.com?...access_token=<token>...`.

### 2.2 Seznam zařízení

```
GET /me/device/list?access_token=<token>
→ {"data":[{"mac":"AABBCCDDEEFF","mydlink_id":"12345678","device_model":"DCS-P6000LH",
            "online":true,"gen":2, ...}, ...]}
```

### 2.3 Detail zařízení

```
POST /me/device/info?access_token=<token>
Body: {"data":[{"mydlink_id":"12345678"}]}
→ {"data":[{ "device_token":"<MAC>-<uuid>",   ← cloudový token, ROTUJE, stahovat před každou session
             "auth_key":"<32 hex>",
             "private_ip":"192.168.0.194", "private_port":"8080",
             "da_url":"wss://192.168.0.194:8080/SwitchCamera",
             "local_liveview":"http://192.168.0.194:8088/live.m3u8",
             "fw_ver":"1.06.01", "features":[...], ... }]}
```

---

## 3. WSS řídicí kanál

`wss://<private_ip>:8080/SwitchCamera`, TLS s certifikátem `mydlink Device CA`
(self-signed → bez ověření certifikátu i hostname). Zprávy jsou JSON text frames.

**Obecná pravidla**
- `sequence_id` je **povinné v každé zprávě** (i `sign_in`). Bez něj kamera
  zprávu tiše zahodí, nepřijde ani chyba. Hodnota libovolná, odpověď ji zrcadlí.
- `timestamp` = unix sekundy.
- `client_id` = libovolný unikátní řetězec, appka používá tvar
  `<7 číslic>-<uuid>`; v `sign_in`/`keep_alive` je prázdný.
- SA příkazy (`conn_*`, `rtsp_command`) mají `"sa_cmd": 1`.
- Odpověď nese `"code": 0` (+ `"message": "no error"`) při úspěchu.

### 3.1 sign_in

```json
→ {"sequence_id":1013,"command":"sign_in","client_id":"","timestamp":1794173510}
← {"sequence_id":1013,"command":"sign_in","local_cid":37603,
   "salt":"36da575569ab9f2a9df1762447dc150e","init":1,
   "device_id":"AABBCCDDEEFF","code":0,"message":"no error"}
```

### 3.2 Lokální device_token

```
device_token = device_id + "-" + sha1_hex(cloud_device_token + salt)
```
Používá se ve všech dalších zprávách spolu s `local_cid`.

### 3.3 conn_init – založení SA spojení

Klient otevře UDP socket a oznámí jeho adresu.

```json
→ {"client_info":{"local_port":48226,"local_addr":"192.168.0.159"},
   "need_stream_info":1,
   "device_id":"AABBCCDDEEFF","local_cid":37603,"device_token":"<lokální token>",
   "sequence_id":N,"sa_cmd":1,"client_id":"<cid>","command":"conn_init","timestamp":T}

← {"conn_id":177514111,"code":0,
   "device_info":{"local_addr":"192.168.0.194","local_port":43834,
                  "device_token":"c31c45ab7b86487046f81bc08baae132",
                  "client_token":"394f0694960d2ad23699f159183c79f9"},
   "stream_info":["v=0\r\n...SDP..."], ...}
```
- `device_info.local_addr/local_port` = UDP endpoint kamery pro média.
- `device_info.device_token` / `client_token` (32 hex, generované kamerou:
  MD5 z řetězců + času, `sa_util_create_pair_key`) = **klíčový materiál pro
  UDP handshake i SRTP** (viz 4.2, 4.3). Pozor – jiné než WSS `device_token`.
- `need_stream_info:1` → odpověď obsahuje SDP, samostatné DESCRIBE není třeba.

SDP kamery:
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
← {"device_info":{"remote_addr":"<veřejná IP kamery>","remote_port":...},"code":0}
```
Appka posílá svou STUN-mapovanou (veřejnou) adresu. V LAN stačí poslat
vlastní LAN adresu – kamera stejně komunikuje přes `local_addr` z `conn_init`.

### 3.5 rtsp_command – RTSP tunelované v JSON

Na kameře běží LIVE555 RTSP server, `rtsp_msg` je syrový RTSP text.

```json
→ {"fast_play_media":[1,1,0],"fast_play":1,
   "rtsp_msg":"PLAY rtsp://127.0.0.1/live/profile.0 RTSP/1.0\r\nCSeq: 5\r\nUser-Agent: LibVLC/3.0.8 (LIVE555 Streaming Media v2014.02.26)\r\nSession: 4758B1B1\r\nRange: npt=0.000-\r\n\r\n",
   "device_id":"...","local_cid":...,"device_token":"...","sequence_id":N,
   "sa_cmd":1,"conn_id":177514111,"rtsp_id":4,"client_id":"<cid>",
   "command":"rtsp_command","timestamp":T}
← {"rtsp_msg":"RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: ...\r\nRTP-Info: url=.../video;seq=...;rtptime=...,url=.../audio;...\r\n\r\n","code":0,...}
```
- `fast_play:1` + `fast_play_media:[video,audio,?]` = PLAY bez předchozího
  SETUP; `Session` si klient vymyslí (8 hex).
- Klasický OPTIONS/DESCRIBE/SETUP/PLAY přes tunel funguje taky. `Transport:`
  v odpovědi na SETUP (`127.0.0.1`, `server_port=6970-6971`) je interní
  loopback na kameře – ignorovat.
- Stream path: `/live/profile.0` (u multikanálových zařízení `/live/profile.0.<uid>`).

### 3.6 Udržování a ukončení

| Zpráva | Interval | Formát |
|--------|----------|--------|
| `keep_alive` | ~30 s | `{"local_cid":..,"device_token":"..","sequence_id":N,"command":"keep_alive","client_id":"","timestamp":T}` |
| `rtsp_command` OPTIONS | ~15 s | `OPTIONS rtsp://127.0.0.1/live/profile.0 RTSP/1.0` + `Session:` |
| `rtsp_command` TEARDOWN | konec | standardní RTSP TEARDOWN se `Session:` |
| `conn_close` | konec | `{"device_id","local_cid","device_token","sequence_id","sa_cmd":1,"conn_id","client_id","command":"conn_close","timestamp"}` |

Appka po TEARDOWN + `conn_close` zakládá pro další náhled nový `conn_init`
(už bez `need_stream_info`).

### 3.7 Ostatní příkazy (nejsou pro stream potřeba)

`get_setting`, `get_setup_status`, `start_viewing` / `start_viewing_hd`
(cloud/relay cesta a přehrávání nahrávek – pro LAN náhled se nepoužívá).

---

## 4. UDP mediální kanál

Po `conn_init` kamera komunikuje z `device_info.local_addr:local_port` na
klientův `client_info.local_port`.

### 4.1 Framing (stejný jako RTSP interleaved, jen v UDP datagramu)

```
0x24 '$' | channel (1 B) | length (2 B, big-endian) | payload (length B)
```

| channel | obsah |
|---------|-------|
| `base+0` | video SRTP (H264, PT 96) |
| `base+1` | video SRTCP |
| `base+2` | audio SRTP (Opus, PT 97) |
| `base+3` | audio SRTCP |
| `0xFF` | SA řídicí zprávy (handshake, keep-alive) |

`base` není konstantní (v capture `0x20`, živě `0x40`) – zjistit z prvního
mediálního paketu jako `channel & ~3`.

### 4.2 Connectivity check (kanál 0xFF) – `sa_util_create_ctrl_data`, `sa_util_verify_peer_msg`

Typy 0–2 (payload 21 B):
```
type (1 B) | nonce (4 B, big-endian) | MD5( nonce jako little-endian uint32 ‖ tokA ‖ tokB )  (16 B)
```
- tokA/tokB = hex řetězce z `conn_init` `device_info` (ASCII, bez NUL):
  - kamera → klient: `tokA = device_token`, `tokB = client_token`
  - klient → kamera: `tokA = client_token`, `tokB = device_token`
- nonce náhodné pro každý paket.

| type | směr | význam |
|------|------|--------|
| 0 | oba | check – odesílatel ještě neověřil protistranu |
| 1 | klient → kamera | check – klient už ověřil kameru |
| 2 | kamera → klient | check – kamera už ověřila klienta |
| 5 | oba | keep-alive; payload jen `05` (len=1), kamera odpovídá `05` + 13 B nul |

Průběh (z `capture2.pcap`):
```
kamera  0 ─►            (opakuje ~300 ms)
        ◄─ 0  klient    (dokud nepřijde platný check od kamery)
        ◄─ 1  klient    (po ověření kamery, opakuje ~250 ms)
        ════ kamera začíná posílat média ════
kamera  2 ─►            (klient je ověřený)
        ◄─ 5  klient    → kamera 5     (dále každých ~15 s)
```
**Bez platné odpovědi typu 1 kamera nikdy nezačne posílat média** – jen
opakuje typ 0.

### 4.3 SRTP – fcn.00038cfc v `libsa.so`

Profil `AES_CM_128_HMAC_SHA1_80` (výchozí politika libsrtp, RTP i RTCP),
replay window 128.

```
material    = MD5(device_token ‖ client_token) ‖ MD5(client_token ‖ device_token)   (binární, 32 B)
master_key  = material[0:16]
master_salt = material[16:30]
```
(tokeny = hex řetězce z `conn_init` `device_info`)

- Stejný klíč pro oba směry (ověřeno: SRTCP od telefonu i od kamery projde HMAC).
- Odvození session klíčů standardně dle RFC 3711 (KDR = 0, labely 0–5).
- RTP hlavička je nešifrovaná → vypadá jako validní RTP, ale payload je
  šifrovaný a končí 10B auth tagem.
- ROC začíná na 0.
- Klient musí posílat zpět **SRTCP** (Receiver Reports) zašifrované stejným
  klíčem na kanálech `base+1` / `base+3`.

Po dešifrování: standardní RTP H264 (SPS/PPS + FU-A, RFC 6184) a Opus (RFC 7587).

---

## 5. Minimální sekvence klienta

1. Login → `access_token`; `/me/device/info` → `device_token` (cloud), `private_ip`, MAC.
2. WSS connect → `sign_in` → `salt`, `local_cid`; spočítat lokální `device_token`.
3. Otevřít UDP socket, `conn_init` (`need_stream_info:1`) → `conn_id`,
   UDP endpoint kamery, `device_token`/`client_token`, SDP.
4. `conn_add_candidate`.
5. UDP: odpovídat na checky (0 → po ověření 1), čekat na typ 2, pak keep-alive 5.
6. `rtsp_command` PLAY s `fast_play`.
7. Přijímat `$`-framy, demux podle kanálu, SRTP unprotect → RTP.
8. Udržovat: WSS `keep_alive` ~30 s, OPTIONS tunelem ~15 s, UDP `05` ~15 s,
   SRTCP RR.
9. Konec: TEARDOWN tunelem, `conn_close`.

---

## 6. Nevyřešené / neověřené

- Doba platnosti `access_token`.
- Cloud/relay cesta mimo LAN (STUN `mp-eu-sas`, `start_viewing`, cloud WSS DCD).
- Port 8081 (TLS, stejný certifikát) – účel neznámý, pro stream nepotřebný.
- HLS na 8088 (`auth_key:device_token` Digest) – auth funguje, playlist zůstává prázdný.
- Význam `fast_play_media[2]` a `rtsp_id`.
