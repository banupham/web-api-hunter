WEB API HUNTER V3
=================

MUC TIEU V3
-----------
V3 tap trung vao WebSocket / binary / protobuf, dac biet huu ich khi website
nhan event realtime ma V2 chi luu duoc vai sample frame.

Khong chi TikTok:
- REST / XHR / fetch
- GraphQL
- JSON-RPC / custom RPC
- gRPC-Web hints
- WebSocket
- SSE
- protobuf HTTP
- endpoint tim trong JavaScript


V3 KHAC V2
----------
1. LUU TOAN BO WEBSOCKET MESSAGE
   V2 chi giu 5 sample sent + 5 sample received trong record.

   V3 tao mot record rieng cho MOI WebSocket message.

2. TAB WEBSOCKET FRAMES
   Co:
   - frame number
   - sent / received
   - opcode
   - raw byte size
   - action
   - chuoi text tim thay
   - socket URL

3. SEARCH DECODED WS
   Trong tab WEBSOCKET FRAMES co o:
     Search decoded WS

   Vi du:
     DOMTEST98765
     Hạt bụi cuộc đời
     biillllllllll95
     WebcastChatMessage

   Search tren:
   - text WebSocket
   - printable UTF-8 trong binary
   - protobuf length-delimited strings
   - noi dung tim thay sau gzip/zlib decompress

4. BINARY WEBSOCKET
   Theo Chrome CDP:
   opcode=1 -> UTF-8 text
   opcode!=1 -> payloadData la Base64

   V3 tu Base64 decode thanh raw bytes.

5. PROTOBUF HINTS KHONG CAN .proto
   V3 khong tu nhan no "biet schema".
   No chi:
   - scan wire field number / wire type
   - tim length-delimited field
   - thu UTF-8
   - tim nested protobuf theo heuristic
   - tim gzip/zlib blob

   Day la cong cu tim dau vet, khong phai protobuf decoder hoan chinh.

6. GZIP / ZLIB
   V3 scan magic trong binary frame va thu decompress.
   Neu thanh cong se tim string/protobuf tiep ben trong.

7. EXPORT WEBSOCKET RIENG
   session_...\

     observed_api.jsonl
     discovered_api.json
     markers.json
     api_summary.json

     websocket_frames.jsonl
     websocket_action_frames.jsonl
     websocket_strings.txt

     websocket_binary\
       frame_000001_received_op2.bin
       ...

   websocket_binary chi luu raw binary frame nam trong ACTION WINDOW.

8. REQUEST REDIRECTION
   V3 dung request_key co generation de han che redirect chain bi de len nhau.

9. MV3 SERVICE WORKER
   Extension luu attachment/action state vao chrome.storage.session.
   Khi popup mo lai no doi chieu chrome.debugger.getTargets().

10. REDACT NANG HON
   Ngoai Authorization/Cookie, V3 redact cac header/query token pho bien:
   - msToken
   - X-Bogus
   - X-Gnarly
   - X-Dynosaur
   - ticket-guard
   - secsdk
   - signature/token...
   - device_id trong query

   Muc dich: phan tich protocol ma khong can export security token dong.


CAI DAT
-------
1. Giai nen ZIP.
2. Chay:
     START_APP.cmd

3. chrome://extensions
4. Developer mode
5. Neu dang co V1/V2:
     Remove hoac Disable no

6. Load unpacked:
     extension\


CACH BAT COMMENT / EVENT REALTIME
---------------------------------
Vi du TikTok LIVE:

1. Mo TikTok LIVE.
2. Extension -> Start capture.
3. Action name:
     COMMENT_DOMTEST98765

4. MARK START.
5. Lam DUNG MOT hanh dong / gui dung mot comment de nhan dien:
     DOMTEST98765

6. Cho 2-5 giay de response / WebSocket echo ve.
7. MARK END.

8. Trong Python:
     tab WEBSOCKET FRAMES

9. Search:
     DOMTEST98765

10. Neu khong tim duoc truc tiep:
     Export
     xem websocket_strings.txt
     hoac gui ca session ZIP de phan tich.


TIKTOK HUONG PHAN TICH
----------------------
V3 duoc thiet ke de tach ro hai duong:

A. HTTP state-changing
   vi du endpoint gui comment:
     /webcast/room/chat/

B. realtime receive
   vi du WebSocket:
     webcast-ws.../webcast/im/...

   hoac HTTP protobuf fallback:
     /webcast/im/fetch/

V3 KHONG:
- tao/replay security token
- bypass signing
- bypass CAPTCHA
- bypass rate-limit
- tu dong fake interaction

No chi quan sat traffic do browser that tu tao.


ACTION WINDOW
-------------
Quan trong.

MARK START
  -> frame sau do duoc gan action_window=true

MARK END
  -> dung gan action

Tab WS mac dinh:
  Received only = ON
  Action frames only = ON

Nen rat it rac hon V2.


EXPORT DE GUI CHATGPT
---------------------
Tot nhat nen ZIP ca folder:

  session_YYYYMMDD_HHMMSS\

Neu chi gui file nho:
  api_summary.json
  websocket_action_frames.jsonl
  websocket_strings.txt

Neu can giai binary sau:
  gui them websocket_binary\


GIOI HAN
--------
- Khong co schema .proto thi field protobuf chi la heuristic.
- Neu application ma hoa payload rieng, V3 chi thay ciphertext/raw bytes.
- Raw response body HTTP van co gioi han preview trong observed record.
- Moi WebSocket payload duoc giu toi da 6,000,000 ky tu trong receiver.
- Action binary frames duoc export thanh .bin.
