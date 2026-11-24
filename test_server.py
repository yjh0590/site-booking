"""서버 자가 점검: 푸시 암호화·발송, 입력 검사, 감지→알림 흐름. 실행: python test_server.py"""
import base64, json, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["DB"] = ":memory:"
import http_ece
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import server

got = []


class Capture(BaseHTTPRequestHandler):  # 가짜 푸시 서비스
    def do_POST(self):
        got.append(({k.lower(): v for k, v in self.headers.items()},self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(201)
        self.end_headers()

    def log_message(self, *a):
        pass


cap = HTTPServer(("127.0.0.1", 0), Capture)
threading.Thread(target=cap.serve_forever, daemon=True).start()

# 브라우저가 만드는 것과 같은 구독 키
priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
auth = os.urandom(16)
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
ep = f"http://127.0.0.1:{cap.server_port}/push"
server.q("insert into subs values(?, ?)", ep, json.dumps({"endpoint": ep, "keys": {"p256dh": b64(pub), "auth": b64(auth)}}))

# 1) 푸시가 VAPID 서명 + aes128gcm 암호화로 가고, 풀면 내용이 맞는지
assert server.push(ep, "제목", "본문", "https://example.com")
headers, body = got.pop()
assert headers["authorization"].startswith("vapid ") and headers["content-encoding"] == "aes128gcm"
assert int(headers["ttl"]) > 0, "TTL 0이면 폰이 오프라인일 때 알림이 버려짐"
msg = json.loads(http_ece.decrypt(body, private_key=priv, auth_secret=auth, version="aes128gcm"))
assert msg == {"title": "제목", "body": "본문", "url": "https://example.com"}, msg

# 2) 입력 검사: 내부망/이상한 주소 거부
for bad in ("http://127.0.0.1/", "http://192.168.0.1/", "file:///etc/passwd", "ftp://x.com", "http://169.254.169.254/"):
    try:
        server.public_url(bad)
        raise AssertionError(bad)
    except ValueError:
        pass
try:
    server.api_subscribe({"sub": {"endpoint": "https://127.0.0.1/x", "keys": {"p256dh": "a"}}})
    raise AssertionError("내부망 구독 허용됨")
except ValueError:
    pass
for nxt in ("http://192.168.0.1/admin", "http://localhost:8000/"):  # 리다이렉트로 내부망 진입 차단
    try:
        server.SafeRedirect().redirect_request(None, None, 302, "", {}, nxt)
        raise AssertionError(nxt)
    except ValueError:
        pass

# 초대 코드: 새 기기는 코드 필요, 이미 등록된 기기는 생략 가능
new_sub = {"endpoint": "https://fcm.googleapis.com/fcm/send/new", "keys": {"p256dh": "a", "auth": "b"}}
for wrong in ("", "틀림"):
    try:
        server.api_subscribe({"sub": new_sub, "code": wrong})
        raise AssertionError("코드 없이 구독됨")
    except ValueError:
        pass
assert server.api_subscribe({"sub": new_sub, "code": server.INVITE.upper()})["ok"]
assert server.api_subscribe({"sub": new_sub})["ok"]
try:
    server.api_add({"endpoint": "모르는사람", "url": "https://example.com"})
    raise AssertionError("구독 없이 등록됨")
except ValueError:
    pass

# 3) 감지 흐름: '접수예정'이 사라지면 딱 한 번 알림
wid = server.q("insert into watches(endpoint, name, url, keyword) values(?,?,?,?)", ep, "포켓몬", "https://x.test", "!접수예정")
assert not server.evaluate(wid, ep, "포켓몬", "https://x.test", "!접수예정", None, "<p>접수예정</p>")
old = server.q("select state from watches where id=?", wid)[0][0]
assert server.evaluate(wid, ep, "포켓몬", "https://x.test", "!접수예정", old, "<p>접수중</p>")
assert "포켓몬" in json.loads(http_ece.decrypt(got.pop()[1], private_key=priv, auth_secret=auth, version="aes128gcm"))["body"]
old = server.q("select state from watches where id=?", wid)[0][0]
assert not server.evaluate(wid, ep, "포켓몬", "https://x.test", "!접수예정", old, "<p>접수중</p>")  # 중복 알림 없음
item = server.api_list({"endpoint": ep})["items"][0]
assert item["opened"] == 1 and item["checked"] and item["error"] is None
print("ok")
