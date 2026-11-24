"""콕콕 예약알림 웹앱 서버. 사용법은 README.md 참고.

실행:  python server.py   → http://localhost:8000
cloudflared가 설치돼 있으면 폰에서 열 HTTPS 주소도 자동으로 만들어 출력해요.
"""
import atexit, base64, hmac, ipaddress, json, os, re, secrets, shutil, socket, sqlite3, subprocess, threading, time
import urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from pywebpush import webpush

from watch import INTERVAL, fetch, page_text, should_alert, state

ROOT = Path(__file__).parent
KEY = ROOT / "vapid.pem"
HOST, PORT = os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", 8000))
SUB = os.environ.get("VAPID_SUB", "mailto:noreply@example.com")
MAX_WATCHES = 20
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/manifest.json": ("manifest.json", "application/manifest+json"),
    "/icon.png": ("icon.png", "image/png"),
}

# 초대 코드: 환경변수 INVITE_CODE, 없으면 invite.txt에 한 번 만들어 두고 계속 사용
INVITE_FILE = ROOT / "invite.txt"
if not (INVITE := os.environ.get("INVITE_CODE", "").strip()):
    if not INVITE_FILE.exists():
        INVITE_FILE.write_text("".join(secrets.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(6)))
    INVITE = INVITE_FILE.read_text().strip()

if not KEY.exists():
    v = Vapid()
    v.generate_keys()
    v.save_key(str(KEY))
PUBLIC_KEY = base64.urlsafe_b64encode(Vapid.from_file(str(KEY)).public_key.public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).rstrip(b"=").decode()

db = sqlite3.connect(os.environ.get("DB", ROOT / "booking.db"), check_same_thread=False)
lock = threading.Lock()  # ponytail: DB 전역 락, 사용자 수십 명 규모면 충분
db.executescript("""
create table if not exists subs(endpoint text primary key, info text not null);
create table if not exists watches(
  id integer primary key, endpoint text not null, name text, url text,
  keyword text, state text, opened integer default 0);
""")
for col in ("checked integer", "error text"):  # 예전 DB에 컬럼 추가
    try:
        db.execute(f"alter table watches add column {col}")
    except sqlite3.OperationalError:
        pass


def q(sql, *args):
    with lock:
        cur = db.execute(sql, args)
        rows = cur.fetchall()
        db.commit()
        return rows if rows or not sql.lstrip().lower().startswith("insert") else cur.lastrowid


def public_url(url, https_only=False):
    """서버가 내부망(공유기, 클라우드 메타데이터 등)으로 요청하지 않게 막음."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in (("https",) if https_only else ("http", "https")) or not p.hostname:
        raise ValueError("http:// 또는 https:// 로 시작하는 주소를 넣어 주세요")
    try:
        addrs = socket.getaddrinfo(p.hostname, None)
    except OSError:
        raise ValueError("그런 주소는 찾을 수 없어요 🤔")
    if any(not ipaddress.ip_address(a[4][0].split("%")[0]).is_global for a in addrs):
        raise ValueError("내부망 주소는 등록할 수 없어요")
    return url


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트로 내부망에 들어가는 것도 막음."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_open = urllib.request.build_opener(SafeRedirect).open


def safe_fetch(url):
    # ponytail: 검사와 접속 사이 DNS가 바뀌는 공격(재바인딩)은 못 막음, 공개 서비스면 접속 IP 고정 필요
    return fetch(public_url(url), _open)


def push(endpoint, title, body, url="/"):
    row = q("select info from subs where endpoint=?", endpoint)
    if not row:
        return False
    try:
        webpush(json.loads(row[0][0]), json.dumps({"title": title, "body": body, "url": url}),
                vapid_private_key=str(KEY), vapid_claims={"sub": SUB}, timeout=10,
                ttl=86400)  # 폰이 꺼져 있어도 하루 동안 보관했다가 전달
        return True
    except Exception as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status in (404, 410):  # 사용자가 알림을 끊음 → 정리
            q("delete from watches where endpoint=?", endpoint)
            q("delete from subs where endpoint=?", endpoint)
        print("푸시 실패:", status, e)
        return False


def evaluate(wid, endpoint, name, url, kw, old, raw=None):
    new = state(safe_fetch(url) if raw is None else raw, kw)
    hit = should_alert(None if old is None else json.loads(old), new, kw)
    q("update watches set state=?, opened=max(opened, ?), checked=?, error=null where id=?",
      json.dumps(new), int(hit), int(time.time()), wid)
    if hit:
        push(endpoint, "🎉 예약 열렸어요!", f"{name} — 지금 바로 확인해 보세요!", url)
    return hit


def poller():
    while True:
        for row in q("select id, endpoint, name, url, keyword, state from watches"):
            try:
                evaluate(*row)
            except Exception as e:
                print(time.strftime("[%H:%M:%S]"), "확인 실패:", row[3], e)
                q("update watches set checked=?, error=? where id=?", int(time.time()), str(e)[:100], row[0])
        time.sleep(INTERVAL)


def owned(d):
    ep = str(d.get("endpoint", ""))
    if not q("select 1 from subs where endpoint=?", ep):
        raise ValueError("먼저 알림을 켜 주세요 🔔")
    return ep


def api_subscribe(d):
    info = d.get("sub") or {}
    public_url(str(info.get("endpoint", "")), https_only=True)
    if not (info.get("keys") or {}).get("p256dh"):
        raise ValueError("알림 구독 정보가 이상해요")
    known = q("select 1 from subs where endpoint=?", info["endpoint"])  # 이미 등록된 기기는 코드 생략
    if not known and not hmac.compare_digest(str(d.get("code", "")).strip().lower().encode(), INVITE.lower().encode()):
        raise ValueError("초대 코드가 맞지 않아요 🔒")
    q("insert or replace into subs values(?, ?)", info["endpoint"], json.dumps(info))
    return {"ok": True}


def api_list(d):
    cols = ("id", "name", "url", "keyword", "opened", "checked", "error")
    rows = q(f"select {', '.join(cols)} from watches where endpoint=? order by id desc", owned(d))
    return {"interval": INTERVAL // 60, "now": int(time.time()), "items": [dict(zip(cols, r)) for r in rows]}


def api_add(d):
    ep = owned(d)
    if q("select count(*) from watches where endpoint=?", ep)[0][0] >= MAX_WATCHES:
        raise ValueError(f"최대 {MAX_WATCHES}개까지 등록할 수 있어요")
    url = public_url(str(d.get("url", "")).strip())
    name = str(d.get("name", "")).strip()[:40] or "이름 없는 사이트"
    kw = str(d.get("keyword", "")).strip()[:50]
    if kw in ("!", ""):
        kw = ""
    try:
        raw = safe_fetch(url)
    except ValueError:
        raise
    except Exception:
        raise ValueError("이 사이트에 들어갈 수 없어요. 주소를 다시 확인해 주세요 🥲")
    wid = q("insert into watches(endpoint, name, url, keyword) values(?,?,?,?)", ep, name, url, kw)
    hit = evaluate(wid, ep, name, url, kw, None, raw)
    text = page_text(raw)
    if hit:
        note = "벌써 조건이 맞아요! 알림을 보냈어요 🎉"
    elif kw and not kw.startswith("!"):
        note = f"지금은 '{kw}' 글자가 없어요. 생기면 바로 알려드릴게요!"
    elif len(text) < 300:
        note = "페이지 내용이 거의 안 보여요. 이 사이트는 감지가 어려울 수 있어요 😢"
    else:
        note = f"등록 완료! {INTERVAL // 60}분마다 살펴볼게요 👀"
    return {"ok": True, "note": note}


def api_delete(d):
    q("delete from watches where id=? and endpoint=?", int(d.get("id", 0)), owned(d))
    return {"ok": True}


def api_test(d):
    if not push(owned(d), "🐣 콕콕! 테스트 알림이에요", "예약이 열리면 이렇게 바로 콕 알려드릴게요!"):
        raise ValueError("알림을 보내지 못했어요. 알림을 다시 켜 주세요")
    return {"ok": True}


ROUTES = {"/api/subscribe": api_subscribe, "/api/list": api_list, "/api/add": api_add,
          "/api/delete": api_delete, "/api/test": api_test}


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/key":
            return self.reply(200, {"key": PUBLIC_KEY})
        if path not in STATIC:
            return self.reply(404, {"error": "없는 페이지예요"})
        name, ctype = STATIC[path]
        self.reply(200, (ROOT / "web" / name).read_bytes(), ctype)

    def do_POST(self):
        fn, n = ROUTES.get(self.path), int(self.headers.get("Content-Length") or 0)
        if not fn:
            return self.reply(404, {"error": "없는 기능이에요"})
        if n > 10_000:
            return self.reply(413, {"error": "요청이 너무 커요"})
        try:
            self.reply(200, fn(json.loads(self.rfile.read(n) or b"{}")))
        except (ValueError, TypeError) as e:
            self.reply(400, {"error": str(e)})
        except Exception as e:
            print("서버 오류:", e)
            self.reply(500, {"error": "앗, 서버에 문제가 생겼어요"})


def start_tunnel():
    """cloudflared로 임시 HTTPS 주소를 만들어 폰 접속 링크를 출력."""
    exe = shutil.which("cloudflared") or next((p for p in (
        r"C:\Program Files (x86)\cloudflared\cloudflared.exe", r"C:\Program Files\cloudflared\cloudflared.exe")
        if os.path.exists(p)), None)
    if os.environ.get("TUNNEL") == "0":
        return
    if not exe:
        print("ℹ️  cloudflared가 없어서 폰용 주소는 만들지 않았어요. (README의 '폰에서 쓰기' 참고)")
        return
    proc = subprocess.Popen([exe, "tunnel", "--no-autoupdate", "--url", f"http://localhost:{PORT}"],
                            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
    atexit.register(proc.terminate)

    def read():  # 파이프가 막히지 않게 끝까지 읽음
        for line in proc.stderr:
            if m := re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line):
                print(f"\n📱 폰에서 이 주소를 여세요 (가족·친구에게 공유해도 돼요):\n   {m.group(0)}/?code={INVITE}\n", flush=True)

    threading.Thread(target=read, daemon=True).start()


if __name__ == "__main__":
    threading.Thread(target=poller, daemon=True).start()
    print(f"🐣 콕콕 예약알림 실행 중 → http://localhost:{PORT}")
    print(f"   초대 코드: {INVITE}   확인 주기: {INTERVAL // 60}분   (끄려면 이 창을 닫거나 Ctrl+C)")
    start_tunnel()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
