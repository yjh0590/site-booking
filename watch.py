"""예매 오픈 감시: urls.txt의 사이트를 주기적으로 확인하고, 바뀌면 알림.

urls.txt 한 줄 형식:  URL [키워드]
  - 키워드 있음 → 페이지에 키워드가 '새로 나타나면' 알림 (권장, 오탐 적음)
  - !키워드    → 페이지에서 키워드가 '사라지면' 알림 (예: !접수예정)
  - 키워드 없음 → 페이지 본문 텍스트가 바뀌면 알림
실행: python watch.py          (자가 점검: python watch.py --test)
폰 알림(선택): 환경변수 NTFY_TOPIC=<아무 비밀 문자열> 설정 후 ntfy 앱에서 같은 토픽 구독
"""
import ctypes, hashlib, html, os, re, sys, threading, time, urllib.request

INTERVAL = max(1, int(os.environ.get("CHECK_MINUTES", 5))) * 60  # ponytail: 전체 공통 주기, 필요하면 사이트별로
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def page_text(raw):
    raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", raw)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", raw)).split())


def state(raw, keyword):
    """키워드 모드: 키워드 포함 여부(bool). 변경 모드: 본문 해시."""
    text = page_text(raw)
    if not keyword:
        return hashlib.sha256(text.encode()).hexdigest()
    # "!키워드" → 키워드가 '사라지면' True
    return (keyword.lstrip("!") in text) != keyword.startswith("!")


def should_alert(old, new, keyword):
    if old is None:  # 첫 확인은 기준값만 저장
        return bool(keyword) and new is True  # 이미 키워드가 있으면 바로 알림
    return (new is True and old is False) if keyword else new != old


def notify(msg):
    print(time.strftime("[%H:%M:%S]"), "알림:", msg, flush=True)
    threading.Thread(target=ctypes.windll.user32.MessageBoxW,
                     args=(0, msg, "예매 알림", 0x40 | 0x40000), daemon=True).start()
    if topic := os.environ.get("NTFY_TOPIC"):
        try:
            urllib.request.urlopen(f"https://ntfy.sh/{topic}", msg.encode(), timeout=10)
        except Exception as e:
            print("ntfy 실패:", e)


def fetch(url, opener=urllib.request.urlopen):
    req = urllib.request.Request(url, headers=UA)
    with opener(req, timeout=20) as r:
        return r.read(3_000_000).decode(r.headers.get_content_charset() or "utf-8", "replace")


def load(path="urls.txt"):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                url, _, kw = line.strip().partition(" ")
                yield url, kw.strip()


def main():
    targets, seen = list(load()), {}
    print(f"{len(targets)}개 사이트 감시 시작, {INTERVAL}초 간격")
    while True:
        for url, kw in targets:
            try:
                raw = fetch(url)
            except Exception as e:
                print(time.strftime("[%H:%M:%S]"), "접속 실패:", url, e)
                continue
            new = state(raw, kw)
            if should_alert(seen.get(url), new, kw):
                what = (f"[{kw[1:]}] 사라짐" if kw.startswith("!") else f"[{kw}] 등장") if kw else "페이지 변경"
                notify(f"{what}\n{url}")
            seen[url] = new
        time.sleep(INTERVAL)


def test():
    a = "<html><script>var t=1</script><p>준비중</p></html>"
    b = "<html><script>var t=2</script><p>예매하기 &amp; 안내</p></html>"
    assert page_text(b) == "예매하기 & 안내"
    assert state(a, "") == state(a.replace("t=1", "t=9"), "")  # 스크립트 변화는 무시
    assert should_alert(state(a, ""), state(b, ""), "")
    assert not should_alert(None, state(a, ""), "")
    assert not should_alert(None, state(a, "예매하기"), "예매하기")
    assert should_alert(state(a, "예매하기"), state(b, "예매하기"), "예매하기")
    assert should_alert(None, state(b, "예매하기"), "예매하기")
    assert not should_alert(True, True, "예매하기")
    assert not should_alert(None, state(a, "!준비중"), "!준비중")  # 아직 있음
    assert should_alert(state(a, "!준비중"), state(b, "!준비중"), "!준비중")  # 사라짐
    print("ok")


if __name__ == "__main__":
    test() if "--test" in sys.argv else main()
