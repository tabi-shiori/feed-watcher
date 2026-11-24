#!/usr/bin/env python3
"""
Privacy-Preserving 24/7 Feed Update Monitor & iOS Bark Silent-Pin Notifier
- All sensitive parameters (BARK_KEY, WEREAD_COOKIE, MONITOR_TARGETS_JSON) are loaded from
  encrypted environment secrets or local gitignored config.json.
- Deduplication state (state.json) stores only irreversible 20-char SHA-256 hashes (seen_hashes).
- Public CI logs never print feed names, article titles, or article URLs.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import html
import io
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import qrcode
import requests

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "state.json"
SNAPSHOT_DIR = BASE_DIR / "snapshots"
LOG_PATH = BASE_DIR / "monitor.log"
QR_PNG_PATH = BASE_DIR / "weread_qr.png"

BEIJING_TZ = datetime.timezone(datetime.timedelta(hours=8))
WEREAD_BASE = "https://weread.qq.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# 排除源与 ID 的单向 SHA-256 前缀
EXCLUDED_HASHES = {
    "31a5f4222848f2e91f17",
    "6e7f741c7d853a6e026e",
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "bark_key": "",
    "bark_server": "https://api.day.app",
    "bark_mode": "silent_pin",
    "bark_group": "订阅更新",
    "click_action": "article_url",
    "weread_cookie": "",
    "weread_vid": "",
    "monitored_accounts": [],
    "excluded_accounts": [],
    "monitored_book_ids": {},
    "auto_snapshot": True,
    "golden_window_interval_sec": 180,
    "daytime_interval_sec": 300,
    "night_interval_sec": 900,
}

_ACTIVE_COOKIE_STR: str = ""


def sha20(value: str) -> str:
    """计算单向 SHA-256 摘要（前 20 位十六进制），用于无明文隐私去重。"""
    norm = (value or "").strip()
    if not norm:
        return ""
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:20]


def setup_logger() -> logging.Logger:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("feed_monitor")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fh.setFormatter(fmt)
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(fh)
        logger.addHandler(sh)
    return logger


logger = setup_logger()


def load_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except Exception as exc:
            logger.warning("读取配置文件失败: %s", exc)

    if os.environ.get("BARK_KEY"):
        cfg["bark_key"] = os.environ["BARK_KEY"].strip()
    if os.environ.get("BARK_SERVER"):
        cfg["bark_server"] = os.environ["BARK_SERVER"].strip().rstrip("/")
    if os.environ.get("BARK_MODE"):
        cfg["bark_mode"] = os.environ["BARK_MODE"].strip()
    if os.environ.get("WEREAD_COOKIE"):
        cfg["weread_cookie"] = os.environ["WEREAD_COOKIE"].strip()
    if _ACTIVE_COOKIE_STR:
        cfg["weread_cookie"] = _ACTIVE_COOKIE_STR
    if os.environ.get("MONITOR_TARGETS_JSON"):
        try:
            targets = json.loads(os.environ["MONITOR_TARGETS_JSON"])
            if isinstance(targets, dict):
                cfg["monitored_book_ids"] = targets
                if not cfg.get("monitored_accounts"):
                    cfg["monitored_accounts"] = sorted(set(targets.values()))
        except Exception as exc:
            logger.warning("解析 MONITOR_TARGETS_JSON 失败: %s", exc)

    book_ids = dict(cfg.get("monitored_book_ids") or {})
    for bid in list(book_ids.keys()):
        if sha20(bid) in EXCLUDED_HASHES or sha20(book_ids[bid]) in EXCLUDED_HASHES:
            book_ids.pop(bid, None)
    cfg["monitored_book_ids"] = book_ids
    return cfg


def save_config(cfg: Dict[str, Any], path: Path = CONFIG_PATH) -> Dict[str, Any]:
    merged = load_config(path)
    merged.update(cfg)
    path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return merged


def normalize_bark_key_and_server(raw_key: str, default_server: str = "https://api.day.app") -> Tuple[str, str]:
    raw = (raw_key or "").strip()
    server = (default_server or "https://api.day.app").strip().rstrip("/")
    if not raw:
        return server, ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urllib.parse.urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}"
        parts = [p for p in parsed.path.split("/") if p and p != "push"]
        key = parts[0] if parts else ""
        return base, key
    return server, raw.strip("/")


def is_account_monitored(account_name: str, config: Optional[Dict[str, Any]] = None) -> bool:
    cfg = config or load_config()
    name = (account_name or "").strip()
    if not name:
        return False
    if sha20(name) in EXCLUDED_HASHES:
        return False
    for ex in cfg.get("excluded_accounts") or []:
        if ex and ex in name:
            return False
    # 检查前缀匹配排除项
    for i in range(1, len(name) + 1):
        if sha20(name[:i]) in EXCLUDED_HASHES:
            return False

    monitored = list(cfg.get("monitored_accounts") or [])
    book_map = cfg.get("monitored_book_ids") or {}
    for v in book_map.values():
        if v and v not in monitored:
            monitored.append(v)
    for target in monitored:
        if target and (target == name or target in name):
            return True
    return False


def build_mp_url_from_review_id(review_id: str, book_id: str = "") -> str:
    rid = str(review_id or "").strip()
    if not rid:
        return ""
    if rid.startswith("http://") or rid.startswith("https://"):
        return rid
    token = rid
    prefix = f"{book_id}_" if book_id else ""
    if prefix and rid.startswith(prefix):
        token = rid[len(prefix):]
    elif "_" in token:
        token = token.split("_")[-1]
    token = token.replace("~", "_")
    return f"https://mp.weixin.qq.com/s/{urllib.parse.quote(token, safe='')}"


def build_bark_payload(
    article: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cfg = config or DEFAULT_CONFIG
    _, device_key = normalize_bark_key_and_server(
        cfg.get("bark_key", ""),
        cfg.get("bark_server", "https://api.day.app"),
    )

    account = (article.get("account") or "订阅号").strip()
    title = (article.get("title") or "新文章更新").strip()
    pub_time = (article.get("published_at") or "刚刚").strip()
    url = (article.get("url") or "").strip()
    summary = (article.get("summary") or "").strip()

    clean_summary = re.sub(r"<[^>]+>", "", summary)
    clean_summary = html.unescape(clean_summary).strip()
    clean_summary = re.sub(r"\s+", " ", clean_summary)
    if len(clean_summary) > 110:
        clean_summary = clean_summary[:110] + "…"

    notif_title = f"【{account}】更新：{title}"
    notif_subtitle = f"{pub_time} · 点击直接看全文"
    notif_body = clean_summary if clean_summary else f"公众号「{account}」发布了新文章《{title}》，点击立即查看。"

    mode = cfg.get("bark_mode", "silent_pin")
    payload: Dict[str, Any] = {
        "device_key": device_key,
        "id": f"mp_{sha20(title)}",
        "title": notif_title,
        "subtitle": notif_subtitle,
        "body": notif_body,
        "group": cfg.get("bark_group", "订阅更新"),
        "isArchive": "1",
    }

    if mode == "silent_pin":
        payload["level"] = "timeSensitive"
        payload["sound"] = "silence"
    elif mode == "normal_ring":
        payload["level"] = "timeSensitive"
        payload["sound"] = "minuet"
    elif mode == "critical_alarm":
        payload["level"] = "critical"
        payload["volume"] = "10"
        payload["call"] = "1"
        payload["sound"] = "alarm"
    else:
        payload["level"] = "timeSensitive"
        payload["sound"] = "silence"

    click_action = cfg.get("click_action", "article_url")
    if click_action == "wechat_app" or not url:
        payload["url"] = "weixin://"
        if url:
            payload["copy"] = url
            payload["autoCopy"] = "1"
        else:
            payload["copy"] = title
    else:
        payload["url"] = url
        payload["copy"] = url

    return payload


def send_bark_notification(
    article: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    timeout: int = 10,
) -> Dict[str, Any]:
    cfg = config or load_config()
    server, device_key = normalize_bark_key_and_server(
        cfg.get("bark_key", ""),
        cfg.get("bark_server", "https://api.day.app"),
    )
    if not device_key:
        return {
            "ok": False,
            "error": "missing_bark_key",
        }

    payload = build_bark_payload(article, cfg)
    push_endpoint = f"{server}/push"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        push_endpoint,
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Feed-Update-Notifier/2.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_resp = resp.read().decode("utf-8", errors="replace")
            resp_json = json.loads(raw_resp)
            ok = resp.status == 200 and resp_json.get("code") == 200
            return {
                "ok": ok,
                "status": resp.status,
                "response": resp_json,
            }
    except Exception as exc:
        logger.error("Bark push failed: %s", exc)
        return {
            "ok": False,
            "error": str(exc),
        }


def get_poll_interval_seconds(
    now_dt: Optional[datetime.datetime] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[int, str]:
    cfg = config or DEFAULT_CONFIG
    now_bj = (now_dt or datetime.datetime.now(datetime.timezone.utc)).astimezone(BEIJING_TZ)
    hm = now_bj.hour * 60 + now_bj.minute

    if 8 * 60 + 15 <= hm <= 12 * 60 + 30:
        return int(cfg.get("golden_window_interval_sec", 180)), "早间黄金高发期 (08:15-12:30)"
    if 12 * 60 + 30 < hm <= 23 * 60 + 30:
        return int(cfg.get("daytime_interval_sec", 300)), "日间/盘前活跃期 (12:30-23:30)"
    return int(cfg.get("night_interval_sec", 900)), "夜间巡航期 (23:30-08:15)"


def save_article_snapshot(article: Dict[str, Any], cookie_str: str = "") -> Optional[str]:
    """仅在本地非公开环境下保存快照（GitHub Actions 公开仓库模式下跳过落盘以保护隐私）"""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return None
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    account = re.sub(r"[^\w\u4e00-\u9fff-]+", "_", article.get("account") or "feed")
    title = re.sub(r"[^\w\u4e00-\u9fff-]+", "_", article.get("title") or "item")[:40]
    date_prefix = datetime.datetime.now(BEIJING_TZ).strftime("%Y%m%d_%H%M%S")
    stem = f"{date_prefix}_{account}_{title}"

    snapshot_record = dict(article)
    snapshot_record["saved_at"] = datetime.datetime.now(BEIJING_TZ).isoformat()
    json_file = SNAPSHOT_DIR / f"{stem}.json"
    json_file.write_text(json.dumps(snapshot_record, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(json_file.relative_to(BASE_DIR))


def parse_wewe_json_feed(feed_data: Dict[str, Any], fallback_account: str = "") -> List[Dict[str, Any]]:
    feed_title = (feed_data.get("title") or fallback_account or "").strip()
    items = feed_data.get("items") or []
    articles: List[Dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        author_name = ""
        authors = item.get("authors")
        if isinstance(authors, list) and authors and isinstance(authors[0], dict):
            author_name = (authors[0].get("name") or "").strip()
        if not author_name and isinstance(item.get("author"), dict):
            author_name = (item["author"].get("name") or "").strip()

        account = author_name or feed_title or fallback_account or "feed"
        article_id = str(item.get("id") or item.get("url") or "").strip()
        title = (item.get("title") or "").strip()
        url = (item.get("url") or item.get("external_url") or "").strip()
        content_html = item.get("content_html") or item.get("content_text") or item.get("summary") or ""
        published_raw = (item.get("date_published") or item.get("date_modified") or "").strip()

        pub_display = published_raw
        if published_raw:
            try:
                dt = datetime.datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
                pub_display = dt.astimezone(BEIJING_TZ).strftime("%Y-%m-%d %H:%M")
            except Exception:
                pub_display = published_raw

        if not article_id and title:
            article_id = sha20(f"{account}:{title}:{url}")

        articles.append(
            {
                "id": article_id,
                "account": account,
                "title": title,
                "url": url,
                "published_at": pub_display,
                "published_raw": published_raw,
                "summary": content_html,
                "content_html": content_html,
                "source": "json_feed",
            }
        )
    return articles


class WereadDirectManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.uid: str = ""
        self.confirm_url: str = ""
        self.qr_base64: str = ""
        self.status: str = "idle"
        self.status_msg: str = "尚未生成二维码"
        self.session: Optional[requests.Session] = None
        self.poll_thread: Optional[threading.Thread] = None
        self.started_at: float = 0.0

    def start_new_qr_session(self) -> Dict[str, Any]:
        with self._lock:
            sess = requests.Session()
            sess.headers.update(
                {
                    "User-Agent": UA,
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Origin": WEREAD_BASE,
                    "Referer": f"{WEREAD_BASE}/",
                }
            )
            resp = sess.get(f"{WEREAD_BASE}/api/auth/getLoginUid", timeout=15)
            data = resp.json()
            uid = str(data.get("uid") or (data.get("data") or {}).get("uid") or "").strip()
            if not uid:
                raise RuntimeError(f"获取登录 UID 失败: {data}")

            confirm_url = f"{WEREAD_BASE}/web/confirm?uid={uid}"
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=3,
            )
            qr.add_data(confirm_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")

            buf = io.BytesIO()
            img.save(buf, format="PNG")
            png_bytes = buf.getvalue()
            QR_PNG_PATH.write_bytes(png_bytes)

            self.uid = uid
            self.confirm_url = confirm_url
            self.qr_base64 = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
            self.session = sess
            self.status = "waiting_scan"
            self.status_msg = "请使用手机微信扫描二维码，并在手机上点击「确认登录」"
            self.started_at = time.time()

            t = threading.Thread(target=self._poll_loop, args=(uid, sess), daemon=True)
            self.poll_thread = t
            t.start()

            return {
                "ok": True,
                "uid": uid,
                "confirm_url": confirm_url,
                "qr_base64": self.qr_base64,
                "status": self.status,
                "status_msg": self.status_msg,
            }

    def _poll_loop(self, uid: str, sess: requests.Session) -> None:
        while time.time() - self.started_at < 300:
            if self.uid != uid:
                return
            try:
                resp = sess.get(
                    f"{WEREAD_BASE}/api/auth/getLoginInfo",
                    params={"uid": uid, "otp": ""},
                    timeout=35,
                )
                if resp.status_code != 200:
                    time.sleep(2)
                    continue
                data = resp.json()
                inner = data.get("data") or {}
                succeed = data.get("succeed") or inner.get("succeed")
                logic_code = data.get("logicCode") or inner.get("logicCode") or ""

                if logic_code == 1 or str(logic_code) == "1":
                    self.status_msg = "📱 已扫码！请在手机微信上点击「确认登录」..."

                if succeed:
                    vid = str(
                        data.get("webLoginVid")
                        or data.get("vid")
                        or data.get("userVid")
                        or inner.get("webLoginVid")
                        or inner.get("vid")
                        or inner.get("userVid")
                        or ""
                    )
                    access_token = str(
                        data.get("accessToken")
                        or inner.get("accessToken")
                        or data.get("skey")
                        or ""
                    )
                    refresh_token = str(
                        data.get("refreshToken")
                        or inner.get("refreshToken")
                        or ""
                    )

                    cookies: Dict[str, str] = {c.name: c.value for c in sess.cookies}
                    if vid:
                        cookies["wr_vid"] = vid
                    if access_token and not cookies.get("wr_skey"):
                        cookies["wr_skey"] = access_token
                    if refresh_token and not cookies.get("wr_rt"):
                        cookies["wr_rt"] = urllib.parse.quote(refresh_token, safe="")

                    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items() if v)
                    save_config({"weread_cookie": cookie_str, "weread_vid": vid})

                    self.status = "logged_in"
                    self.status_msg = f"✅ 扫码登录成功 (VID={vid})"
                    return
            except requests.exceptions.Timeout:
                continue
            except Exception:
                time.sleep(2)

        if self.uid == uid and self.status == "waiting_scan":
            self.status = "expired"
            self.status_msg = "二维码已超时，请刷新重试"


WEREAD_QR_MANAGER = WereadDirectManager()

_last_backup_check_ts: float = 0.0
_last_cookie_renew_ts: float = 0.0


def renew_weread_cookie_if_needed(cookie_str: str, force: bool = False) -> str:
    global _last_cookie_renew_ts, _ACTIVE_COOKIE_STR
    now = time.time()
    # wr_skey 有效期为 5400 秒（90 分钟），因此进程启动首次及每 35 分钟（2100 秒）主动用 wr_rt 静默续期
    if not force and _last_cookie_renew_ts and (now - _last_cookie_renew_ts < 2100):
        return _ACTIVE_COOKIE_STR or cookie_str

    base_cookie = _ACTIVE_COOKIE_STR or cookie_str
    try:
        sess = requests.Session()
        sess.headers.update(
            {
                "User-Agent": UA,
                "Accept": "application/json, text/plain, */*",
                "Origin": WEREAD_BASE,
                "Referer": f"{WEREAD_BASE}/",
            }
        )
        cookies_dict: Dict[str, str] = {}
        for part in base_cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies_dict[k.strip()] = v.strip()
                sess.cookies.set(k.strip(), v.strip(), domain="weread.qq.com")

        # 根据 cookie 中的 wr_ql 自动匹配 ql 参数（wr_ql=0 时必须传 ql=False，否则报 -2013）
        ql_flag = cookies_dict.get("wr_ql") == "1"
        r = sess.post(
            f"{WEREAD_BASE}/web/login/renewal",
            json={"rq": "%2Fweb%2Fmp%2Fcover", "ql": ql_flag},
            timeout=12,
        )
        _last_cookie_renew_ts = now
        if r.status_code == 200:
            rj = r.json()
            if not rj.get("errCode") and not rj.get("errcode"):
                for c in sess.cookies:
                    cookies_dict[c.name] = c.value
                if rj.get("accessToken"):
                    cookies_dict["wr_skey"] = str(rj["accessToken"])
                new_cookie_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items() if v)
                if new_cookie_str:
                    _ACTIVE_COOKIE_STR = new_cookie_str
                    if os.environ.get("GITHUB_ACTIONS") != "true" and new_cookie_str != cookie_str:
                        save_config({"weread_cookie": new_cookie_str})
                    return new_cookie_str
    except Exception:
        pass
    return base_cookie


def fetch_weread_direct_articles(
    config: Optional[Dict[str, Any]] = None,
    check_backups: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    global _last_backup_check_ts
    cfg = config or load_config()
    raw_cookie = (cfg.get("weread_cookie") or "").strip()
    book_map: Dict[str, str] = dict(cfg.get("monitored_book_ids") or {})

    diag: Dict[str, Any] = {
        "mode": "weread_direct_light",
        "cookie_configured": bool(raw_cookie),
        "auth_valid": False,
        "feeds_checked": 0,
        "errors": [],
    }
    if not raw_cookie:
        diag["errors"].append("missing_cookie")
        return [], diag

    # 主动确保 wr_skey 处于有效期内（避免 /api/mp/cover 在过期时仍返回 200 静态旧缓存）
    cookie_str = renew_weread_cookie_if_needed(raw_cookie)

    headers = {
        "Cookie": cookie_str,
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Origin": WEREAD_BASE,
        "Referer": f"{WEREAD_BASE}/",
    }

    # 通过真实鉴权接口 /web/shelf/sync 校验 wr_skey 是否真正有效
    try:
        r_sync = requests.get(
            f"{WEREAD_BASE}/web/shelf/sync",
            params={"userVid": "", "synckey": "0"},
            headers=headers,
            timeout=12,
        )
        if r_sync.status_code == 200:
            sj = r_sync.json()
            if sj.get("errCode") in (-2012, -2010):
                cookie_str = renew_weread_cookie_if_needed(cookie_str, force=True)
                headers["Cookie"] = cookie_str
                r_sync = requests.get(
                    f"{WEREAD_BASE}/web/shelf/sync",
                    params={"userVid": "", "synckey": "0"},
                    headers=headers,
                    timeout=12,
                )
                sj = r_sync.json() if r_sync.status_code == 200 else {}
            if not sj.get("errCode") and not sj.get("errcode"):
                diag["auth_valid"] = True
            else:
                diag["errors"].append(f"auth_{sj.get('errCode')}")
    except Exception:
        diag["errors"].append("sync_check_err")

    now = time.time()
    should_check_backups = check_backups or (now - _last_backup_check_ts >= 900)
    if should_check_backups:
        _last_backup_check_ts = now

    collected: List[Dict[str, Any]] = []
    book_items = list(book_map.items())

    for idx, (book_id, fallback_name) in enumerate(book_items):
        if sha20(book_id) in EXCLUDED_HASHES or not is_account_monitored(fallback_name, cfg):
            continue
        is_primary = idx < 2
        if not is_primary and not should_check_backups:
            continue

        diag["feeds_checked"] += 1
        try:
            r_cov = requests.get(
                f"{WEREAD_BASE}/api/mp/cover",
                params={"bookId": book_id},
                headers=headers,
                timeout=12,
            )
            if r_cov.status_code == 401:
                cookie_str = renew_weread_cookie_if_needed(cookie_str, force=True)
                headers["Cookie"] = cookie_str
                r_cov = requests.get(
                    f"{WEREAD_BASE}/api/mp/cover",
                    params={"bookId": book_id},
                    headers=headers,
                    timeout=12,
                )

            if r_cov.status_code == 200:
                cj = r_cov.json()
                rid = str(cj.get("reviewId") or "").strip()
                title = str(cj.get("title") or "").strip()
                acc_name = str(cj.get("name") or fallback_name).strip()
                if rid and title and is_account_monitored(acc_name, cfg):
                    url = build_mp_url_from_review_id(rid, book_id)
                    collected.append(
                        {
                            "id": rid,
                            "book_id": book_id,
                            "account": acc_name,
                            "title": title,
                            "url": url,
                            "published_at": datetime.datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M"),
                            "summary": f"公众号「{acc_name}」发布了新文章",
                            "source": "weread_cover",
                        }
                    )
            elif r_cov.status_code == 401:
                diag["errors"].append("http_401")
        except Exception:
            diag["errors"].append("request_err")

    return collected, diag


def load_state(path: Path = STATE_PATH) -> Dict[str, Any]:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {
        "initialized": True,
        "baseline_synced": True,
        "seen_hashes": [],
        "last_status": "idle",
        "consecutive_auth_failures": 0,
        "auth_alert_sent_date": None,
    }


def save_state(state: Dict[str, Any], path: Path = STATE_PATH) -> None:
    # 仅保留无明文的哈希字段，彻底杜绝向公开仓库写入任何文章标题或公众号名
    clean_state = {
        "initialized": bool(state.get("initialized", True)),
        "baseline_synced": bool(state.get("baseline_synced", True)),
        "seen_hashes": sorted(set(state.get("seen_hashes") or [])),
        "last_status": state.get("last_status", "monitoring_active"),
        "consecutive_auth_failures": int(state.get("consecutive_auth_failures") or 0),
        "auth_alert_sent_date": state.get("auth_alert_sent_date"),
    }
    path.write_text(json.dumps(clean_state, ensure_ascii=False, indent=2), encoding="utf-8")


def run_check_cycle(
    config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    cfg = config or load_config()
    state = load_state()

    # 兼容迁移旧版 seen_ids / seen_titles 为单向 SHA-256 哈希
    seen_hashes = set(state.get("seen_hashes") or [])
    for old_id in state.get("seen_ids") or []:
        if old_id:
            seen_hashes.add(sha20(old_id))
    for old_title in state.get("seen_titles") or []:
        if old_title:
            seen_hashes.add(sha20(old_title.rstrip("~～ ")))

    prev_hashes = sorted(seen_hashes)
    prev_fails = int(state.get("consecutive_auth_failures") or 0)

    articles, diag = fetch_weread_direct_articles(cfg, check_backups=force_refresh)
    new_articles: List[Dict[str, Any]] = []
    push_results: List[Dict[str, Any]] = []

    is_first_baseline = not state.get("baseline_synced") and len(articles) > 0

    for art in reversed(articles):
        aid = art.get("id") or ""
        title = (art.get("title") or "").strip()
        account = (art.get("account") or "").strip()
        if not is_account_monitored(account, cfg):
            continue

        id_hash = sha20(aid)
        title_hash = sha20(title.rstrip("~～ "))

        if (id_hash and id_hash in seen_hashes) or (title_hash and title_hash in seen_hashes):
            if id_hash:
                seen_hashes.add(id_hash)
            if title_hash:
                seen_hashes.add(title_hash)
            continue

        if id_hash:
            seen_hashes.add(id_hash)
        if title_hash:
            seen_hashes.add(title_hash)

        if is_first_baseline:
            continue

        new_articles.append(art)
        if cfg.get("auto_snapshot", True):
            save_article_snapshot(art, cfg.get("weread_cookie", ""))

        push_res = send_bark_notification(art, cfg)
        push_results.append({"hash": id_hash, "pushed": push_res.get("ok", False)})

    if len(articles) > 0:
        state["baseline_synced"] = True
    state["seen_hashes"] = sorted(seen_hashes)
    now_str = datetime.datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")

    today_bj = datetime.datetime.now(BEIJING_TZ).strftime("%Y-%m-%d")
    if diag.get("auth_valid"):
        state["last_status"] = "monitoring_active"
        state["consecutive_auth_failures"] = 0
        state["auth_alert_sent_date"] = None
    elif not diag.get("cookie_configured"):
        state["last_status"] = "waiting_qr_scan"
    else:
        fails = prev_fails + 1
        state["consecutive_auth_failures"] = fails
        state["last_status"] = f"auth_failed_{fails}"
        if fails >= 2 and state.get("auth_alert_sent_date") != today_bj:
            alert_res = send_bark_notification(
                {
                    "account": "监控系统告警",
                    "title": "⚠️ 微信读书登录已过期，请重新扫码",
                    "published_at": now_str,
                    "url": "https://github.com/tabi-shiori/feed-watcher/actions",
                    "summary": "微信读书长效凭证已过期（HTTP 401），请重新扫一次微信读书二维码恢复监控。",
                },
                cfg,
            )
            if alert_res.get("ok"):
                state["auth_alert_sent_date"] = today_bj

    meaningful_change = (
        bool(new_articles)
        or state["seen_hashes"] != prev_hashes
        or int(state.get("consecutive_auth_failures") or 0) != prev_fails
    )
    if meaningful_change or os.environ.get("GITHUB_ACTIONS") != "true":
        save_state(state)

    return {
        "checked_at": now_str,
        "auth_valid": diag.get("auth_valid", False),
        "feeds_checked": diag.get("feeds_checked", 0),
        "articles_scanned": len(articles),
        "new_articles_count": len(new_articles),
        "pushed_count": sum(1 for r in push_results if r.get("pushed")),
    }


def get_sample_latest_article() -> Dict[str, Any]:
    return {
        "id": "sample_test_id",
        "account": "订阅提醒测试",
        "title": "Bark 静音亮屏置顶测试通知",
        "published_at": datetime.datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M"),
        "url": "https://mp.weixin.qq.com/",
        "summary": "测试通知：收到时屏幕无声点亮并带有时效性置顶标记。",
    }


def git_sync_state_if_needed() -> None:
    """在长驻 GitHub Actions 容器运行期间，一旦发现新文章更新了 state.json，立即实时 push 回仓库。"""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    try:
        import subprocess
        subprocess.run(["git", "config", "user.name", "github-actions[bot]"], cwd=BASE_DIR, check=False)
        subprocess.run(
            ["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"],
            cwd=BASE_DIR,
            check=False,
        )
        subprocess.run(["git", "add", "state.json"], cwd=BASE_DIR, check=False)
        diff_res = subprocess.run(["git", "diff", "--staged", "--quiet"], cwd=BASE_DIR)
        if diff_res.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", "chore(state): update seen item hashes [skip ci]"],
                cwd=BASE_DIR,
                check=False,
            )
            subprocess.run(["git", "pull", "--rebase", "origin", "main"], cwd=BASE_DIR, check=False)
            subprocess.run(["git", "push", "origin", "main"], cwd=BASE_DIR, check=False)
    except Exception as exc:
        logger.warning("Git sync warning: %s", exc)


def main() -> None:
    parser = argparse.ArgumentParser(description="Privacy-preserving feed update notifier")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--burst-seconds", type=int, default=0)
    parser.add_argument("--burst-interval", type=int, default=0)
    parser.add_argument("--test-bark", action="store_true")
    parser.add_argument("--bark-key", type=str, default="")
    parser.add_argument("--gen-qr", action="store_true")
    args = parser.parse_args()

    cfg = load_config()
    if args.bark_key:
        cfg = save_config({"bark_key": args.bark_key.strip()})

    if args.test_bark:
        sample = get_sample_latest_article()
        res = send_bark_notification(sample, cfg)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return

    if args.gen_qr:
        info = WEREAD_QR_MANAGER.start_new_qr_session()
        print(json.dumps({k: v for k, v in info.items() if k != "qr_base64"}, ensure_ascii=False, indent=2))
        return

    if args.burst_seconds > 0:
        start_ts = time.time()
        round_idx = 0
        last_res: Dict[str, Any] = {}
        while True:
            round_idx += 1
            cfg = load_config()
            last_res = run_check_cycle(cfg, force_refresh=(round_idx % 5 == 1))
            if last_res.get("new_articles_count", 0) > 0:
                git_sync_state_if_needed()
            sleep_sec = args.burst_interval if args.burst_interval > 0 else get_poll_interval_seconds(config=cfg)[0]
            if round_idx == 1 or round_idx % 5 == 0 or last_res.get("new_articles_count", 0) > 0:
                logger.info(
                    "Patrol #%d | auth=%s | scanned=%d | new=%d | next=%ds",
                    round_idx,
                    last_res.get("auth_valid"),
                    last_res.get("articles_scanned", 0),
                    last_res.get("new_articles_count", 0),
                    sleep_sec,
                )
            elapsed = time.time() - start_ts
            if elapsed + sleep_sec > args.burst_seconds:
                break
            time.sleep(sleep_sec)
        git_sync_state_if_needed()
        print(json.dumps(last_res, ensure_ascii=False, indent=2))
        return

    if args.once:
        res = run_check_cycle(cfg, force_refresh=True)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return

    while True:
        interval_sec, _ = get_poll_interval_seconds(config=cfg)
        res = run_check_cycle(cfg, force_refresh=True)
        logger.info(
            "Patrol done | scanned=%d | new=%d | next=%ds",
            res["articles_scanned"],
            res["new_articles_count"],
            interval_sec,
        )
        time.sleep(interval_sec)
        cfg = load_config()


if __name__ == "__main__":
    main()
