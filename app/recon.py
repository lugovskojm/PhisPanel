import csv
import html
import os
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests

from bs4 import BeautifulSoup

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+")

JUNK_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")


def _normalize_obfuscated(text: str) -> str:
    t = html.unescape(text)
    t = re.sub(r"\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}|\bat\b)\s*", "@", t, flags=re.I)
    t = re.sub(r"\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\})\s*", ".", t, flags=re.I)
    return t


def extract_emails(raw_html: str) -> set[str]:
    text = unquote(_normalize_obfuscated(raw_html))
    soup = BeautifulSoup(raw_html, "html.parser")
    mailto_text = " ".join(
        (a.get("href") or "").replace("mailto:", " ")
        for a in soup.find_all("a", href=True)
    )
    text += " " + mailto_text
    found = set()
    for m in EMAIL_RE.findall(text):
        email = m.lower().strip(".,;:()")
        if any(email.endswith(s) for s in JUNK_SUFFIXES):
            continue
        if "@2x" in email or "example." in email:
            continue
        found.add(email)
    return found


_NAME_STOPWORDS = {
    "директор", "начальник", "министр", "заместитель", "глава", "секретарь",
    "руководитель", "председатель", "управляющий", "инженер", "специалист",
    "консультант", "координатор", "преподаватель", "профессор", "доцент",
    "министерство", "ведомство", "агентство", "управление", "комитет", "отдел",
    "аппарат", "приёмная", "секретариат", "пресс-служба", "коллектив", "команда",
    "университет", "институт", "академия", "факультет", "кафедра", "лаборатория",
    "россия", "москва", "петербург", "область", "город", "район", "единый",
    "портал", "сайт", "новости", "контакты", "телефон", "факс", "адрес", "режим",
    "образование", "науки", "федеральное", "министерство образования",
    "saint", "petersburg", "russia", "moscow", "university", "institute",
    "academy", "ministry", "education", "science", "about", "us", "rector",
    "authorities", "institutes", "faculties", "departments", "structure",
    "international", "affairs", "admissions", "recruitment", "career",
    "news", "events", "contacts", "vacancies", "grants", "research",
    "campus", "street", "st", "building", "hall", "block", "floor",
    "director", "manager", "head", "office",
}

_FUNCTIONAL_LOCALS = {
    "info", "priem", "press", "pr", "hr", "post", "office", "webmaster",
    "admin", "sales", "support", "mail", "secretary", "reklama", "marketing",
    "help", "it", "team",
}

_WORD_RE = r"[A-ZА-ЯЁ][a-zа-яё\-]+"


def _name_runs(text: str) -> list[str]:
    runs = []
    for m in re.finditer(rf"(?:{_WORD_RE}(?:\s+{_WORD_RE}){{1,2}})", text):
        near = text[max(0, m.start() - 15):m.start()] + text[m.end():min(len(text), m.end() + 15)]
        if any(ch.isdigit() for ch in near):
            continue
        words = m.group(0).split()
        kept = [w for w in words if w.strip("-").lower() not in _NAME_STOPWORDS]
        if 2 <= len(kept) <= 3:
            runs.append(" ".join(kept))
    return runs


def guess_name_near_email(raw_html: str, email: str) -> str:
    try:
        soup = BeautifulSoup(raw_html, "html.parser")
    except (AttributeError, TypeError):
        return ""
    needle = email.lower()

    for a in soup.find_all("a", href=True):
        if needle not in (a.get("href") or "").lower():
            continue
        label = re.sub(r"\s+", " ", a.get_text(" ", strip=True))
        if label and label.lower() != needle:
            runs = _name_runs(label)
            if runs:
                return runs[0]

    for node in soup.find_all(string=lambda t: t and needle in _normalize_obfuscated(t).lower()):
        block = node.parent
        for _level in range(5):
            if block is None or getattr(block, "name", None) == "body":
                break
            text = re.sub(r"\s+", " ", block.get_text(" ", strip=True))
            if len(text) > 800:
                break
            cleaned = EMAIL_RE.sub("", _normalize_obfuscated(text))
            cleaned = re.sub(r"[\d\s()+\-]{7,}", "", cleaned)
            runs = _name_runs(cleaned)
            if runs:
                return runs[0]
            block = block.parent

    local_part = needle.split("@", 1)[0].lower()
    if local_part not in _FUNCTIONAL_LOCALS and "_" not in local_part:
        candidates: list[str] = []
        if soup.title is not None:
            candidates.append(soup.title.get_text(" ", strip=True))
        for tag in ("h1", "h2", "h3", "h4"):
            for el in soup.find_all(tag)[:5]:
                candidates.append(el.get_text(" ", strip=True))
        for text in candidates:
            runs = _name_runs(re.sub(r"\s+", " ", text))
            if runs:
                return runs[0]
    return ""


def _stand_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    return bool(re.fullmatch(r"[a-z0-9.\-:\[\]]+", host))


def run_recon(
    start_url: str,
    max_pages: int = 40,
    timeout: float = 6.0,
    max_depth: int = 3,
    max_queue: int = 200,
    retries: int = 1,
    include_status: bool = False,
    cross_domain: bool = False,
    cross_confirm: str = "",
    on_progress=None,
):
    try:
        max_pages = max(1, min(int(max_pages), 100))
        max_depth = max(0, min(int(max_depth), 10))
        max_queue = max(1, min(int(max_queue), 500))
        retries = max(0, min(int(retries), 3))
    except (TypeError, ValueError) as exc:
        raise ValueError("Параметры разведки должны быть числами") from exc

    start = start_url if re.match(r"^https?://", start_url) else f"https://{start_url}"
    parsed_start = urlparse(start)
    host = (parsed_start.hostname or "").lower()
    if not _stand_host(host):
        raise ValueError("Ожидается http/https URL с хостом")
    try:
        port = parsed_start.port
    except ValueError as exc:
        raise ValueError("Некорректный порт в URL") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Некорректный порт в URL")
    if cross_domain and cross_confirm != "CONFIRM":
        raise ValueError("Cross-domain режим требует подтверждение CONFIRM")

    tool_dir = Path(__file__).resolve().parent.parent / "data" / "tools" / "email-crawler"
    dist_entry = tool_dir / "dist" / "index.js"
    if not dist_entry.exists():
        raise RuntimeError("atesahmet0/email-crawler dist/index.js не собран")

    node = Path("C:/Program Files/nodejs/node.exe")
    if not node.exists():
        node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js executable не найден")

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    output_dir = Path(__file__).resolve().parent.parent / "data" / "recon"
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / f"{run_id}.csv"

    command = [
        str(node),
        str(dist_entry),
        "--url",
        start,
        "--output",
        str(csv_path),
        "--depth",
        str(max_depth),
        "--max-pages",
        str(min(max_pages, max_queue)),
    ]
    if cross_domain:
        command.append("--cross-domain")
    # --debug: CLI печатает строки «Visiting URL» — прогресс-бар панели зависит от них
    command.append("--debug")

    env = {
        **os.environ,
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "NO_PROXY": "*",
    }
    attempts = retries + 1
    last_error = "неизвестная ошибка"
    completed_output = None
    for _attempt in range(attempts):
        # CLI сам ограничивает страницу 10 с; даём 12 с/страницу + запас на DNS/TLS
        deadline = time.monotonic() + max(30, min(int(max_pages) * 12 + 60, 900))
        out_lines: list[str] = []
        timed_out = False
        try:
            with subprocess.Popen(
                command,
                cwd=str(tool_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            ) as proc:
                for line in proc.stdout:
                    out_lines.append(line)
                    if on_progress is not None and "Visiting URL" in line:
                        pages_done = sum(1 for l in out_lines if "Visiting URL" in l)
                        on_progress(pages_done, line.rsplit("): ", 1)[-1].strip())
                    if time.monotonic() > deadline:
                        proc.kill()
                        timed_out = True
                        break
                try:
                    returncode = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    returncode = proc.wait(timeout=5)
        except OSError as exc:
            last_error = f"Не удалось запустить email-crawler: {exc}"
            continue
        output_text = "".join(out_lines)
        if returncode == 0 and not timed_out:
            completed_output = output_text
            break
        detail = output_text.strip()[-1000:] or "неизвестная ошибка"
        last_error = (
            f"Email-crawler превысил таймаут процесса: {detail}"
            if timed_out
            else f"Email-crawler завершился с ошибкой: {detail}"
        )
    if completed_output is None:
        raise RuntimeError(last_error)

    found: dict[str, dict] = {}
    if csv_path.exists():
        try:
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    email = (row.get("email") or "").strip().lower()
                    source_url = (row.get("sourceURL") or "").strip()
                    if not email or email in found:
                        continue
                    found[email] = {
                        "email": email,
                        "url": source_url,
                        "name": "",
                    }
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            raise RuntimeError(f"Не удалось прочитать результаты email-crawler: {exc}") from exc

    # Best-effort имена сотрудников: перечитываем страницы, где нашлась почта
    # (лимит 30 адресов, чтобы не тормозить при большом результате)
    if found and len(found) <= 30:
        for item in found.values():
            if not item["url"]:
                continue
            try:
                resp = requests.get(item["url"], headers={"User-Agent": UA}, timeout=8)
                if resp.status_code == 200:
                    item["name"] = guess_name_near_email(resp.text, item["email"])
            except requests.RequestException:
                pass

    results = list(found.values())
    visited_urls = []
    for line in completed_output.splitlines():
        if "Visiting URL" not in line:
            continue
        last_part = line.rsplit("): ", 1)[-1].strip()
        if last_part and last_part not in visited_urls:
            visited_urls.append(last_part)

    pages_visited = len(visited_urls)
    http_errors = sum(1 for line in completed_output.splitlines() if "HTTP Error for" in line)
    pages = [
        {"url": url, "status": "completed", "depth": 0}
        for url in visited_urls
    ]
    status = {
        "tool": "atesahmet0/email-crawler",
        "http_errors": http_errors,
        "command": " ".join(command),
        "run_id": run_id,
        "csv_path": str(csv_path),
        "pages_visited": pages_visited,
        "queue_remaining": 0,
        "pages": pages,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "cross_domain": cross_domain,
        "stdout": completed_output[-2000:].strip(),
    }
    if include_status:
        return results, min(max_pages, max_queue), status
    return results, min(max_pages, max_queue)
