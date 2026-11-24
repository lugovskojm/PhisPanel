"""PhishPanel — веб-панель мониторинга устойчивости персонала к фишингу."""
import base64
import hashlib
import hmac
import os
import re
import csv
import io
import json
import imaplib
import smtplib
import threading
import uuid
import zipfile
import shutil
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import models
from .clone import archive_mirror, clone_site, entry_rel_path, media_type_for
from .db import DATA_DIR, Base, SessionLocal, engine, get_db
from .models import (
    ArchiveJob,
    Campaign,
    CampaignContact,
    Contact,
    CredentialSubmission,
    EmailTemplate,
    LandingPage,
    Setting,
    TrackingEvent,
)
from .recon import run_recon

Base.metadata.create_all(engine)

app = FastAPI(title="PhishPanel")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# Additive migration for databases created by earlier versions.
with engine.begin() as conn:
    columns = {
        row[1]
        for row in conn.exec_driver_sql("PRAGMA table_info(campaign_contacts)").fetchall()
    }
    additions = (
        ("delivery_status", "VARCHAR(30) DEFAULT 'pending'"),
        ("delivery_error", "TEXT DEFAULT ''"),
        ("imap_location", "VARCHAR(30) DEFAULT 'not_checked'"),
        ("imap_error", "TEXT DEFAULT ''"),
        ("sent_at", "DATETIME"),
        ("checked_at", "DATETIME"),
    )
    for name, ddl in additions:
        if name not in columns:
            conn.exec_driver_sql(f"ALTER TABLE campaign_contacts ADD COLUMN {name} {ddl}")

NAV_ITEMS = [
    ("dashboard", "/", "Дашборд"),
    ("campaigns", "/campaigns", "Кампании"),
    ("recon", "/recon", "Разведка"),
    ("contacts", "/contacts", "Контакты"),
    ("landings", "/landings", "Лендинг-страницы"),
    ("mail_templates", "/mail_templates", "Шаблоны писем"),
    ("settings", "/settings", "Настройки"),
]

# 1x1 прозрачный GIF для трекинга открытий
PIXEL_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def render(request: Request, template: str, **ctx):
    flash = request.query_params.get("flash", "")
    ctx.setdefault("active", "")
    ctx["nav"] = NAV_ITEMS
    ctx["flash"] = flash
    return templates.TemplateResponse(request, template, ctx)


@app.middleware("http")
async def panel_auth(request: Request, call_next):
    path = request.url.path
    if path in ("/setup", "/login", "/static") or path.startswith(("/static/", "/landing/", "/track/")):
        return await call_next(request)

    db = SessionLocal()
    try:
        username = get_setting(db, "panel_username", "")
        password_hash = get_setting(db, "panel_password_hash", "")
    finally:
        db.close()

    if not username or not password_hash:
        if path != "/setup":
            return RedirectResponse("/setup", status_code=302)
        return await call_next(request)
    if not request.session.get("panel_authenticated"):
        if path != "/login":
            return RedirectResponse("/login", status_code=302)
    return await call_next(request)


app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("ARM_SESSION_SECRET", os.urandom(32).hex()),
    same_site="lax",
)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 100_000
        )
        return hmac.compare_digest(digest.hex(), digest_hex.lower())
    except (ValueError, AttributeError, TypeError):
        return False


def get_setting(db: Session, key: str, default: str = "") -> str:
    item = db.get(Setting, key)
    return item.value if item and item.value else default


def set_setting(db: Session, key: str, value: str) -> None:
    item = db.get(Setting, key)
    if not item:
        item = Setting(key=key)
        db.add(item)
    item.value = value


def is_stand_host(host: str) -> bool:
    """Проверка формата хоста; доменные ограничения сняты."""
    host = (host or "").strip().lower().rstrip(".")
    return bool(re.fullmatch(r"[a-z0-9.\-:\[\]]+", host))


def require_stand_url(url: str) -> None:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    if parsed.scheme not in {"http", "https"} or not is_stand_host(parsed.hostname or ""):
        raise ValueError("Ожидается http/https URL с хостом")


def is_stand_recipient(email: str) -> bool:
    """Проверка формата e-mail; доменные ограничения сняты."""
    return bool(re.fullmatch(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", (email or "").strip()))


def campaign_metrics(db: Session, campaign_id: int) -> dict:
    opens = (
        db.query(func.count(TrackingEvent.id))
        .filter_by(campaign_id=campaign_id, event_type="open")
        .scalar()
    )
    clicks = (
        db.query(func.count(TrackingEvent.id))
        .filter_by(campaign_id=campaign_id, event_type="click")
        .scalar()
    )
    creds = (
        db.query(func.count(CredentialSubmission.id))
        .filter_by(campaign_id=campaign_id)
        .scalar()
    )
    return {"opens": opens or 0, "clicks": clicks or 0, "creds": creds or 0}


@app.get("/setup")
def setup_page(request: Request, db: Session = Depends(get_db)):
    username = get_setting(db, "panel_username", "")
    password_hash = get_setting(db, "panel_password_hash", "")
    if username and password_hash:
        return RedirectResponse("/login", status_code=302)
    return render(request, "auth/setup.html")


@app.post("/setup")
def setup_password(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing_username = get_setting(db, "panel_username", "")
    existing_hash = get_setting(db, "panel_password_hash", "")
    if existing_username and existing_hash:
        return RedirectResponse("/login", status_code=302)
    username = username.strip()
    if not username:
        return RedirectResponse("/setup?flash=Укажите имя пользователя", status_code=302)
    if len(password) < 12:
        return RedirectResponse("/setup?flash=Пароль должен содержать минимум 12 символов", status_code=302)
    set_setting(db, "panel_username", username)
    set_setting(db, "panel_password_hash", hash_password(password))
    db.commit()
    return RedirectResponse("/login", status_code=302)


@app.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    username = get_setting(db, "panel_username", "")
    password_hash = get_setting(db, "panel_password_hash", "")
    if not username or not password_hash:
        return RedirectResponse("/setup", status_code=302)
    flash = request.query_params.get("flash", "")
    return render(request, "auth/login.html", flash=flash)


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    saved_username = get_setting(db, "panel_username", "")
    saved_hash = get_setting(db, "panel_password_hash", "")
    if username.strip() != saved_username or not verify_password(password, saved_hash):
        return RedirectResponse("/login?flash=Неверное имя пользователя или пароль", status_code=302)
    request.session["panel_authenticated"] = True
    return RedirectResponse("/", status_code=302)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=302)


# ---------------------------------------------------------------- дашборд

@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    stats = {
        "campaigns": db.query(func.count(Campaign.id)).scalar() or 0,
        "contacts": db.query(func.count(Contact.id)).scalar() or 0,
        "landings": db.query(func.count(LandingPage.id)).filter_by(status="ready").scalar() or 0,
        "opens": db.query(func.count(TrackingEvent.id)).filter_by(event_type="open").scalar() or 0,
        "clicks": db.query(func.count(TrackingEvent.id)).filter_by(event_type="click").scalar() or 0,
        "creds": db.query(func.count(CredentialSubmission.id)).scalar() or 0,
    }
    recent = (
        db.query(Campaign).order_by(Campaign.created_at.desc()).limit(5).all()
    )
    for c in recent:
        c.metrics = campaign_metrics(db, c.id)  # type: ignore[attr-defined]
    return render(request, "dashboard.html", stats=stats, recent=recent)


# ---------------------------------------------------------------- кампании

@app.get("/campaigns")
def campaigns_list(request: Request, db: Session = Depends(get_db)):
    items = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    for c in items:
        c.metrics = campaign_metrics(db, c.id)  # type: ignore[attr-defined]
    return render(request, "campaigns/list.html", active="campaigns", items=items)


@app.get("/campaigns/new")
def campaigns_new(request: Request):
    landings = db_query_landings()
    templates_list = db_query_templates()
    return render(
        request,
        "campaigns/create.html",
        active="campaigns",
        landings=landings,
        templates_list=templates_list,
    )


def db_query_landings():
    from .db import SessionLocal

    db = SessionLocal()
    try:
        return db.query(LandingPage).filter_by(status="ready").all()
    finally:
        db.close()


def db_query_templates():
    from .db import SessionLocal

    db = SessionLocal()
    try:
        return db.query(EmailTemplate).order_by(EmailTemplate.created_at.desc()).all()
    finally:
        db.close()


@app.post("/campaigns/new")
def campaigns_create(
    name: str = Form(...),
    sender_name: str = Form(""),
    sender_email: str = Form(""),
    subject: str = Form(""),
    body_html: str = Form(""),
    landing_page_id: int | None = Form(None),
    db: Session = Depends(get_db),
):
    if sender_email and not is_stand_recipient(sender_email.strip().lower()):
        return RedirectResponse("/campaigns/new?flash=Некорректный адрес отправителя", status_code=302)
    c = Campaign(
        name=name,
        sender_name=sender_name,
        sender_email=sender_email,
        subject=subject,
        body_html=body_html,
        landing_page_id=landing_page_id or None,
    )
    db.add(c)
    db.commit()
    return RedirectResponse(f"/campaigns/{c.id}?flash=Кампания создана", status_code=302)


@app.get("/campaigns/{cid}")
def campaign_detail(request: Request, cid: int, db: Session = Depends(get_db)):
    c = db.get(Campaign, cid)
    if not c:
        return RedirectResponse("/", status_code=302)
    metrics = campaign_metrics(db, cid)
    rows = []
    for cc in c.contacts:
        contact = cc.contact
        opens = (
            db.query(func.count(TrackingEvent.id))
            .filter_by(campaign_id=cid, contact_email=contact.email, event_type="open")
            .scalar()
        ) or 0
        clicks = (
            db.query(func.count(TrackingEvent.id))
            .filter_by(campaign_id=cid, contact_email=contact.email, event_type="click")
            .scalar()
        ) or 0
        rows.append({
            "contact": contact,
            "opens": opens,
            "clicks": clicks,
            "delivery_status": cc.delivery_status or "pending",
            "delivery_error": cc.delivery_error or "",
            "imap_location": cc.imap_location or "not_checked",
            "imap_error": cc.imap_error or "",
        })
    creds = (
        db.query(CredentialSubmission)
        .filter_by(campaign_id=cid)
        .order_by(CredentialSubmission.created_at.desc())
        .all()
    )
    landing = None
    if c.landing_page_id:
        landing = db.get(LandingPage, c.landing_page_id)
    return render(
        request,
        "campaigns/detail.html",
        active="campaigns",
        campaign=c,
        metrics=metrics,
        rows=rows,
        creds=creds,
        landing=landing,
    )


@app.post("/campaigns/{cid}/add_contacts")
def campaign_add_contacts(
    cid: int, emails: str = Form(""), db: Session = Depends(get_db)
):
    added = 0
    for raw in re.split(r"[,\s]+", emails.strip()):
        email = raw.lower().strip()
        if not re.fullmatch(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", email):
            continue
        if not is_stand_recipient(email):
            continue
        contact = db.query(Contact).filter_by(email=email).first()
        if not contact:
            contact = Contact(email=email)
            db.add(contact)
            db.flush()
        exists = (
            db.query(CampaignContact)
            .filter_by(campaign_id=cid, contact_id=contact.id)
            .first()
        )
        if not exists:
            db.add(CampaignContact(campaign_id=cid, contact_id=contact.id))
            added += 1
    db.commit()
    return RedirectResponse(f"/campaigns/{cid}?flash=Добавлено получателей: {added}", status_code=302)


@app.post("/campaigns/{cid}/status")
def campaign_status(cid: int, status: str = Form("draft"), db: Session = Depends(get_db)):
    c = db.get(Campaign, cid)
    if c and status in ("draft", "active", "done"):
        c.status = status
        db.commit()
    return RedirectResponse(f"/campaigns/{cid}?flash=Статус обновлён", status_code=302)


@app.delete("/campaigns/{cid}/contacts/{contact_id}")
def campaign_remove_contact_delete(cid: int, contact_id: int, db: Session = Depends(get_db)):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return JSONResponse({"detail": "Кампания не найдена"}, status_code=404)
    link = (
        db.query(CampaignContact)
        .filter_by(campaign_id=cid, contact_id=contact_id)
        .first()
    )
    if not link:
        return JSONResponse({"detail": "Контакт в кампании не найден"}, status_code=404)
    db.delete(link)
    db.commit()
    return JSONResponse({"detail": "Контакт удалён из кампании", "campaign_id": cid, "contact_id": contact_id})


@app.post("/campaigns/{cid}/contacts/{contact_id}/delete")
def campaign_remove_contact_post(cid: int, contact_id: int, db: Session = Depends(get_db)):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return RedirectResponse("/campaigns?flash=Кампания не найдена", status_code=302)
    link = (
        db.query(CampaignContact)
        .filter_by(campaign_id=cid, contact_id=contact_id)
        .first()
    )
    if not link:
        return RedirectResponse(f"/campaigns/{cid}?flash=Контакт в кампании не найден", status_code=302)
    db.delete(link)
    db.commit()
    return RedirectResponse(f"/campaigns/{cid}?flash=Контакт удалён из кампании", status_code=302)


@app.delete("/campaigns/{cid}")
def campaign_delete(cid: int, db: Session = Depends(get_db)):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return JSONResponse({"detail": "Кампания не найдена"}, status_code=404)
    db.query(CampaignContact).filter_by(campaign_id=cid).delete(synchronize_session=False)
    db.query(CredentialSubmission).filter_by(campaign_id=cid).delete(synchronize_session=False)
    db.query(TrackingEvent).filter_by(campaign_id=cid).delete(synchronize_session=False)
    db.delete(campaign)
    db.commit()
    return JSONResponse({"detail": "Кампания удалена", "id": cid})


@app.post("/campaigns/{cid}/delete")
def campaign_delete_post(cid: int, db: Session = Depends(get_db)):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return RedirectResponse("/campaigns?flash=Кампания не найдена", status_code=302)
    db.query(CampaignContact).filter_by(campaign_id=cid).delete(synchronize_session=False)
    db.query(CredentialSubmission).filter_by(campaign_id=cid).delete(synchronize_session=False)
    db.query(TrackingEvent).filter_by(campaign_id=cid).delete(synchronize_session=False)
    db.delete(campaign)
    db.commit()
    return RedirectResponse("/campaigns?flash=Кампания удалена", status_code=302)


# ---------------------------------------------------------------- контакты

@app.get("/contacts")
def contacts_index(request: Request, q: str = "", db: Session = Depends(get_db)):
    query = db.query(Contact)
    if q:
        like = f"%{q}%"
        query = query.filter((Contact.email.ilike(like)) | (Contact.name.ilike(like)))
    items = query.order_by(Contact.created_at.desc()).all()
    return render(request, "contacts/index.html", active="contacts", items=items, q=q)


@app.post("/contacts/add")
def contacts_add(
    email: str = Form(""),
    name: str = Form(""),
    found_url: str = Form(""),
    source: str = Form("manual"),
    emails_bulk: str = Form(""),
    db: Session = Depends(get_db),
):
    added, skipped = 0, 0
    if emails_bulk.strip():
        for line in emails_bulk.splitlines():
            email = line.lower().strip()
            if not re.fullmatch(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", email):
                continue
            if not is_stand_recipient(email):
                skipped += 1
                continue
            exists = db.query(Contact).filter_by(email=email).first()
            if exists:
                skipped += 1
                continue
            db.add(Contact(email=email, source=source))
            added += 1
    elif email.strip():
        email = email.lower().strip()
        if not is_stand_recipient(email):
            return RedirectResponse("/contacts?flash=Некорректный адрес e-mail", status_code=302)
        exists = db.query(Contact).filter_by(email=email).first()
        if not exists:
            db.add(
                Contact(
                    email=email,
                    name=name,
                    found_url=found_url,
                    source=source,
                )
            )
            added += 1
        else:
            skipped += 1
    db.commit()
    msg = f"Добавлено: {added}" + (f", уже были: {skipped}" if skipped else "")
    return RedirectResponse(f"/contacts?flash={msg}", status_code=302)


@app.post("/contacts/delete")
def contacts_delete(id: int = Form(...), db: Session = Depends(get_db)):
    contact = db.get(Contact, id)
    if not contact:
        return RedirectResponse("/contacts?flash=Контакт не найден", status_code=302)
    db.query(CampaignContact).filter_by(contact_id=id).delete(synchronize_session=False)
    db.delete(contact)
    db.commit()
    return RedirectResponse("/contacts?flash=Контакт удалён", status_code=302)


@app.post("/contacts/{id}/delete")
def contact_delete_post(id: int, db: Session = Depends(get_db)):
    return contacts_delete(id=id, db=db)


@app.delete("/contacts/{id}")
def contact_delete(id: int, db: Session = Depends(get_db)):
    contact = db.get(Contact, id)
    if not contact:
        return JSONResponse({"detail": "Контакт не найден"}, status_code=404)
    db.query(CampaignContact).filter_by(contact_id=id).delete(synchronize_session=False)
    db.delete(contact)
    db.commit()
    return JSONResponse({"detail": "Контакт удалён", "id": id})


# ---------------------------------------------------------------- разведка

# Запуски crawler'а идут в фоновом потоке; состояние хранится в памяти процесса.
_RECON_JOBS: dict[str, dict] = {}
_RECON_LOCK = threading.Lock()


def _recon_worker(
    run_id: str,
    domain: str,
    max_pages: int,
    max_depth: int,
    retries: int,
    cross_domain: bool,
    cross_confirm: str,
) -> None:
    """Фоновый запуск email-crawler; прогресс пишется в _RECON_JOBS."""

    def on_progress(pages_done: int, last_url: str = "") -> None:
        with _RECON_LOCK:
            job = _RECON_JOBS.get(run_id)
            if job is not None:
                job["pages_done"] = pages_done
                if last_url:
                    job["last_url"] = last_url

    try:
        results, pages, status_info = run_recon(
            domain,
            max_pages=max_pages,
            max_depth=max_depth,
            retries=retries,
            include_status=True,
            cross_domain=cross_domain,
            cross_confirm=cross_confirm,
            on_progress=on_progress,
        )
    except (ValueError, RuntimeError) as exc:
        # ValueError — неверный ввод; RuntimeError — сбой запуска crawler'а
        with _RECON_LOCK:
            job = _RECON_JOBS.get(run_id)
            if job is not None:
                job["status"] = "error"
                job["error"] = str(exc)
        return
    with _RECON_LOCK:
        job = _RECON_JOBS.get(run_id)
        if job is not None:
            job.update(
                status="done",
                results=results,
                pages=pages,
                status_info=status_info,
                pages_done=max_pages,
            )


@app.get("/recon")
def recon_index(request: Request, domain: str = ""):
    with _RECON_LOCK:
        active_id, active_job = next(
            ((k, v) for k, v in _RECON_JOBS.items() if v["status"] == "running"),
            (None, None),
        )
        if active_job is not None:
            return render(
                request,
                "recon/index.html",
                active="recon",
                domain=domain,
                results=None,
                pages=0,
                status=None,
                job={"run_id": active_id, "max_pages": active_job["max_pages"]},
            )
        last_done = next(
            (v for v in reversed(list(_RECON_JOBS.values())) if v["status"] == "done"),
            None,
        )
    if last_done is not None:
        return render(
            request,
            "recon/index.html",
            active="recon",
            domain=last_done["domain"],
            results=last_done["results"],
            pages=last_done["pages"],
            status=last_done["status_info"],
        )
    return render(
        request,
        "recon/index.html",
        active="recon",
        domain=domain,
        results=None,
        pages=0,
        status=None,
        job=None,
    )


@app.post("/recon")
def recon_run(
    request: Request,
    domain: str = Form(...),
    max_pages: int = Form(40),
    max_depth: int = Form(3),
    retries: int = Form(1),
    cross_domain: bool = Form(False),
    cross_confirm: str = Form(""),
):
    run_id = uuid.uuid4().hex[:12]
    safe_max_pages = max(1, min(int(max_pages), 100))
    with _RECON_LOCK:
        if len(_RECON_JOBS) >= 20:  # не раздуваем память старыми запусками
            _RECON_JOBS.pop(next(iter(_RECON_JOBS)))
        _RECON_JOBS[run_id] = {
            "status": "running",
            "domain": domain,
            "max_pages": safe_max_pages,
            "pages_done": 0,
            "last_url": "",
            "results": None,
            "pages": 0,
            "status_info": None,
            "error": "",
        }
    threading.Thread(
        target=_recon_worker,
        args=(run_id, domain.strip(), max_pages, max_depth, retries, cross_domain, cross_confirm),
        daemon=True,
    ).start()
    return render(
        request,
        "recon/index.html",
        active="recon",
        domain=domain,
        results=None,
        pages=0,
        status=None,
        job={"run_id": run_id, "max_pages": safe_max_pages},
    )


@app.get("/recon/progress/{run_id}")
def recon_progress(run_id: str):
    with _RECON_LOCK:
        job = _RECON_JOBS.get(run_id)
        payload = (
            {k: job[k] for k in ("status", "pages_done", "max_pages", "last_url", "error")}
            if job is not None
            else None
        )
    if payload is None:
        return JSONResponse({"status": "missing"}, status_code=404)
    return JSONResponse(payload)


@app.get("/recon/run/{run_id}")
def recon_run_page(request: Request, run_id: str):
    with _RECON_LOCK:
        job = dict(_RECON_JOBS[run_id]) if run_id in _RECON_JOBS else None
    if not job or job["status"] != "done":
        return RedirectResponse("/recon", status_code=302)
    return render(
        request,
        "recon/index.html",
        active="recon",
        domain=job["domain"],
        results=job["results"],
        pages=job["pages"],
        status=job["status_info"],
    )


@app.get("/recon/export/{run_id}.csv")
def recon_export(run_id: str):
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{8}", run_id):
        return Response(status_code=404)
    csv_path = DATA_DIR / "recon" / f"{run_id}.csv"
    if not csv_path.exists():
        return Response(status_code=404)
    return FileResponse(csv_path, media_type="text/csv", filename=f"{run_id}.csv")


@app.post("/recon/add_all")
def recon_add_all(items: str = Form(""), db: Session = Depends(get_db)):
    """Массовое добавление найденных адресов (JSON-список {email, name, url})."""
    try:
        rows = json.loads(items) if items else []
    except ValueError:
        rows = []
    added = 0
    for row in rows:
        email = (row.get("email") or "").lower().strip()
        if not is_stand_recipient(email):
            continue
        exists = db.query(Contact).filter_by(email=email).first()
        if not exists:
            db.add(
                Contact(
                    email=email,
                    name=(row.get("name") or "").strip(),
                    found_url=(row.get("url") or "").strip(),
                    source="recon",
                )
            )
            added += 1
    db.commit()
    return RedirectResponse(f"/contacts?flash=Из разведки добавлено: {added}", status_code=302)


# ---------------------------------------------------------------- лендинги

@app.get("/landings")
def landings_index(request: Request, url: str = "", name: str = "", db: Session = Depends(get_db)):
    items = db.query(LandingPage).order_by(LandingPage.created_at.desc()).all()
    archives = db.query(ArchiveJob).order_by(ArchiveJob.created_at.desc()).all()
    return render(
        request,
        "landings/index.html",
        active="landings",
        items=items,
        archives=archives,
        url=url,
        name=name,
    )


def normalize_source_url(url: str) -> str:
    """Дополняет схему для URL без неё (pro.guap.ru → https://pro.guap.ru)."""
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


@app.post("/landings/clone")
def landings_clone(url: str = Form(...), name: str = Form(""), render_js: bool = Form(False), db: Session = Depends(get_db)):
    url = normalize_source_url(url)
    lp = LandingPage(name=name or url, source_url=url, status="pending")
    db.add(lp)
    db.commit()
    dest = DATA_DIR / "clones" / f"{lp.id}"
    try:
        info = clone_site(url, dest, render_js=render_js)
        lp.storage_path = f"clones/{lp.id}"
        lp.status = "ready"
        lp.note = info.get("note", "")
        flash = f"Клон готов: {url} ({info.get('pages', 0)} страниц)"
    except Exception as e:  # noqa: BLE001 — показываем ошибку в панели
        lp.status = "error"
        lp.note = str(e)
        flash = f"Ошибка клонирования: {e}"
    db.commit()
    return RedirectResponse(f"/landings?flash={flash}", status_code=302)


@app.post("/landings/archive")
def landings_archive(
    url: str = Form(...),
    name: str = Form(""),
    mode: str = Form("monolith"),
    depth: int = Form(1),
    page_limit: int = Form(10),
    timeout_seconds: int = Form(6),
    max_bytes: int = Form(5_000_000),
    db: Session = Depends(get_db),
):
    url = normalize_source_url(url)
    job = ArchiveJob(
        name=name or url,
        source_url=url,
        mode={"monolith": "static", "playwright": "js"}.get(mode, mode)
        if {"monolith": "static", "playwright": "js"}.get(mode, mode) in {"static", "js"}
        else "static",
        depth=max(0, min(depth, 5)),
        page_limit=max(1, min(page_limit, 50)),
        timeout_seconds=max(1, min(timeout_seconds, 30)),
        max_bytes=max(100_000, min(max_bytes, 50_000_000)),
        status="pending",
    )
    db.add(job)
    db.commit()
    dest = DATA_DIR / "archives" / str(job.id)
    try:
        info = archive_mirror(
            url,
            dest,
            depth=job.depth,
            page_limit=job.page_limit,
            timeout=job.timeout_seconds,
            max_bytes=job.max_bytes,
            mode=job.mode,
        )
        job.status = "ready"
        job.storage_path = f"archives/{job.id}"
        job.note = f"{info['pages']} страниц, {info['assets']} ассетов"
    except Exception as exc:
        job.status = "error"
        job.note = str(exc)
    db.commit()
    return RedirectResponse(f"/landings?flash=Архив: {job.status}", status_code=302)


@app.delete("/landings/{lid}")
def landing_delete(lid: int, db: Session = Depends(get_db)):
    lp = db.get(LandingPage, lid)
    if not lp:
        return JSONResponse({"detail": "Лендинг не найден"}, status_code=404)
    db.query(Campaign).filter_by(landing_page_id=lid).update({"landing_page_id": None}, synchronize_session=False)
    db.query(CredentialSubmission).filter_by(landing_page_id=lid).delete(synchronize_session=False)
    if lp.storage_path:
        storage = DATA_DIR / lp.storage_path
        if storage.exists():
            if storage.is_dir():
                shutil.rmtree(storage)
            else:
                storage.unlink()
    db.delete(lp)
    db.commit()
    return JSONResponse({"detail": "Лендинг удалён", "id": lid})


@app.post("/landings/{lid}/delete")
def landing_delete_post(lid: int, db: Session = Depends(get_db)):
    lp = db.get(LandingPage, lid)
    if not lp:
        return RedirectResponse("/landings?flash=Лендинг не найден", status_code=302)
    db.query(Campaign).filter_by(landing_page_id=lid).update({"landing_page_id": None}, synchronize_session=False)
    db.query(CredentialSubmission).filter_by(landing_page_id=lid).delete(synchronize_session=False)
    if lp.storage_path:
        storage = DATA_DIR / lp.storage_path
        if storage.exists():
            if storage.is_dir():
                shutil.rmtree(storage)
            else:
                storage.unlink()
    db.delete(lp)
    db.commit()
    return RedirectResponse("/landings?flash=Лендинг удалён", status_code=302)


@app.post("/landings/delete")
def landing_delete_form(id: int = Form(...), db: Session = Depends(get_db)):
    return landing_delete_post(lid=id, db=db)


@app.delete("/landings/archive/{aid}")
def archive_delete(aid: int, db: Session = Depends(get_db)):
    job = db.get(ArchiveJob, aid)
    if not job:
        return JSONResponse({"detail": "Архив не найден"}, status_code=404)
    if job.storage_path:
        storage = DATA_DIR / job.storage_path
        if storage.exists():
            shutil.rmtree(storage) if storage.is_dir() else storage.unlink()
    db.delete(job)
    db.commit()
    return JSONResponse({"detail": "Архив удалён", "id": aid})


@app.post("/landings/archive/{aid}/delete")
def archive_delete_post(aid: int, db: Session = Depends(get_db)):
    job = db.get(ArchiveJob, aid)
    if not job:
        return RedirectResponse("/landings?flash=Архив не найден", status_code=302)
    if job.storage_path:
        storage = DATA_DIR / job.storage_path
        if storage.exists():
            shutil.rmtree(storage) if storage.is_dir() else storage.unlink()
    db.delete(job)
    db.commit()
    return RedirectResponse("/landings?flash=Архив удалён", status_code=302)


@app.get("/landings/archive/{aid}")
def archive_view(aid: int, db: Session = Depends(get_db)):
    job = db.get(ArchiveJob, aid)
    if not job or job.status != "ready":
        return HTMLResponse("<h3>Архив не готов</h3>", status_code=404)
    base = DATA_DIR / job.storage_path
    entry = entry_rel_path(job.source_url)
    if not (base / entry).exists() and (base / "index.html").exists():
        return RedirectResponse(f"/landings/archive/{aid}/", status_code=307)
    if entry.endswith("index.html"):
        parent = entry.rsplit("/", 1)[0] + "/" if "/" in entry else ""
        return RedirectResponse(f"/landings/archive/{aid}/{parent}", status_code=307)
    return RedirectResponse(f"/landings/archive/{aid}/{entry}", status_code=307)


@app.get("/landings/archive/{aid}/download")
def archive_download(aid: int, db: Session = Depends(get_db)):
    job = db.get(ArchiveJob, aid)
    if not job or job.status != "ready":
        return Response(status_code=404)
    source = DATA_DIR / job.storage_path
    zip_path = DATA_DIR / f"archive-{aid}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in source.rglob("*"):
            if file.is_file():
                archive.write(file, file.relative_to(source).as_posix())
    return FileResponse(zip_path, media_type="application/zip", filename=f"archive-{aid}.zip")


@app.get("/landing/{lid}")
def landing_serve(lid: int, db: Session = Depends(get_db)):
    lp = db.get(LandingPage, lid)
    if not lp or lp.status != "ready":
        return HTMLResponse("<h3>Лендинг не готов</h3>", status_code=404)
    base = DATA_DIR / lp.storage_path
    entry = entry_rel_path(lp.source_url)
    if not (base / entry).exists() and (base / "index.html").exists():
        # старые одностраничные клоны: единственный файл лежит в корне зеркала
        return RedirectResponse(f"/landing/{lid}/", status_code=307)
    if entry.endswith("index.html"):
        parent = entry.rsplit("/", 1)[0] + "/" if "/" in entry else ""
        return RedirectResponse(f"/landing/{lid}/{parent}", status_code=307)
    return RedirectResponse(f"/landing/{lid}/{entry}", status_code=307)


@app.get("/landing/{lid}/assets/{filename}")
def landing_asset(lid: int, filename: str, db: Session = Depends(get_db)):
    lp = db.get(LandingPage, lid)
    if not lp or ".." in filename or "/" in filename:
        return Response(status_code=404)
    path = DATA_DIR / lp.storage_path / "assets" / filename
    if not path.exists():
        return Response(status_code=404)
    return FileResponse(path, media_type=media_type_for(path))


@app.post("/landing/{lid}/login")
async def landing_login(request: Request, lid: int, db: Session = Depends(get_db)):
    lp = db.get(LandingPage, lid)
    if not lp:
        return HTMLResponse("<h3>Страница не найдена</h3>", status_code=404)
    try:
        data = await request.json()
    except json.JSONDecodeError:
        data = {}

    login, password = "", ""
    for k, v in data.items():
        kl = str(k).lower()
        if "pass" in kl and not password:
            password = str(v)
        elif any(s in kl for s in ("email", "mail", "user", "login")) and not login:
            login = str(v)

    campaign_id, contact_email = None, ""
    token = data.get("__token__", "") or request.cookies.get("ptoken", "")
    if ":" in str(token):
        cid_part, email_part = str(token).split(":", 1)
        email_part = unquote(email_part)
        if cid_part.isdigit():
            campaign_id = int(cid_part)
        contact_email = email_part

    if login and "@" in login and not is_stand_recipient(login):
        login = ""
    if login and "@" not in login:
        login = login if login.lower().startswith("test") else ""

    db.add(
        CredentialSubmission(
            landing_page_id=lp.id,
            campaign_id=campaign_id,
            contact_email=contact_email or login,
            login=login,
            password_hash=hash_password(password) if password else "",
            ip=request.client.host if request.client else "",
        )
    )
    db.commit()
    return HTMLResponse(
        """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Проверка</title></head>
<body style="font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f6fa">
<div style="text-align:center"><div style="font-size:48px">⏳</div>
<h2>Проверяем данные…</h2><p>Пожалуйста, не закрывайте страницу.</p></div></body></html>"""
    )


@app.get("/landing/{lid}/event")
def landing_event(lid: int, request: Request, type: str = "click", to: str = "", db: Session = Depends(get_db)):
    campaign_id, contact_email = None, ""
    token = request.cookies.get("ptoken", "")
    if ":" in token:
        cid_part, email_part = token.split(":", 1)
        from urllib.parse import unquote

        email_part = unquote(email_part)
        if cid_part.isdigit():
            campaign_id = int(cid_part)
        contact_email = email_part
    db.add(
        TrackingEvent(
            campaign_id=campaign_id,
            contact_email=contact_email,
            event_type="click",
            url=to,
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", "")[:500],
        )
    )
    db.commit()
    return Response(status_code=204)


MIRROR_404_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Страница не найдена</title></head>
<body style="font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f6fa;color:#333">
<div style="text-align:center">
<h2>Страница не найдена</h2><p>Страница отсутствует в копии сайта.</p></div></body></html>"""


def serve_mirror_file(base_dir: Path, rel_path: str):
    """FileResponse для файла зеркала по относительному пути либо None."""
    base_dir = base_dir.resolve()
    rel = (rel_path or "").strip("/")
    candidates = []
    if rel:
        candidates.append(rel)
        if not Path(rel).suffix:
            candidates.append(f"{rel}/index.html")
    else:
        candidates.append("index.html")
    for cand in candidates:
        file_path = (base_dir / cand).resolve()
        try:
            file_path.relative_to(base_dir)
        except ValueError:
            continue  # выход за пределы зеркала через ..
        if file_path.is_file():
            return FileResponse(file_path, media_type=media_type_for(file_path))
    return None


@app.get("/landing/{lid}/{path:path}")
def landing_subpage(lid: int, path: str, db: Session = Depends(get_db)):
    lp = db.get(LandingPage, lid)
    if not lp or lp.status != "ready":
        return HTMLResponse("<h3>Лендинг не готов</h3>", status_code=404)
    response = serve_mirror_file(DATA_DIR / lp.storage_path, path)
    if response is None:
        return HTMLResponse(MIRROR_404_PAGE, status_code=404)
    return response


@app.get("/landings/archive/{aid}/{path:path}")
def archive_subpage(aid: int, path: str, db: Session = Depends(get_db)):
    job = db.get(ArchiveJob, aid)
    if not job or job.status != "ready":
        return HTMLResponse("<h3>Архив не готов</h3>", status_code=404)
    response = serve_mirror_file(DATA_DIR / job.storage_path, path)
    if response is None:
        return HTMLResponse(MIRROR_404_PAGE, status_code=404)
    return response


# ---------------------------------------------------------------- шаблоны писем

@app.get("/mail_templates")
def mail_templates_index(request: Request, name: str = "", subject: str = "", body_html: str = "", db: Session = Depends(get_db)):
    items = db.query(EmailTemplate).order_by(EmailTemplate.created_at.desc()).all()
    return render(
        request,
        "mail_templates/index.html",
        active="mail_templates",
        items=items,
        name=name,
        subject=subject,
        body_html=body_html,
    )


@app.post("/mail_templates/new")
def mail_templates_create(
    name: str = Form(...), subject: str = Form(""), body_html: str = Form("")
):
    from .db import SessionLocal

    db = SessionLocal()
    try:
        db.add(EmailTemplate(name=name, subject=subject, body_html=body_html))
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/mail_templates?flash=Шаблон сохранён", status_code=302)


@app.post("/mail_templates/delete")
def mail_templates_delete(id: int = Form(...)):
    from .db import SessionLocal

    db = SessionLocal()
    try:
        t = db.get(EmailTemplate, id)
        if t:
            db.delete(t)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/mail_templates?flash=Шаблон удалён", status_code=302)


# ---------------------------------------------------------------- настройки

SETTING_KEYS = [
    ("attacker_smtp_host", "SMTP сервер атакующего (host)", "127.0.0.1"),
    ("attacker_smtp_port", "SMTP порт", "1025"),
    ("smtp_security", "SMTP защита (none/starttls/ssl)", "none"),
    ("smtp_username", "SMTP имя пользователя", ""),
    ("smtp_from", "Адрес From", ""),
    ("victim_imap_host", "IMAP сервер жертвы (host)", "127.0.0.1"),
    ("victim_imap_port", "IMAP порт", "1143"),
    ("imap_security", "IMAP защита (none/ssl)", "none"),
    ("imap_username", "IMAP имя пользователя", ""),
    ("track_base_url", "Базовый URL панели", "http://127.0.0.1:8000"),
    ("lookalike_domains", "Lookalike-домены (.test через запятую)", ""),
]


@app.get("/settings")
def settings_index(request: Request, db: Session = Depends(get_db)):
    values = {s.key: s.value for s in db.query(Setting).all()}
    fields = [(k, label, values.get(k, default)) for k, label, default in SETTING_KEYS]
    return render(request, "settings/index.html", active="settings", fields=fields)


@app.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    for key, _, _ in SETTING_KEYS:
        value = str(form.get(key, "")).strip()
        if key in {"attacker_smtp_host", "victim_imap_host"} and value and not is_stand_host(value):
            return RedirectResponse("/settings?flash=Некорректный SMTP/IMAP-хост", status_code=302)
        if key in {"attacker_smtp_port", "victim_imap_port"} and value:
            try:
                port = int(value)
            except ValueError:
                return RedirectResponse("/settings?flash=Некорректный порт SMTP/IMAP", status_code=302)
            if not 1 <= port <= 65535:
                return RedirectResponse("/settings?flash=Некорректный порт SMTP/IMAP", status_code=302)
        if key == "track_base_url" and value:
            try:
                require_stand_url(value)
            except ValueError as exc:
                return RedirectResponse(f"/settings?flash={exc}", status_code=302)
        s = db.get(Setting, key)
        if not s:
            s = Setting(key=key)
            db.add(s)
        s.value = value
    db.commit()
    return RedirectResponse("/settings?flash=Настройки сохранены", status_code=302)


def smtp_connection(db: Session, password: str):
    host = get_setting(db, "attacker_smtp_host", "127.0.0.1")
    port = int(get_setting(db, "attacker_smtp_port", "1025"))
    security = get_setting(db, "smtp_security", "none")
    if not is_stand_host(host):
        raise ValueError("Некорректный SMTP-хост")
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        server = smtplib.SMTP(host, port, timeout=10)
    server.ehlo()
    if security == "starttls":
        server.starttls()
        server.ehlo()
    username = get_setting(db, "smtp_username", "")
    if username:
        server.login(username, password)
    return server


@app.post("/settings/smtp_test")
def smtp_test(
    recipient: str = Form(...),
    password: str = Form(""),
    db: Session = Depends(get_db),
):
    recipient = recipient.strip().lower()
    if not is_stand_recipient(recipient):
        return RedirectResponse("/settings?flash=Некорректный адрес получателя", status_code=302)
    set_setting(db, "smtp_test_secret_hash", hash_password(password) if password else "")
    set_setting(db, "smtp_test_secret_meta", "тестовый SMTP-пароль принят" if password else "пароль не указан")
    db.commit()
    try:
        server = smtp_connection(db, password)
        server.noop()
        server.quit()
        return RedirectResponse("/settings?flash=SMTP-подключение успешно", status_code=302)
    except Exception as exc:
        return RedirectResponse(f"/settings?flash=SMTP ошибка: {exc}", status_code=302)


@app.post("/campaigns/{cid}/send")
def campaign_send(
    cid: int,
    password: str = Form(""),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return RedirectResponse("/campaigns", status_code=302)
    smtp_from = get_setting(db, "smtp_from", "")
    if not smtp_from:
        smtp_from = campaign.sender_email or "noreply@stand.test"
    base_url = get_setting(db, "track_base_url", "http://127.0.0.1:8000").rstrip("/")
    try:
        server = smtp_connection(db, password)
    except Exception as exc:
        for cc in campaign.contacts:
            cc.delivery_status = "failed"
            cc.delivery_error = str(exc)
        db.commit()
        return RedirectResponse(f"/campaigns/{cid}?flash=SMTP ошибка: {exc}", status_code=302)

    sent_count = 0
    for cc in campaign.contacts:
        contact = cc.contact
        link = f"{base_url}/track/click/{cid}/{quote(contact.email.lower())}"
        body = (campaign.body_html or "").replace("{name}", contact.name or "").replace("{link}", link)
        pixel = f'<img src="{base_url}/track/open/{cid}/{quote(contact.email.lower())}" width="1" height="1" alt="">'
        msg = EmailMessage()
        msg["Subject"] = campaign.subject or "Учебное письмо"
        msg["From"] = campaign.sender_name + " <" + smtp_from + ">" if campaign.sender_name else smtp_from
        msg["To"] = contact.email
        msg.set_content(body)
        msg.add_alternative(body + pixel, subtype="html")
        try:
            server.send_message(msg)
            cc.delivery_status = "sent"
            cc.delivery_error = ""
            cc.sent_at = datetime.now()
            sent_count += 1
        except Exception as exc:
            cc.delivery_status = "failed"
            cc.delivery_error = str(exc)
    server.quit()
    db.commit()
    return RedirectResponse(f"/campaigns/{cid}?flash=SMTP отправка завершена: успешно {sent_count}", status_code=302)


@app.post("/settings/imap_test")
def imap_test(
    mailbox: str = Form(...),
    password: str = Form(""),
    db: Session = Depends(get_db),
):
    set_setting(db, "imap_test_secret_hash", hash_password(password) if password else "")
    set_setting(db, "imap_test_secret_meta", "тестовый IMAP-пароль принят" if password else "пароль не указан")
    db.commit()
    host = get_setting(db, "victim_imap_host", "127.0.0.1")
    port = int(get_setting(db, "victim_imap_port", "1143"))
    security = get_setting(db, "imap_security", "none")
    if not is_stand_host(host):
        return RedirectResponse("/settings?flash=Некорректный IMAP-хост", status_code=302)
    try:
        client = imaplib.IMAP4_SSL(host, port, timeout=10) if security == "ssl" else imaplib.IMAP4(host, port, timeout=10)
        client.login(mailbox, password)
        client.logout()
        return RedirectResponse("/settings?flash=IMAP-подключение успешно", status_code=302)
    except Exception as exc:
        return RedirectResponse(f"/settings?flash=IMAP ошибка: {exc}", status_code=302)


@app.post("/campaigns/{cid}/imap_check")
def campaign_imap_check(
    cid: int,
    password: str = Form(""),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return RedirectResponse("/campaigns", status_code=302)
    host = get_setting(db, "victim_imap_host", "127.0.0.1")
    port = int(get_setting(db, "victim_imap_port", "1143"))
    security = get_setting(db, "imap_security", "none")
    username = get_setting(db, "imap_username", "")
    if not is_stand_host(host):
        return RedirectResponse(f"/campaigns/{cid}?flash=Некорректный IMAP-хост", status_code=302)
    try:
        client = imaplib.IMAP4_SSL(host, port, timeout=10) if security == "ssl" else imaplib.IMAP4(host, port, timeout=10)
    except Exception as exc:
        return RedirectResponse(f"/campaigns/{cid}?flash=IMAP ошибка: {exc}", status_code=302)
    checked = 0
    try:
        client.login(username or (campaign.contacts[0].contact.email if campaign.contacts else "test@stand.test"), password)
        for cc in campaign.contacts:
            location = "not_found"
            for folder, label in (("INBOX", "INBOX"), ("JUNK", "JUNK"), ("Spam", "JUNK")):
                typ, _ = client.select(folder, readonly=True)
                if typ != "OK":
                    continue
                typ, ids = client.search(
                    None,
                    "HEADER",
                    "To",
                    cc.contact.email,
                    "SUBJECT",
                    campaign.subject or "",
                )
                if typ == "OK" and ids and ids[0].strip():
                    location = label
                    break
            cc.imap_location = location
            cc.imap_error = ""
            cc.checked_at = datetime.now()
            checked += 1
        client.logout()
    except Exception as exc:
        for cc in campaign.contacts:
            cc.imap_location = "error"
            cc.imap_error = str(exc)
    try:
        client.shutdown()
    except Exception:
        pass
    db.commit()
    return RedirectResponse(f"/campaigns/{cid}?flash=IMAP-проверка завершена: {checked} получателей", status_code=302)


@app.get("/campaigns/{cid}/report.csv")
def campaign_csv_report(cid: int, db: Session = Depends(get_db)):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return RedirectResponse("/campaigns", status_code=302)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["email", "delivery_status", "delivery_error", "imap_location", "imap_error", "sent_at", "checked_at"])
    for cc in campaign.contacts:
        writer.writerow([
            cc.contact.email,
            cc.delivery_status or "pending",
            cc.delivery_error or "",
            cc.imap_location or "not_checked",
            cc.imap_error or "",
            cc.sent_at.isoformat() if cc.sent_at else "",
            cc.checked_at.isoformat() if cc.checked_at else "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue().encode("utf-8-sig")]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="campaign-{cid}-report.csv"'},
    )


@app.get("/campaigns/{cid}/report.pdf")
def campaign_pdf_report(cid: int, db: Session = Depends(get_db)):
    campaign = db.get(Campaign, cid)
    if not campaign:
        return RedirectResponse("/campaigns", status_code=302)

    lines = [f"Campaign: {campaign.name}", ""]
    for cc in campaign.contacts:
        lines.append(
            f"{cc.contact.email}|{cc.delivery_status or 'pending'}|"
            f"{cc.imap_location or 'not_checked'}"
        )

    def pdf_escape(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_lines = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
    for index, line in enumerate(lines[:60]):
        content_lines.append(f"({pdf_escape(line)}) Tj")
        if index + 1 < len(lines[:60]):
            content_lines.append("T*")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", "replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode())
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return Response(
        bytes(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="campaign-{cid}-report.pdf"'},
    )


# ---------------------------------------------------------------- трекинг

@app.get("/track/open/{cid}/{email}")
def track_open(cid: int, email: str, request: Request, db: Session = Depends(get_db)):
    db.add(
        TrackingEvent(
            campaign_id=cid,
            contact_email=email.lower(),
            event_type="open",
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", "")[:500],
        )
    )
    db.commit()
    return Response(content=PIXEL_GIF, media_type="image/gif")


@app.get("/track/click/{cid}/{email}")
def track_click(cid: int, email: str, request: Request, db: Session = Depends(get_db)):
    c = db.get(Campaign, cid)
    target = "/"
    if c and c.landing_page_id:
        target = f"/landing/{c.landing_page_id}"
    db.add(
        TrackingEvent(
            campaign_id=cid,
            contact_email=email.lower(),
            event_type="click",
            url=target,
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", "")[:500],
        )
    )
    db.commit()
    from urllib.parse import quote

    resp = RedirectResponse(target, status_code=302)
    resp.set_cookie("ptoken", f"{cid}:{quote(email.lower())}", max_age=7 * 24 * 3600)
    return resp
