from fastapi.testclient import TestClient

from app.main import app, hash_password, verify_password, smtp_connection
from app.db import SessionLocal
from app.main import get_setting, set_setting
from app.clone import entry_dir, validate_stand_url
import re
import time
from pathlib import Path
from app.recon import extract_emails, run_recon


def test_password_hash_roundtrip():
    stored = hash_password("only-a-test-value")
    assert "$" in stored
    assert verify_password("only-a-test-value", stored)
    assert not verify_password("wrong-value", stored)


def test_mailto_and_obfuscated_email_normalization():
    html = """
    <a href="mailto:alice%40stand.test?subject=Hello">mail</a>
    <p>bob [at] stand [dot] test</p>
    """
    emails = extract_emails(html)
    assert "alice@stand.test" in emails
    assert "bob@stand.test" in emails


def test_recon_requires_host():
    try:
        run_recon("http://", max_pages=1)
    except ValueError as exc:
        assert "URL" in str(exc)
    else:
        raise AssertionError("Hostless recon URL was not blocked")


def test_panel_auth_redirect():
    client = TestClient(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] in ("/setup", "/login")


def test_smtp_connection_stub(monkeypatch):
    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass
        def ehlo(self): return 250
        def noop(self): return (250, b"ok")
        def quit(self): return (221, b"bye")

    monkeypatch.setattr("app.main.smtplib.SMTP", FakeSMTP)
    db = SessionLocal()
    set_setting(db, "attacker_smtp_host", "127.0.0.1")
    set_setting(db, "attacker_smtp_port", "1025")
    set_setting(db, "smtp_security", "none")
    db.commit()
    server = smtp_connection(db, "")
    assert server.noop()[0] == 250
    db.close()


def test_imap_stub(monkeypatch):
    class FakeIMAP:
        def __init__(self, *args, **kwargs): pass
        def login(self, *args): return ("OK", [b"logged in"])
        def logout(self): return ("BYE", [b""])
        def select(self, *args, **kwargs): return ("OK", [b"1"])
        def search(self, *args): return ("OK", [b"1"])

    monkeypatch.setattr("app.main.imaplib.IMAP4", lambda *args, **kwargs: FakeIMAP())
    db = SessionLocal()
    set_setting(db, "victim_imap_host", "127.0.0.1")
    set_setting(db, "victim_imap_port", "1143")
    set_setting(db, "imap_security", "none")
    db.commit()
    client = __import__("imaplib").IMAP4("127.0.0.1", 1143)
    assert client.login("tester@stand.test", "test-only")[0] == "OK"
    db.close()


def test_website_downloader_engine():
    from website_downloader.crawler import CrawlOptions, crawl_site

    assert callable(crawl_site) and CrawlOptions is not None
    assert entry_dir("https://example.com/login/") == "login"
    assert entry_dir("https://example.com") == ""


def test_recon_e2e_stubbed_crawler(monkeypatch):
    """Сквозной сценарий: POST /recon → (stub) Node CLI → CSV → рендер → контакты."""
    import app.recon as recon_mod
    from app.models import Contact

    class _Popen:
        def __init__(self, command, **kwargs):
            out = Path(command[command.index("--output") + 1])
            out.write_text(
                "email,sourceURL\nivan.petrov@stand.test,https://stand.test/team\n",
                encoding="utf-8",
            )
            self.stdout = iter([
                "Starting email extraction from: https://stand.test/\n",
                "[CRAWL] Visiting URL (depth 0): https://stand.test/\n",
                "[CRAWL] Found 1 email(s) on https://stand.test/team:\n",
            ])

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(recon_mod.subprocess, "Popen", _Popen)

    class _Resp:
        status_code = 200
        text = "<div>Ivan Petrov, CEO, ivan.petrov@stand.test</div>"

    monkeypatch.setattr(recon_mod.requests, "get", lambda *a, **k: _Resp())

    db = SessionLocal()
    old_user = get_setting(db, "panel_username", "admin")
    old_hash = get_setting(db, "panel_password_hash", "")
    set_setting(db, "panel_username", old_user)
    set_setting(db, "panel_password_hash", hash_password("recon-e2e-pass-1"))
    db.commit()
    try:
        client = TestClient(app)
        client.post("/login", data={"username": old_user, "password": "recon-e2e-pass-1"})

        # первая страница — без преждевременного предупреждения «Почты не найдены»
        r = client.get("/recon")
        assert "Почты не найдены" not in r.text

        r = client.post(
            "/recon",
            data={"domain": "stand.test", "max_pages": 5, "max_depth": 1, "retries": 0},
        )
        assert r.status_code == 200
        match = re.search(r'var runId = "([0-9a-f]+)"', r.text)
        assert match is not None  # прогресс-бар с id запуска отрендерился
        run_id = match.group(1)

        data: dict = {}
        deadline = time.time() + 15
        while time.time() < deadline:
            pr = client.get(f"/recon/progress/{run_id}")
            assert pr.status_code == 200
            data = pr.json()
            if data["status"] in ("done", "error"):
                break
            time.sleep(0.2)
        assert data.get("status") == "done", data

        r = client.get(f"/recon/run/{run_id}")
        assert r.status_code == 200
        assert "ivan.petrov@stand.test" in r.text
        assert "Ivan Petrov" in r.text  # имя подобрано best-effort

        existing = db.query(Contact).filter_by(email="ivan.petrov@stand.test").first()
        if existing:
            db.delete(existing)
            db.commit()
        r = client.post(
            "/recon/add_all",
            data={"items": '[{"email":"ivan.petrov@stand.test","name":"Ivan Petrov","url":"https://stand.test/team"}]'},
            follow_redirects=False,
        )
        assert r.status_code in (302, 307)
        contact = db.query(Contact).filter_by(email="ivan.petrov@stand.test").first()
        assert contact is not None
        assert contact.name == "Ivan Petrov"
        assert contact.found_url == "https://stand.test/team"
    finally:
        set_setting(db, "panel_username", old_user)
        set_setting(db, "panel_password_hash", old_hash)
        db.commit()
        db.close()


def test_external_archive_url_guard():
    assert validate_stand_url("http://lab.test/page")[0] == "lab.test"
    host, port = validate_stand_url("https://example.com/page")
    assert (host, port) == ("example.com", "443")
    try:
        validate_stand_url("ftp://lab.test/file")
    except ValueError:
        pass
    else:
        raise AssertionError("Non-http archive URL was not blocked")


def test_email_crawler_dist_exists():
    dist = Path("data/tools/email-crawler/dist/index.js")
    assert dist.exists()
    assert dist.stat().st_size > 1000


def test_delete_routes_remove_records_and_links():
    from app.models import (
        ArchiveJob,
        Campaign,
        CampaignContact,
        Contact,
        LandingPage,
    )

    db = SessionLocal()
    try:
        campaign = Campaign(name="delete-route-campaign")
        contact = Contact(email="delete-route-contact@stand.test")
        landing = LandingPage(
            name="delete-route-landing",
            source_url="https://stand.test/",
            status="ready",
            storage_path="",
        )
        archive = ArchiveJob(
            name="delete-route-archive",
            source_url="https://stand.test/",
            status="ready",
            storage_path="",
        )
        db.add_all([campaign, contact, landing, archive])
        db.commit()

        db.add(CampaignContact(campaign_id=campaign.id, contact_id=contact.id))
        db.commit()

        campaign_id = campaign.id
        contact_id = contact.id
        landing_id = landing.id
        archive_id = archive.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        old_user = get_setting(db, "panel_username", "admin")
        old_hash = get_setting(db, "panel_password_hash", "")
        set_setting(db, "panel_username", "delete-route-admin")
        set_setting(db, "panel_password_hash", hash_password("delete-route-password"))
        db.commit()
    finally:
        db.close()

    client = TestClient(app)
    login = client.post(
        "/login",
        data={
            "username": "delete-route-admin",
            "password": "delete-route-password",
        },
        follow_redirects=False,
    )
    assert login.status_code in (302, 307)

    assert client.delete(f"/campaigns/{campaign_id}").status_code == 200
    assert client.delete(f"/contacts/{contact_id}").status_code == 200
    assert client.delete(f"/landings/{landing_id}").status_code == 200
    assert client.delete(f"/landings/archive/{archive_id}").status_code == 200

    db = SessionLocal()
    try:
        assert db.get(Campaign, campaign_id) is None
        assert db.get(Contact, contact_id) is None
        assert db.get(LandingPage, landing_id) is None
        assert db.get(ArchiveJob, archive_id) is None
        set_setting(db, "panel_username", old_user)
        set_setting(db, "panel_password_hash", old_hash)
        db.commit()
    finally:
        db.close()
