"""Модели БД."""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .db import Base


class Campaign(Base):
    """Фишинг-кампания."""
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    status = Column(String(50), default="draft")  # draft / active / done
    sender_name = Column(String(200), default="")
    sender_email = Column(String(200), default="")
    subject = Column(String(300), default="")
    body_html = Column(Text, default="")  # плейсхолдеры: {link}, {name}
    landing_page_id = Column(Integer, ForeignKey("landing_pages.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.now)

    contacts = relationship(
        "CampaignContact", back_populates="campaign", cascade="all, delete-orphan"
    )


class Contact(Base):
    """Почтовый адрес «сотрудника» жертвы."""
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(200), default="")
    source = Column(String(50), default="manual")  # manual / recon
    found_url = Column(String(500), default="")
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)


class CampaignContact(Base):
    """Связка «кампания → получатель»."""
    __tablename__ = "campaign_contacts"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    contact_id = Column(Integer, ForeignKey("contacts.id"), nullable=False)
    delivery_status = Column(String(30), default="pending")
    delivery_error = Column(Text, default="")
    imap_location = Column(String(30), default="not_checked")
    imap_error = Column(Text, default="")
    sent_at = Column(DateTime, nullable=True)
    checked_at = Column(DateTime, nullable=True)

    campaign = relationship("Campaign", back_populates="contacts")
    contact = relationship("Contact")


class LandingPage(Base):
    """Клон сайта жертвы (страница-приманка)."""
    __tablename__ = "landing_pages"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), default="")
    source_url = Column(String(500), default="")
    storage_path = Column(String(500), default="")  # относительно data/
    status = Column(String(50), default="pending")  # pending / ready / error
    note = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.now)


class EmailTemplate(Base):
    """Шаблон фишинг-письма."""
    __tablename__ = "email_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    subject = Column(String(300), default="")
    body_html = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.now)


class TrackingEvent(Base):
    """Событие трекинга: open (открытие письма) / click (переход по ссылке)."""
    __tablename__ = "tracking_events"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True, index=True)
    contact_email = Column(String(255), default="", index=True)
    event_type = Column(String(20), nullable=False)  # open / click
    url = Column(String(1000), default="")
    ip = Column(String(64), default="")
    user_agent = Column(String(500), default="")
    created_at = Column(DateTime, default=datetime.now)


class CredentialSubmission(Base):
    """Перехваченные логин/пароль на лендинг-странице."""
    __tablename__ = "credential_submissions"

    id = Column(Integer, primary_key=True)
    landing_page_id = Column(Integer, ForeignKey("landing_pages.id"), nullable=False)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)
    contact_email = Column(String(255), default="")
    login = Column(String(255), default="")
    password_hash = Column(String(200), default="")
    ip = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.now)


class Setting(Base):
    """Настройки приложения (ключ-значение)."""
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, default="")


class ArchiveJob(Base):
    """Безопасная локальная задача архивации стендового сайта."""
    __tablename__ = "archive_jobs"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), default="")
    source_url = Column(String(500), nullable=False)
    mode = Column(String(20), default="monolith")
    depth = Column(Integer, default=1)
    page_limit = Column(Integer, default=10)
    timeout_seconds = Column(Integer, default=6)
    max_bytes = Column(Integer, default=5_000_000)
    status = Column(String(30), default="pending")
    note = Column(Text, default="")
    storage_path = Column(String(500), default="")
    created_at = Column(DateTime, default=datetime.now)
