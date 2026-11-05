from datetime import datetime, timezone
from sqlalchemy import ForeignKey, Index, UniqueConstraint, String, DateTime, Integer, Text, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def now():
    return datetime.now(timezone.utc)

class Hospital(Base):
    __tablename__ = "hospitals"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    code: Mapped[str] = mapped_column(String(30), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class Department(Base):
    __tablename__ = "departments"
    id: Mapped[int] = mapped_column(primary_key=True)
    hospital_id: Mapped[int] = mapped_column(ForeignKey("hospitals.id"), index=True)
    name: Mapped[str] = mapped_column(String(140))
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (UniqueConstraint("hospital_id", "name"),)

class HospitalManager(Base):
    """Delegated directory administrator for exactly one hospital (not a clinical membership)."""
    __tablename__ = "hospital_managers"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    hospital_id: Mapped[int] = mapped_column(ForeignKey("hospitals.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (UniqueConstraint("user_id", "hospital_id"),)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(140))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    role: Mapped[str] = mapped_column(String(30), default="doctor")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (UniqueConstraint("user_id", "department_id"),)

class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf: Mapped[str] = mapped_column(String(80))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Consultation(Base):
    __tablename__ = "consultations"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(42), unique=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(100), nullable=True)
    patient_name: Mapped[str] = mapped_column(String(160))
    patient_ref: Mapped[str] = mapped_column(String(100))
    patient_age: Mapped[str] = mapped_column(String(30), default="")
    floor: Mapped[str] = mapped_column(String(60), default="")
    unit: Mapped[str] = mapped_column(String(80), default="")
    requester_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    initial_receiver_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    current_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    action_owner_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    requested_doctors: Mapped[str] = mapped_column(String(300), default="")
    priority: Mapped[str] = mapped_column(String(16), default="routine")
    clinical_summary: Mapped[str] = mapped_column(Text)
    question: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="active")
    task: Mapped[str] = mapped_column(String(40), default="reply")
    pending_transfer_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    answered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (Index("ix_consult_status_date", "status", "created_at"),
                        UniqueConstraint("created_by", "requester_dept_id", "idempotency_key", name="uq_consult_request"),)

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    consultation_id: Mapped[int] = mapped_column(ForeignKey("consultations.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    actor_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    type: Mapped[str] = mapped_column(String(40))
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Transfer(Base):
    __tablename__ = "transfers"
    id: Mapped[int] = mapped_column(primary_key=True)
    consultation_id: Mapped[int] = mapped_column(ForeignKey("consultations.id"), index=True)
    from_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    to_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    consultation_id: Mapped[int] = mapped_column(ForeignKey("consultations.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    actor_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    stored_name: Mapped[str] = mapped_column(String(120), unique=True)
    original_name: Mapped[str] = mapped_column(String(180))
    mime: Mapped[str] = mapped_column(String(70))
    bytes: Mapped[int] = mapped_column(Integer)
    digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Contact(Base):
    __tablename__ = "contacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    doctor_name: Mapped[str] = mapped_column(String(140))
    phone: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(50), default="consultant")
    note: Mapped[str] = mapped_column(String(200), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))

class CallLog(Base):
    __tablename__ = "call_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    consultation_id: Mapped[int] = mapped_column(ForeignKey("consultations.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    contacted_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    doctor_name: Mapped[str] = mapped_column(String(140))
    result: Mapped[str] = mapped_column(String(40))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Audit(Base):
    __tablename__ = "audits"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(String(400), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Notification(Base):
    """Department-scoped in-app notification, no PHI in the notification body."""
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    consultation_id: Mapped[int] = mapped_column(ForeignKey("consultations.id"), index=True)
    recipient_dept_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    kind: Mapped[str] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (Index("ix_notifications_dept_date", "recipient_dept_id", "created_at"),)

class NotificationRead(Base):
    """Acknowledgment per physician account, not a shared global department read state."""
    __tablename__ = "notification_reads"
    id: Mapped[int] = mapped_column(primary_key=True)
    notification_id: Mapped[int] = mapped_column(ForeignKey("notifications.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (UniqueConstraint("notification_id", "user_id"),)
