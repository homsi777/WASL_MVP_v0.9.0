"""WASL API — LAN/WAN pilot. NOT approved for production clinical data."""
import csv
import io
import hashlib
import hmac
import os
import re
import secrets
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, date, time, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, select_autoescape
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .db import Base, engine, get_db
from .models import (Audit, Attachment, CallLog, Consultation, Contact, Department,
                     Event, Hospital, HospitalManager, LoginSession, Membership, Transfer, User, Notification, NotificationRead, RosterSlot, RosterDayOverride, now)

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./wasl-uploads")).resolve()
MAX_UPLOAD = 8 * 1024 * 1024
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
SESSION_HOURS = 8
pwd = PasswordHasher()
@asynccontextmanager
async def lifespan(application):
    Base.metadata.create_all(engine)  # PILOT ONLY: migrations required before production.
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(title="WASL", version="0.9.2-preview", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
login_failures = defaultdict(deque)
login_lock = Lock()

@app.middleware("http")
async def security_headers(req: Request, call_next):
    resp = await call_next(req)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    if COOKIE_SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

def fail(status, msg):
    raise HTTPException(status_code=status, detail=msg)

def audit(db, user_id, action, target, detail=""):
    db.add(Audit(actor_id=user_id, action=action, target=str(target), detail=str(detail)[:400]))

def clean(value, limit=5000):
    return (value or "").strip()[:limit]

# The hospital clinical day is NOT the calendar day: 09:00 to next 08:59:59.999999.
# Clock-based categorization requires no rollover job and never mutates open consultations.
CLINICAL_TZ = ZoneInfo(os.getenv("CLINICAL_TIMEZONE", "Asia/Damascus"))
CLINICAL_START_HOUR = 9

def clinical_window(at=None):
    moment = at or now()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    local = moment.astimezone(CLINICAL_TZ)
    d = local.date()
    if local.hour < CLINICAL_START_HOUR:
        d -= timedelta(days=1)
    start_local = datetime.combine(d, time(CLINICAL_START_HOUR), tzinfo=CLINICAL_TZ)
    next_local = datetime.combine(d + timedelta(days=1), time(CLINICAL_START_HOUR), tzinfo=CLINICAL_TZ)
    return start_local.astimezone(timezone.utc), next_local.astimezone(timezone.utc), d.isoformat()

def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def notify(db, consultation, recipient_dept_id, kind):
    """Only opaque event data: never store patient text in notifications."""
    db.add(Notification(consultation_id=consultation.id, recipient_dept_id=recipient_dept_id, kind=kind))

def serial_date(value):
    if not value:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()

def user_data(u):
    return {"id": u.id, "username": u.username, "name": u.full_name, "is_admin": u.is_admin}

def department_data(d, db):
    h = db.get(Hospital, d.hospital_id)
    return {"id": d.id, "name": d.name, "hospital_id": d.hospital_id, "hospital": h.name if h else "", "parent_id": d.parent_id, "active": d.active}

def department_ids(db, user):
    return [m.department_id for m in db.scalars(select(Membership).where(Membership.user_id==user.id, Membership.active==True)).all()]

def access_session(req: Request, db: Session):
    token = req.cookies.get("wasl_session", "")
    if not token or len(token) < 48:
        fail(401, "يجب تسجيل الدخول")
    digest = hashlib.sha256(token.encode()).hexdigest()
    session = db.scalar(select(LoginSession).where(LoginSession.token_digest == digest))
    if not session or session.expires_at.replace(tzinfo=timezone.utc) <= now():
        fail(401, "انتهت صلاحية الجلسة")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        fail(401, "الحساب غير مفعّل")
    return user, session

def get_user(req: Request, db: Session = Depends(get_db)):
    return access_session(req, db)[0]

def writing_access(req: Request, db: Session):
    user, session = access_session(req, db)
    supplied = req.headers.get("x-csrf-token", "")
    if not supplied or not hmac.compare_digest(supplied, session.csrf):
        fail(403, "فشل التحقق من حماية الطلب")
    # CSRF token remains mandatory; Origin check rejects mismatched browsers.
    origin = req.headers.get("origin", "")
    if origin:
        from urllib.parse import urlsplit
        parsed = urlsplit(origin)
        raw_host = req.headers.get("host", "")
        expected = os.getenv("PUBLIC_ORIGIN", "")
        if expected:
            if origin.rstrip("/") != expected.rstrip("/"):
                fail(403, "مصدر الطلب غير مسموح")
        elif parsed.netloc != raw_host:
            fail(403, "مصدر الطلب غير مسموح")
    return user

def selected_department(req: Request, db, user):
    raw = req.headers.get("x-department-id", "")
    try:
        department_id = int(raw)
    except (ValueError, TypeError):
        fail(400, "حدد القسم النشط")
    dept = db.get(Department, department_id)
    if not dept or not dept.active or dept.id not in department_ids(db, user):
        fail(403, "لا تملك صلاحية هذا القسم")
    return dept

def admin_only(user):
    if not user.is_admin:
        fail(403, "صلاحية مدير النظام مطلوبة")

def managed_hospital_ids(db, user):
    if user.is_admin:
        return [h.id for h in db.scalars(select(Hospital).where(Hospital.active==True))]
    return [m.hospital_id for m in db.scalars(select(HospitalManager).where(HospitalManager.user_id==user.id, HospitalManager.active==True))]

def hospital_manager_only(db, user, hospital_id):
    hospital=db.get(Hospital,hospital_id)
    if not hospital or not hospital.active:
        fail(404,"المشفى غير موجود أو غير فعال")
    if hospital_id not in managed_hospital_ids(db,user):
        fail(403,"لا تملك صلاحية إدارة أقسام هذا المشفى")
    return hospital

def validate_parent(db, hospital_id, parent_id, current_id=None):
    if parent_id is None:return
    if parent_id==current_id:fail(422,"القسم لا يمكن أن يكون أباً لنفسه")
    parent=db.get(Department,parent_id)
    if not parent or parent.hospital_id!=hospital_id or not parent.active:
        fail(422,"القسم الأب غير صالح أو يتبع مشفى آخر")
    visited=set()
    while parent:
        if parent.id==current_id:fail(422,"لا يمكن إنشاء حلقة في شجرة الأقسام")
        if parent.id in visited:fail(422,"توجد حلقة غير صالحة في الأقسام")
        visited.add(parent.id)
        parent=db.get(Department,parent.parent_id) if parent.parent_id else None

def manager_only(db, user, department_id):
    m = db.scalar(select(Membership).where(Membership.user_id==user.id, Membership.department_id==department_id, Membership.active==True))
    if not m or m.role != "department_admin":
        fail(403, "صلاحية مسؤول القسم مطلوبة")

def can_see(db, user, dept, consultation):
    if dept.id in (consultation.requester_dept_id, consultation.initial_receiver_dept_id,
                   consultation.current_dept_id, consultation.action_owner_dept_id):
        return True
    for t in db.scalars(select(Transfer).where(Transfer.consultation_id==consultation.id)):
        if dept.id in (t.from_dept_id, t.to_dept_id):
            return True
    return False

def permitted_consult(db, consultation_id, user, dept, lock=False):
    query = select(Consultation).where(Consultation.id==consultation_id)
    if lock:
        query = query.with_for_update()
    c = db.scalar(query)
    if not c:
        fail(404, "الاستشارة غير موجودة")
    if not can_see(db, user, dept, c):
        audit(db, user.id, "denied_read", consultation_id, str(dept.id))
        db.commit()
        fail(403, "لا يسمح لك بالاطلاع على هذه الاستشارة")
    return c

def event_record(db, c, user, dept, event_type, body=""):
    e = Event(consultation_id=c.id, actor_id=user.id, actor_dept_id=dept.id, type=event_type, body=clean(body, 12000))
    db.add(e)
    audit(db, user.id, event_type, c.code, "department=" + str(dept.id))
    return e

def consultation_data(db, c):
    current = db.get(Department, c.current_dept_id)
    return {
        "id": c.id, "code": c.code, "patient_name": c.patient_name, "patient_ref": c.patient_ref,
        "patient_age": c.patient_age, "floor": c.floor, "unit": c.unit,
        "requester_dept_id": c.requester_dept_id, "initial_receiver_dept_id": c.initial_receiver_dept_id,
        "current_dept_id": c.current_dept_id, "action_owner_dept_id": c.action_owner_dept_id,
        "current_department": current.name if current else "", "created_by": c.created_by,
        "requested_doctors": c.requested_doctors, "priority": c.priority, "clinical_summary": c.clinical_summary,
        "question": c.question, "status": c.status, "task": c.task,
        "pending_transfer_id": c.pending_transfer_id, "created_at": serial_date(c.created_at),
        "answered_at": serial_date(c.answered_at), "closed_at": serial_date(c.closed_at),
        "clinical_day": clinical_window(c.created_at)[2], "archived": c.status == "closed"
    }

def involved_ids(db, dept_id):
    direct = set(db.scalars(select(Consultation.id).where(or_(Consultation.initial_receiver_dept_id==dept_id,
       Consultation.current_dept_id==dept_id, Consultation.action_owner_dept_id==dept_id))).all())
    transfers = db.scalars(select(Transfer.consultation_id).where(or_(Transfer.from_dept_id==dept_id, Transfer.to_dept_id==dept_id))).all()
    return direct | set(transfers)

class Credentials(BaseModel):
    username: str
    password: str

@app.get("/healthz")
def healthz(db: Session=Depends(get_db)):
    db.execute(select(Hospital.id).limit(1))
    return {"ok": True, "service": "wasl"}

@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")

@app.post("/api/auth/login")
def login(data: Credentials, req: Request, resp: Response, db: Session = Depends(get_db)):
    username = clean(data.username, 80).lower()
    addr = req.client.host if req.client else "unknown"
    key = addr + ":" + username
    with login_lock:
        recent = login_failures[key]
        while recent and recent[0] < now() - timedelta(minutes=15):
            recent.popleft()
        if len(recent) >= 5:
            fail(429, "محاولات كثيرة. حاول لاحقاً")
    user = db.scalar(select(User).where(User.username==username))
    valid = False
    if user and user.active:
        try:
            valid = pwd.verify(user.password_hash, data.password)
        except (VerifyMismatchError, VerificationError):
            valid = False
    if not valid:
        with login_lock:
            login_failures[key].append(now())
        fail(401, "بيانات الدخول غير صحيحة")
    with login_lock:
        login_failures.pop(key, None)
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    db.add(LoginSession(user_id=user.id, token_digest=hashlib.sha256(token.encode()).hexdigest(), csrf=csrf,
                        expires_at=now()+timedelta(hours=SESSION_HOURS)))
    audit(db, user.id, "login", user.id)
    db.commit()
    resp.set_cookie("wasl_session", token, httponly=True, secure=COOKIE_SECURE, samesite="strict", max_age=SESSION_HOURS*3600, path="/")
    return {"user": user_data(user), "csrf": csrf}

@app.get("/api/me")
def me(req: Request, db: Session=Depends(get_db)):
    user, session = access_session(req, db)
    return {"user": user_data(user), "csrf": session.csrf, "memberships": department_ids(db, user)}

@app.post("/api/auth/logout")
def logout(req: Request, resp: Response, db: Session=Depends(get_db)):
    user = writing_access(req, db)
    token = req.cookies.get("wasl_session", "")
    digest = hashlib.sha256(token.encode()).hexdigest()
    s = db.scalar(select(LoginSession).where(LoginSession.token_digest==digest))
    if s:
        db.delete(s)
    audit(db, user.id, "logout", user.id)
    db.commit()
    resp.delete_cookie("wasl_session", path="/")
    return {"ok": True}

class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=14, max_length=120)

@app.post("/api/auth/change-password")
def change_password(data: PasswordChange, req: Request, db: Session=Depends(get_db)):
    user = writing_access(req,db)
    # Per clinical governance decision: only Super Admin accounts manage their own
    # password. Doctor and department-admin credentials are issued and rotated
    # exclusively from the Super Admin panel (POST /api/admin/users/{id}/set-password).
    admin_only(user)
    try:
        verified = pwd.verify(user.password_hash, data.current_password)
    except (VerifyMismatchError, VerificationError):
        verified = False
    if not verified:
        fail(403,"كلمة المرور الحالية غير صحيحة")
    if data.new_password == data.current_password:
        fail(422,"اختر كلمة مرور جديدة مختلفة")
    if len(set(data.new_password)) < 8:
        fail(422,"كلمة المرور الجديدة ضعيفة جداً")
    user.password_hash = pwd.hash(data.new_password)
    current = hashlib.sha256(req.cookies["wasl_session"].encode()).hexdigest()
    for item in db.scalars(select(LoginSession).where(LoginSession.user_id==user.id)).all():
        if item.token_digest != current:
            db.delete(item)
    audit(db,user.id,"password_changed",user.id)
    db.commit()
    return {"ok": True, "other_sessions_revoked": True}

@app.get("/api/directory")
def directory(user: User=Depends(get_user), db: Session=Depends(get_db)):
    return {"hospitals": [{"id": h.id, "name": h.name, "code": h.code} for h in db.scalars(select(Hospital).where(Hospital.active==True).order_by(Hospital.name))],
      "departments": [department_data(d, db) for d in db.scalars(select(Department).where(Department.active==True).order_by(Department.hospital_id,Department.name))],
      "memberships": [{"department_id": m.department_id, "role": m.role} for m in db.scalars(select(Membership).where(Membership.user_id==user.id, Membership.active==True))], "managed_hospital_ids": managed_hospital_ids(db,user)}

@app.get("/api/consultations")
def consultations(req: Request, folder: Literal["incoming","outgoing"]="incoming", status: str="", floor: str="", unit: str="", priority: str="", q: str="", scope: Literal["open","today","carryover","archive","all"]="open", db: Session=Depends(get_db)):
    user = get_user(req, db)
    dept = selected_department(req, db, user)
    if folder == "outgoing":
        records = db.scalars(select(Consultation).where(Consultation.requester_dept_id==dept.id).order_by(Consultation.created_at.desc())).all()
    else:
        ids = involved_ids(db, dept.id)
        records = db.scalars(select(Consultation).where(Consultation.id.in_(ids)).order_by(Consultation.created_at.desc())).all() if ids else []
    start, end, _ = clinical_window()
    if status == "closed" and scope == "open":
        scope = "archive"
    if scope == "open":
        records = [c for c in records if c.status != "closed"]
    elif scope == "archive":
        records = [c for c in records if c.status == "closed"]
    elif scope == "today":
        records = [c for c in records if c.status != "closed" and start <= aware(c.created_at) < end]
    elif scope == "carryover":
        records = [c for c in records if c.status != "closed" and aware(c.created_at) < start]
    if status:
        records = [c for c in records if c.status==status or (status=="waiting" and c.action_owner_dept_id==dept.id and c.status=="active")]
    if floor:
        records = [c for c in records if c.floor == floor]
    if unit:
        records = [c for c in records if c.unit == unit]
    if priority:
        records = [c for c in records if c.priority == priority]
    if q:
        needle = q.lower().strip()
        records = [c for c in records if needle in (c.code.lower(), c.patient_name.lower(), c.patient_ref.lower()) or needle in c.question.lower()]
    return {"items": [consultation_data(db,c) for c in records[:250]], "total": len(records)}

@app.get("/api/dashboard/filter-options")
def dashboard_filter_options(req:Request,db:Session=Depends(get_db)):
    user=get_user(req,db)
    dept=selected_department(req,db,user)
    ids=involved_ids(db,dept.id)
    inc=db.scalars(select(Consultation).where(Consultation.id.in_(ids))).all() if ids else []
    out=db.scalars(select(Consultation).where(Consultation.requester_dept_id==dept.id)).all()
    records={c.id:c for c in inc+out}.values()
    return {"floors": sorted({c.floor for c in records if c.floor})[:100],
            "units": sorted({c.unit for c in records if c.unit})[:100]}

@app.get("/api/dashboard")
def dashboard(req: Request, floor: str="", unit: str="", db: Session=Depends(get_db)):
    user = get_user(req, db)
    dept = selected_department(req, db, user)
    ids = involved_ids(db, dept.id)
    inc = db.scalars(select(Consultation).where(Consultation.id.in_(ids))).all() if ids else []
    out = db.scalars(select(Consultation).where(Consultation.requester_dept_id==dept.id)).all()
    if floor:
        inc=[c for c in inc if c.floor==floor]
        out=[c for c in out if c.floor==floor]
    if unit:
        inc=[c for c in inc if c.unit==unit]
        out=[c for c in out if c.unit==unit]
    views = set(db.scalars(select(Event.consultation_id).where(Event.actor_dept_id==dept.id, Event.type=="viewed")).all())
    completed_ids = set(db.scalars(select(Event.consultation_id).where(Event.actor_dept_id==dept.id, Event.type=="completed")).all())
    inbound_action = [c for c in inc if c.status=="active" and c.action_owner_dept_id==dept.id]
    sent_waiting = [c for c in out if c.status=="active" and c.action_owner_dept_id!=dept.id]
    # Time thresholds are intentionally DISABLED until a hospital-approved policy sets them.
    limits={k:int(os.getenv("SLA_MINUTES_"+k.upper(),"0") or 0) for k in ("routine","urgent","emergency")}
    def overdue(c):
        threshold=limits.get(c.priority,0)
        if not threshold or c.status!="active":return False
        return (now()-(c.created_at.replace(tzinfo=timezone.utc) if not c.created_at.tzinfo else c.created_at)).total_seconds() > threshold*60
    day_start, day_end, day_label = clinical_window()
    open_in = [c for c in inc if c.status != "closed"]
    open_out = [c for c in out if c.status != "closed"]
    rollover = {
       "current_day": day_label,
       "starts_at": serial_date(day_start),
       "ends_at_exclusive": serial_date(day_end),
       "timezone": str(CLINICAL_TZ),
       "incoming_created_today": sum(1 for c in inc if day_start <= aware(c.created_at) < day_end),
       "outgoing_created_today": sum(1 for c in out if day_start <= aware(c.created_at) < day_end),
       "incoming_open_today": sum(1 for c in open_in if day_start <= aware(c.created_at) < day_end),
       "outgoing_open_today": sum(1 for c in open_out if day_start <= aware(c.created_at) < day_end),
       "incoming_carried": sum(1 for c in open_in if aware(c.created_at) < day_start),
       "outgoing_carried": sum(1 for c in open_out if aware(c.created_at) < day_start),
       "incoming_closed_today": sum(1 for c in inc if c.closed_at and day_start <= aware(c.closed_at) < day_end),
       "outgoing_closed_today": sum(1 for c in out if c.closed_at and day_start <= aware(c.closed_at) < day_end),
       "incoming_archived_total": sum(1 for c in inc if c.status == "closed"),
       "outgoing_archived_total": sum(1 for c in out if c.status == "closed"),
    }
    return {
      "clinical_day": rollover,
      "incoming": {"total":len(inc), "action_required": len(inbound_action),
          "awaiting_response":sum(1 for c in inbound_action if c.current_dept_id==dept.id and c.task in ("reply","assessment")),
          "unread": sum(1 for c in inc if c.id not in views and c.status != "closed"),
          "completed_responses": sum(1 for c in inc if c.id in completed_ids),
          "awaiting_transfer": sum(1 for c in inc if c.pending_transfer_id and c.action_owner_dept_id==dept.id),
          "overdue":sum(1 for c in inbound_action if overdue(c)) if any(limits.values()) else None},
      "outgoing": {"total":len(out), "awaiting_reply":len(sent_waiting),
         "awaiting_closure":sum(1 for c in out if c.status=="completed"),
         "closed":sum(1 for c in out if c.status=="closed"),
         "overdue":sum(1 for c in sent_waiting if overdue(c)) if any(limits.values()) else None},
      "thresholds_configured":bool(any(limits.values())),
      "filters": {"floor":floor,"unit":unit}, "generated_at":serial_date(now())}

@app.get("/api/handover")
def handover(req: Request, db: Session=Depends(get_db)):
    """All older open cases visible to this department; who must act is explicit."""
    user = get_user(req, db)
    dept = selected_department(req, db, user)
    start, end, day = clinical_window()
    ids = involved_ids(db, dept.id) | set(db.scalars(select(Consultation.id).where(Consultation.requester_dept_id==dept.id)))
    records = db.scalars(select(Consultation).where(Consultation.id.in_(ids))).all() if ids else []
    pending = sorted((c for c in records if c.status != "closed" and aware(c.created_at) < start), key=lambda c: (c.priority != "emergency", c.priority != "urgent", aware(c.created_at)))
    return {"clinical_day":day, "timezone":str(CLINICAL_TZ), "generated_at":serial_date(now()),
       "items":[{"consultation":consultation_data(db,c),"requires_our_action":c.action_owner_dept_id==dept.id} for c in pending[:250]], "total":len(pending)}

@app.get("/api/notifications")
def notifications(req: Request, limit:int=40, db:Session=Depends(get_db)):
    user=get_user(req,db); dept=selected_department(req,db,user)
    limit=max(1,min(limit,100))
    notes=db.scalars(select(Notification).where(Notification.recipient_dept_id==dept.id).order_by(Notification.id.desc()).limit(limit)).all()
    read_ids=set(db.scalars(select(NotificationRead.notification_id).where(NotificationRead.user_id==user.id,NotificationRead.notification_id.in_([x.id for x in notes]))).all()) if notes else set()
    return {"items":[{"id":n.id,"consultation_id":n.consultation_id,"kind":n.kind,"created_at":serial_date(n.created_at),"read":n.id in read_ids} for n in notes],
       "unread_in_page":sum(1 for n in notes if n.id not in read_ids)}

@app.post("/api/notifications/{notification_id}/read")
def read_notification(notification_id:int, req:Request, db:Session=Depends(get_db)):
    user=writing_access(req,db); dept=selected_department(req,db,user)
    n=db.get(Notification,notification_id)
    if not n or n.recipient_dept_id!=dept.id:fail(404,"الإشعار غير متاح في هذا القسم")
    found=db.scalar(select(NotificationRead).where(NotificationRead.notification_id==n.id,NotificationRead.user_id==user.id))
    if not found:
        db.add(NotificationRead(notification_id=n.id,user_id=user.id))
        db.commit()
    return {"ok":True}

@app.get("/api/consultations/{consultation_id}")
def consultation_detail(consultation_id: int, req: Request, db: Session=Depends(get_db)):
    user = get_user(req, db)
    dept = selected_department(req, db, user)
    c = permitted_consult(db, consultation_id, user, dept)
    was_seen = db.scalar(select(Event.id).where(Event.consultation_id==c.id, Event.actor_dept_id==dept.id, Event.type=="viewed"))
    if not was_seen:
        event_record(db,c,user,dept,"viewed")
    audit(db,user.id,"read",c.code, "dept="+str(dept.id))
    db.commit()
    events = db.scalars(select(Event).where(Event.consultation_id==c.id).order_by(Event.created_at, Event.id)).all()
    trans = db.scalars(select(Transfer).where(Transfer.consultation_id==c.id).order_by(Transfer.id)).all()
    attachments = db.scalars(select(Attachment).where(Attachment.consultation_id==c.id).order_by(Attachment.id)).all()
    calls = db.scalars(select(CallLog).where(CallLog.consultation_id==c.id).order_by(CallLog.id)).all()
    return {"consultation": consultation_data(db,c),
      "events": [{"id":e.id,"type":e.type,"body":e.body,"actor":db.get(User,e.actor_id).full_name,
                  "actor_dept_id":e.actor_dept_id,"created_at":serial_date(e.created_at)} for e in events if e.type!="viewed"],
      "transfers": [{"id":t.id,"from_dept_id":t.from_dept_id,"to_dept_id":t.to_dept_id,"reason":t.reason,
                     "status":t.status,"created_at":serial_date(t.created_at)} for t in trans],
      "attachments": [{"id":a.id,"name":a.original_name,"mime":a.mime,"bytes":a.bytes,"created_at":serial_date(a.created_at)} for a in attachments],
      "calls": [{"doctor":k.doctor_name,"result":k.result,"note":k.note,"created_at":serial_date(k.created_at)} for k in calls]}

class CreateConsultation(BaseModel):
    patient_name: str=Field(min_length=2,max_length=160)
    patient_ref: str=Field(min_length=1,max_length=100)
    patient_age: str=Field(default="",max_length=30)
    floor: str=Field(default="",max_length=60)
    unit: str=Field(default="",max_length=80)
    receiver_department_id: int
    idempotency_key: str | None = Field(default=None, max_length=100)
    priority: Literal["routine", "urgent", "emergency"]="routine"
    requested_doctors: str=Field(min_length=2,max_length=300)
    clinical_summary: str=Field(min_length=5,max_length=12000)
    question: str=Field(min_length=5,max_length=6000)

@app.post("/api/consultations", status_code=201)
def create_consultation(data: CreateConsultation, req: Request, db: Session=Depends(get_db)):
    user = writing_access(req, db)
    dept = selected_department(req,db,user)
    target = db.get(Department,data.receiver_department_id)
    if not target or not target.active or target.id==dept.id:
        fail(400,"القسم المستقبِل غير صالح")
    if not data.patient_name.strip() or not data.question.strip() or not data.clinical_summary.strip() or len(data.requested_doctors.strip())<2:
        fail(422,"الحقول المطلوبة لا يمكن أن تكون فارغة")
    if data.idempotency_key:
        prior = db.scalar(select(Consultation).where(Consultation.created_by==user.id, Consultation.requester_dept_id==dept.id, Consultation.idempotency_key==data.idempotency_key))
        if prior:
            return {"id": prior.id, "code": prior.code, "duplicate_prevented": True}
    c = Consultation(code="WASL-"+str(now().year)+"-"+uuid.uuid4().hex[:10].upper(), idempotency_key=data.idempotency_key,
        patient_name=clean(data.patient_name,160), patient_ref=clean(data.patient_ref,100),
        patient_age=clean(data.patient_age,30),floor=clean(data.floor,60),unit=clean(data.unit,80),
        requester_dept_id=dept.id,initial_receiver_dept_id=target.id,current_dept_id=target.id,
        action_owner_dept_id=target.id,created_by=user.id,requested_doctors=clean(data.requested_doctors,300),
        priority=data.priority,clinical_summary=clean(data.clinical_summary,12000),question=clean(data.question,6000))
    db.add(c)
    db.flush()
    event_record(db,c,user,dept,"created","أُرسلت الاستشارة إلى قسم " + target.name)
    notify(db,c,target.id,"new_consultation")
    db.commit()
    return {"id":c.id,"code":c.code}

class ActionData(BaseModel):
    action: Literal["reply", "request_info", "provide_info", "request_investigations", "request_assessment",
      "patient_arrived", "patient_returned", "complete", "followup", "close", "note"]
    body: str=Field(default="",max_length=12000)

@app.post("/api/consultations/{consultation_id}/actions")
def take_action(consultation_id: int, data:ActionData, req:Request, db:Session=Depends(get_db)):
    user = writing_access(req,db)
    dept = selected_department(req,db,user)
    c = permitted_consult(db,consultation_id,user,dept,lock=True)
    if c.status=="closed":
        fail(409,"الاستشارة مغلقة ولا تقبل تعديلات")
    if c.pending_transfer_id:
        fail(409,"بانتظار قرار تحويل الاستشارة، أكمل التحويل أولاً")
    a=data.action
    body=clean(data.body,12000)
    if a in {"reply","request_info","request_investigations","request_assessment","complete"}:
        if dept.id != c.current_dept_id or c.status != "active" or c.action_owner_dept_id!=dept.id:
            fail(403,"الرد متاح للقسم المسؤول حالياً عندما تكون المهمة لديه")
    if a in {"provide_info","patient_arrived","patient_returned","followup","close"} and dept.id != c.requester_dept_id:
        fail(403,"هذا الإجراء مخصص للقسم طالب الاستشارة")
    if a in {"provide_info","patient_arrived"} and c.action_owner_dept_id!=dept.id:
        fail(409,"لا توجد مهمة حالية على القسم الطالب")
    if a=="followup" and c.status!="completed":
        fail(409,"طلب الاستكمال متاح فقط بعد إنهاء الرد")
    if a=="close" and c.status!="completed":
        fail(409,"لا يمكن الإغلاق قبل إنهاء القسم المستقبِل لرده")
    if a=="note" and dept.id not in (c.current_dept_id,c.requester_dept_id):
        fail(403,"لا يحق لهذا القسم إضافة تعليق")
    required_body={"reply","request_info","provide_info","request_investigations","request_assessment","followup"}
    if a in required_body and not body:
        fail(422,"أدخل نص الإجراء")
    if a=="complete":
        # Completion requires an independently saved reply AFTER the latest
        # request/response cycle boundary. A completion note cannot bypass it.
        last_cycle_start = db.scalar(select(Event.id).where(
            Event.consultation_id==c.id,
            Event.type.in_([
                "followup_requested", "transfer_accepted",
                "information_requested", "investigations_requested",
                "assessment_requested", "information_provided", "patient_arrived",
            ])
        ).order_by(Event.id.desc()).limit(1)) or 0
        has_fresh_reply = db.scalar(select(Event.id).where(
            Event.consultation_id==c.id,
            Event.actor_dept_id==dept.id,
            Event.type=="reply",
            Event.id>last_cycle_start
        ).order_by(Event.id.desc()).limit(1))
        if not has_fresh_reply:
            fail(422,"يجب حفظ رد طبي جديد بعد آخر إجراء مطلوب قبل إنهاء الاستشارة")
    if a=="request_info":
        c.action_owner_dept_id=c.requester_dept_id
        c.task="provide_info"
    elif a=="request_investigations":
        c.action_owner_dept_id=c.requester_dept_id
        c.task="investigations"
    elif a=="request_assessment":
        c.action_owner_dept_id=c.requester_dept_id
        c.task="patient_arrival"
    elif a=="provide_info":
        if c.task not in ("provide_info","investigations"):
            fail(409,"ليس هناك طلب معلومات أو استقصاءات مفتوح")
        c.action_owner_dept_id=c.current_dept_id
        c.task="reply"
    elif a=="patient_arrived":
        if c.task!="patient_arrival":fail(409,"لم يُطلب حضور المريض")
        c.action_owner_dept_id=c.current_dept_id
        c.task="assessment"
    elif a=="patient_returned":
        # Independent movement record: permitted after arrival, even if the reply was written.
        movement = db.scalars(select(Event).where(Event.consultation_id==c.id, Event.type.in_(["patient_arrived","patient_returned"])).order_by(Event.id.desc())).first()
        if not movement or movement.type!="patient_arrived":
            fail(409,"لا توجد واقعة وصول مريض غير متبوعة بعودة")
        if c.task=="assessment":
            c.action_owner_dept_id=c.current_dept_id
            c.task="reply"
    elif a=="complete":
        c.status="completed"
        c.task="review"
        c.action_owner_dept_id=c.requester_dept_id
        c.answered_at=now()
    elif a=="followup":
        c.status="active"
        c.task="reply"
        c.action_owner_dept_id=c.current_dept_id
    elif a=="close":
        c.status="closed"
        c.task="closed"
        c.closed_at=now()
    elif a=="reply":
        c.task="reply"
    label={"reply":"reply","request_info":"information_requested","provide_info":"information_provided",
        "request_investigations":"investigations_requested","request_assessment":"assessment_requested",
        "patient_arrived":"patient_arrived","patient_returned":"patient_returned", "complete":"completed",
        "followup":"followup_requested", "close":"closed", "note":"note"}[a]
    event_record(db,c,user,dept,label,body)
    if a in {"reply","request_info","request_investigations","request_assessment","complete"}:
        notify(db,c,c.requester_dept_id,"response_completed" if a=="complete" else "requester_update")
    elif a in {"provide_info","patient_arrived","followup"}:
        notify(db,c,c.current_dept_id,"requester_update")
    elif a=="close":
        notify(db,c,c.current_dept_id,"consultation_closed")
    db.commit()
    return {"ok":True,"consultation":consultation_data(db,c)}

class TransferData(BaseModel):
    to_department_id: int
    reason: str=Field(min_length=3,max_length=3000)

@app.post("/api/consultations/{consultation_id}/transfers")
def propose_transfer(consultation_id:int, data:TransferData, req:Request, db:Session=Depends(get_db)):
    user=writing_access(req,db)
    dept=selected_department(req,db,user)
    c=permitted_consult(db,consultation_id,user,dept,lock=True)
    if c.status!="active" or c.current_dept_id!=dept.id or c.action_owner_dept_id!=dept.id or c.pending_transfer_id:
        fail(409,"لا يمكنك التحويل في حالة الطلب الحالية")
    dest=db.get(Department,data.to_department_id)
    if not dest or not dest.active or dest.id==dept.id:
        fail(400,"القسم الفرعي المستقبِل غير صالح")
    t=Transfer(consultation_id=c.id,from_dept_id=dept.id,to_dept_id=dest.id,reason=clean(data.reason,3000),created_by=user.id)
    db.add(t)
    db.flush()
    c.pending_transfer_id=t.id
    c.task="transfer_decision"
    c.action_owner_dept_id=dest.id
    event_record(db,c,user,dept,"transfer_requested", "إلى " + dest.name + " — " + data.reason)
    notify(db,c,dest.id,"transfer_requested")
    db.commit()
    return {"transfer_id":t.id,"status":"pending"}

class TransferDecision(BaseModel):
    decision: Literal["accept","reject"]
    reason: str=Field(default="",max_length=2000)

@app.post("/api/transfers/{transfer_id}/decision")
def decide_transfer(transfer_id:int,data:TransferDecision,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db)
    dept=selected_department(req,db,user)
    t=db.scalar(select(Transfer).where(Transfer.id==transfer_id).with_for_update())
    if not t:fail(404,"التحويل غير موجود")
    c=db.scalar(select(Consultation).where(Consultation.id==t.consultation_id).with_for_update())
    if dept.id!=t.to_dept_id or t.status!="pending" or c.pending_transfer_id!=t.id:
        fail(403,"قرار التحويل للقسم المستقبِل فقط")
    if data.decision=="reject" and not data.reason.strip():fail(422,"سبب الرفض مطلوب")
    t.status="accepted" if data.decision=="accept" else "rejected"
    t.decided_at=now();t.decided_by=user.id
    c.pending_transfer_id=None
    c.task="reply"
    if data.decision=="accept":
        c.current_dept_id=dept.id
        c.action_owner_dept_id=dept.id
        event_record(db,c,user,dept,"transfer_accepted", data.reason)
        notify(db,c,t.from_dept_id,"transfer_accepted")
    else:
        c.action_owner_dept_id=t.from_dept_id
        event_record(db,c,user,dept,"transfer_rejected", data.reason)
        notify(db,c,t.from_dept_id,"transfer_rejected")
    db.commit()
    return {"ok":True,"status":t.status}

@app.post("/api/consultations/{consultation_id}/attachments")
async def upload_attachment(consultation_id:int,req:Request,file:UploadFile=File(...),db:Session=Depends(get_db)):
    user=writing_access(req,db)
    dept=selected_department(req,db,user)
    c=permitted_consult(db,consultation_id,user,dept)
    if c.status=="closed":fail(409,"الاستشارة مغلقة")
    if dept.id not in (c.requester_dept_id,c.current_dept_id):fail(403,"لا يجوز إرفاق ملفات هنا")
    name=Path((file.filename or "attachment").replace("\\","/")).name[:180]
    ext=Path(name).suffix.lower()
    accepted={".pdf":("application/pdf", b"%PDF-"), ".png":("image/png",b"\x89PNG\r\n\x1a\n"), ".jpg":("image/jpeg",b"\xff\xd8\xff"), ".jpeg":("image/jpeg",b"\xff\xd8\xff")}
    if ext not in accepted:fail(415,"المرفقات المسموحة: PDF أو PNG أو JPEG")
    raw=await file.read(MAX_UPLOAD+1)
    if not raw or len(raw)>MAX_UPLOAD:fail(413,"الملف فارغ أو أكبر من 8MB")
    mime,magic=accepted[ext]
    if not raw.startswith(magic):fail(415,"محتوى الملف لا يطابق نوعه")
    storage=uuid.uuid4().hex + ext
    (UPLOAD_DIR/storage).write_bytes(raw)
    try:
        a=Attachment(consultation_id=c.id,actor_id=user.id,actor_dept_id=dept.id,stored_name=storage,
                     original_name=name,mime=mime,bytes=len(raw),digest=hashlib.sha256(raw).hexdigest())
        db.add(a)
        event_record(db,c,user,dept,"attachment_added",name)
        db.commit()
        db.refresh(a)
        return {"id":a.id,"name":a.original_name}
    except Exception:
        (UPLOAD_DIR/storage).unlink(missing_ok=True)
        raise

@app.get("/api/attachments/{attachment_id}")
def download_attachment(attachment_id:int,req:Request,db:Session=Depends(get_db)):
    user=get_user(req,db)
    dept=selected_department(req,db,user)
    a=db.get(Attachment,attachment_id)
    if not a:fail(404,"الملف غير موجود")
    c=permitted_consult(db,a.consultation_id,user,dept)
    audit(db,user.id,"attachment_download",str(attachment_id),c.code)
    db.commit()
    f=UPLOAD_DIR/a.stored_name
    if not f.exists():fail(404,"الملف مفقود من التخزين")
    return FileResponse(f,media_type="application/octet-stream",headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(a.original_name)}"})


# --- Consultation contacts roster (weekly template + day-specific override) ---
class RosterShiftInput(BaseModel):
    doctor_name: str = Field(min_length=2, max_length=140)
    phone: str = Field(min_length=6, max_length=40)
    start: str = Field(pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
    end: str = Field(pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
    contact_role: Literal["primary","backup"] = "primary"
    note: str = Field(default="",max_length=200)

class RosterReplaceInput(BaseModel):
    slots: list[RosterShiftInput] = Field(default_factory=list,max_length=40)

def roster_department(db, department_id):
    dept=db.get(Department,department_id)
    if not dept or not dept.active:fail(404,"القسم غير موجود أو غير فعّال")
    return dept

def roster_authorized_reader(req,db,department_id):
    actor=get_user(req,db)
    if not actor.is_admin:
        selected_department(req,db,actor)  # active clinical membership required to view contacts
    return roster_department(db,department_id)

def roster_authorized_writer(req,db,department_id):
    actor=writing_access(req,db)
    roster_department(db,department_id)
    if not actor.is_admin:
        selected_department(req,db,actor)
        manager_only(db,actor,department_id)
    return actor

def minutes_from_clinical_start(hhmm):
    hr,minute=map(int,hhmm.split(":"))
    return (hr*60+minute-9*60)%1440

def slot_bounds(shift):
    start=minutes_from_clinical_start(shift.start)
    end=minutes_from_clinical_start(shift.end)
    if shift.start==shift.end:
        if shift.start != "09:00":fail(422,"مناوبة 24 ساعة مسموحة من 09:00 إلى 09:00 فقط")
        end=1440
    elif end==0: end=1440
    if end<=start:fail(422,"الفترة تتجاوز حدود اليوم الطبي 09:00–09:00؛ قسّمها على يومين")
    if not re.fullmatch(r"\+?[0-9 ()\-]{6,40}",shift.phone):fail(422,"رقم هاتف المناوبة غير صالح")
    return start,end

def clock_from_minute(minutes):
    n=(minutes+9*60)%(24*60)
    return f"{n//60:02d}:{n%60:02d}"

def roster_public_slot(slot):
    return {"id":slot.id,"doctor_name":slot.doctor_name,"phone":slot.phone,
            "start":clock_from_minute(slot.start_minute),"end":clock_from_minute(slot.end_minute),
            "start_minute":slot.start_minute,"end_minute":slot.end_minute,
            "contact_role":slot.contact_role,"note":slot.note}

def active_roster_slots(db,dept_id,d):
    override=db.scalar(select(RosterDayOverride).where(RosterDayOverride.department_id==dept_id,RosterDayOverride.clinical_date==d))
    source="daily" if override else "weekly"
    condition=(RosterSlot.clinical_date==d) if override else (RosterSlot.weekday==d.weekday())
    return (db.scalars(select(RosterSlot).where(RosterSlot.department_id==dept_id,
                    RosterSlot.kind==source,RosterSlot.active==True,condition)
             .order_by(RosterSlot.start_minute,RosterSlot.contact_role,RosterSlot.id)).all(),source)

def roster_gap_ranges(slots):
    intervals=sorted((s.start_minute,s.end_minute) for s in slots)
    gaps=[];end=0
    for begin,finish in intervals:
        if begin>end:gaps.append({"from":clock_from_minute(end),"to":clock_from_minute(begin)})
        end=max(end,finish)
    if end<1440:gaps.append({"from":clock_from_minute(end),"to":clock_from_minute(1440)})
    return gaps

def roster_response(db,dept_id,d):
    slots,source=active_roster_slots(db,dept_id,d)
    start,end,day=clinical_window()
    on_today=(day==d.isoformat())
    current_min=None
    if on_today:
        elapsed=int((now()-start).total_seconds()//60)
        current_min=max(0,min(1439,elapsed))
    return {"department_id":dept_id,"clinical_date":d.isoformat(),"timezone":str(CLINICAL_TZ),
      "source":source,"slots":[roster_public_slot(x) for x in slots],
      "currently_on_duty":[roster_public_slot(x) for x in slots if current_min is not None and x.start_minute<=current_min<x.end_minute],
      "gaps":roster_gap_ranges(slots),"has_day_override":source=="daily"}

def roster_date(text_date):
    try:return date.fromisoformat(text_date)
    except ValueError:fail(422,"صيغة التاريخ المطلوبة YYYY-MM-DD")

@app.get("/api/rosters/{department_id}")
def get_roster(department_id:int,req:Request,day:str="",db:Session=Depends(get_db)):
    roster_authorized_reader(req,db,department_id)
    d=roster_date(day) if day else date.fromisoformat(clinical_window()[2])
    return roster_response(db,department_id,d)

@app.get("/api/rosters/{department_id}/weekly/{weekday}")
def get_roster_weekly(department_id:int,weekday:int,req:Request,db:Session=Depends(get_db)):
    roster_authorized_reader(req,db,department_id)
    if not 0<=weekday<=6:fail(422,"اليوم يجب أن يكون بين 0 و6")
    rows=db.scalars(select(RosterSlot).where(RosterSlot.department_id==department_id,
      RosterSlot.kind=="weekly",RosterSlot.weekday==weekday,RosterSlot.active==True)
      .order_by(RosterSlot.start_minute,RosterSlot.id)).all()
    return {"department_id":department_id,"weekday":weekday,"slots":[roster_public_slot(x) for x in rows],"gaps":roster_gap_ranges(rows)}

def replace_roster(db,actor,department_id,mode,slots,weekday=None,clinical_date=None):
    if mode=="daily":
        override=db.scalar(select(RosterDayOverride).where(RosterDayOverride.department_id==department_id,
                                  RosterDayOverride.clinical_date==clinical_date))
        if not override:
            override=RosterDayOverride(department_id=department_id,clinical_date=clinical_date,updated_by=actor.id)
            db.add(override)
        else:
            override.updated_by=actor.id;override.updated_at=now()
    conditions=[RosterSlot.department_id==department_id,RosterSlot.kind==mode,RosterSlot.active==True]
    if mode=="weekly":conditions.append(RosterSlot.weekday==weekday)
    else:conditions.append(RosterSlot.clinical_date==clinical_date)
    existing=db.scalars(select(RosterSlot).where(*conditions).with_for_update()).all()
    for old in existing:old.active=False;old.retired_at=now()
    for shift in slots:
        begin,finish=slot_bounds(shift)
        db.add(RosterSlot(department_id=department_id,kind=mode,weekday=weekday if mode=="weekly" else None,
            clinical_date=clinical_date if mode=="daily" else None,start_minute=begin,end_minute=finish,
            doctor_name=clean(shift.doctor_name,140),phone=shift.phone,contact_role=shift.contact_role,
            note=clean(shift.note,200),created_by=actor.id))
    audit(db,actor.id,"roster_replaced",f"department={department_id}",
          f"mode={mode};weekday={weekday};date={clinical_date};slots={len(slots)}")
    db.commit()

@app.put("/api/rosters/{department_id}/weekly/{weekday}")
def put_weekly_roster(department_id:int,weekday:int,data:RosterReplaceInput,req:Request,db:Session=Depends(get_db)):
    actor=roster_authorized_writer(req,db,department_id)
    if not 0<=weekday<=6:fail(422,"اليوم يجب أن يكون بين 0 و6")
    replace_roster(db,actor,department_id,"weekly",data.slots,weekday=weekday)
    return get_roster_weekly(department_id,weekday,req,db)

@app.put("/api/rosters/{department_id}/day/{clinical_date}")
def put_day_roster(department_id:int,clinical_date:str,data:RosterReplaceInput,req:Request,db:Session=Depends(get_db)):
    actor=roster_authorized_writer(req,db,department_id)
    d=roster_date(clinical_date)
    replace_roster(db,actor,department_id,"daily",data.slots,clinical_date=d)
    return roster_response(db,department_id,d)

@app.delete("/api/rosters/{department_id}/day/{clinical_date}")
def delete_day_override(department_id:int,clinical_date:str,req:Request,db:Session=Depends(get_db)):
    actor=roster_authorized_writer(req,db,department_id);d=roster_date(clinical_date)
    override=db.scalar(select(RosterDayOverride).where(RosterDayOverride.department_id==department_id,
                                     RosterDayOverride.clinical_date==d))
    if not override:fail(404,"لا يوجد تعديل يومي لهذا التاريخ")
    for old in db.scalars(select(RosterSlot).where(RosterSlot.department_id==department_id,
                      RosterSlot.kind=="daily",RosterSlot.clinical_date==d,RosterSlot.active==True)):
        old.active=False;old.retired_at=now()
    db.delete(override)
    audit(db,actor.id,"roster_override_deleted",f"department={department_id}",d.isoformat())
    db.commit()
    return roster_response(db,department_id,d)

@app.get("/api/contacts/{department_id}")
def contacts(department_id:int,req:Request,db:Session=Depends(get_db)):
    user=get_user(req,db)
    selected_department(req,db,user)  # only participating doctors may see directory
    d=db.get(Department,department_id)
    if not d or not d.active:fail(404,"القسم غير موجود")
    return [{"id":c.id,"doctor":c.doctor_name,"phone":c.phone,"category":c.category,"note":c.note}
            for c in db.scalars(select(Contact).where(Contact.department_id==department_id,Contact.enabled==True))]

class ContactData(BaseModel):
    doctor_name:str=Field(min_length=2,max_length=140)
    phone:str=Field(min_length=6,max_length=40)
    category:Literal["consultant","on_call","backup"]="consultant"
    note:str=Field(default="",max_length=200)

@app.post("/api/contacts/{department_id}")
def add_contact(department_id:int,data:ContactData,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db)
    selected_department(req,db,user)
    manager_only(db,user,department_id)
    if not re.fullmatch(r"\+?[0-9 ()\-]{6,40}",data.phone):fail(422,"صيغة رقم الهاتف غير صحيحة")
    c=Contact(department_id=department_id,doctor_name=clean(data.doctor_name,140),phone=data.phone,
              category=data.category,note=clean(data.note,200),created_by=user.id)
    db.add(c);db.flush()
    audit(db,user.id,"contact_created",c.id,"dept="+str(department_id))
    db.commit()
    return {"id":c.id}

@app.delete("/api/contacts/{contact_id}")
def remove_contact(contact_id:int,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);c=db.get(Contact,contact_id)
    if not c:fail(404,"الرقم غير موجود")
    manager_only(db,user,c.department_id)
    c.enabled=False
    audit(db,user.id,"contact_deactivated",contact_id)
    db.commit()
    return {"ok":True}

class PhoneLogData(BaseModel):
    doctor_name: str=Field(min_length=2,max_length=140)
    result: Literal["answered","no_answer","requested_app","assessment_agreed"]
    note: str=Field(default="",max_length=1000)

@app.post("/api/consultations/{consultation_id}/calls")
def log_call(consultation_id:int,data:PhoneLogData,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);dept=selected_department(req,db,user)
    c=permitted_consult(db,consultation_id,user,dept)
    if c.status=="closed":fail(409,"الاستشارة مغلقة")
    entry=CallLog(consultation_id=c.id,actor_id=user.id,contacted_dept_id=c.current_dept_id,
                  doctor_name=clean(data.doctor_name,140),result=data.result,note=clean(data.note,1000))
    db.add(entry)
    event_record(db,c,user,dept,"phone_followup",data.result + " — " + data.doctor_name)
    db.commit()
    return {"ok":True}

@app.get("/print/{consultation_id}",response_class=HTMLResponse)
def print_consultation(consultation_id:int,req:Request,db:Session=Depends(get_db)):
    user=get_user(req,db);dept=selected_department(req,db,user)
    c=permitted_consult(db,consultation_id,user,dept)
    events=db.scalars(select(Event).where(Event.consultation_id==c.id, Event.type!="viewed").order_by(Event.id)).all()
    report=Environment(autoescape=select_autoescape(["html"])).from_string((ROOT/"report.html").read_text(encoding="utf-8"))
    context={"c":c,"origin":department_data(db.get(Department,c.requester_dept_id),db),
             "destination":department_data(db.get(Department,c.current_dept_id),db),
             "events":[{"type":e.type,"body":e.body,"author":db.get(User,e.actor_id).full_name,
                        "department":db.get(Department,e.actor_dept_id).name,"at":e.created_at.strftime("%Y-%m-%d %H:%M")}
                        for e in events if e.type in {"reply","completed","followup_requested","information_requested","information_provided","investigations_requested","assessment_requested","transfer_accepted","transfer_rejected","note"}],
             "created_by":db.get(User,c.created_by).full_name,
             "closed_by": next((db.get(User,e.actor_id).full_name for e in reversed(events) if e.type=="closed"),""),
             "print_at":now().strftime("%Y-%m-%d %H:%M")}
    audit(db,user.id,"report_print_view",c.code)
    db.commit()
    return HTMLResponse(report.render(**context))

class NewHospital(BaseModel):
    name:str=Field(min_length=2,max_length=150)
    code:str=Field(min_length=2,max_length=30)
class NewDepartment(BaseModel):
    hospital_id:int
    name:str=Field(min_length=2,max_length=140)
    parent_id:int|None=None
class NewUser(BaseModel):
    username:str=Field(min_length=3,max_length=80)
    full_name:str=Field(min_length=3,max_length=140)
    password:str=Field(min_length=12,max_length=120)
    is_admin:bool=False
class NewMembership(BaseModel):
    user_id:int
    department_id:int
    role:Literal["doctor","department_admin"]="doctor"

@app.get("/api/admin/users")
def admin_users(req:Request,db:Session=Depends(get_db)):
    user=get_user(req,db);admin_only(user)
    return [{**user_data(u),"active":u.active} for u in db.scalars(select(User).order_by(User.full_name))]

class AdminUserEdit(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=80)
    full_name: str | None = Field(default=None, min_length=3, max_length=140)
    active: bool | None = None
    is_admin: bool | None = None

@app.patch("/api/admin/users/{target_id}")
def admin_edit_user(target_id:int,data:AdminUserEdit,req:Request,db:Session=Depends(get_db)):
    actor=writing_access(req,db);admin_only(actor)
    target=db.get(User,target_id)
    if not target:fail(404,"المستخدم غير موجود")
    if target.id==actor.id and (data.active is False or data.is_admin is False):
        fail(409,"لا يمكن إيقاف حسابك أو سحب صلاحية الإدارة من نفسك")
    updates=[]
    if data.username is not None:
        new_username=data.username.strip().lower()
        if not re.fullmatch(r"[a-z0-9._-]{3,80}",new_username):fail(422,"اسم الدخول يجب أن يكون لاتينياً")
        if new_username!=target.username:
            if db.scalar(select(User).where(User.username==new_username,User.id!=target.id)):
                fail(409,"اسم الدخول مستخدم مسبقاً")
            target.username=new_username;updates.append("username")
            # The identity changed; force a fresh login everywhere with the new name.
            for sess in db.scalars(select(LoginSession).where(LoginSession.user_id==target.id)).all():db.delete(sess)
    if data.full_name is not None:
        target.full_name=clean(data.full_name,140);updates.append("name")
    if data.active is not None and data.active!=target.active:
        target.active=data.active;updates.append("active="+str(data.active))
        if not data.active:
            for sess in db.scalars(select(LoginSession).where(LoginSession.user_id==target.id)).all():db.delete(sess)
    if data.is_admin is not None and data.is_admin!=target.is_admin:
        target.is_admin=data.is_admin;updates.append("admin="+str(data.is_admin))
    if not updates: return {"ok":True,"updated":[]}
    audit(db,actor.id,"admin_user_updated",target.id,", ".join(updates))
    db.commit()
    return {"ok":True,"updated":updates}

class AdminSetPassword(BaseModel):
    new_password: str = Field(min_length=14, max_length=120)

@app.post("/api/admin/users/{target_id}/set-password")
def admin_set_password(target_id:int,data:AdminSetPassword,req:Request,db:Session=Depends(get_db)):
    """Super Admin sets/resets any account's password. All of that account's active
    sessions are revoked so the new password takes effect immediately."""
    actor=writing_access(req,db);admin_only(actor)
    target=db.get(User,target_id)
    if not target:fail(404,"المستخدم غير موجود")
    if len(set(data.new_password))<8:fail(422,"كلمة المرور الجديدة ضعيفة جداً")
    target.password_hash=pwd.hash(data.new_password)
    for sess in db.scalars(select(LoginSession).where(LoginSession.user_id==target.id)).all():
        db.delete(sess)
    audit(db,actor.id,"admin_password_reset",target.id)
    db.commit()
    return {"ok":True}

class AdminHospitalEdit(BaseModel):
    name:str|None=Field(default=None,min_length=2,max_length=150)
    active:bool|None=None

@app.patch("/api/admin/hospitals/{hospital_id}")
def admin_edit_hospital(hospital_id:int,data:AdminHospitalEdit,req:Request,db:Session=Depends(get_db)):
    actor=writing_access(req,db);admin_only(actor)
    h=db.get(Hospital,hospital_id)
    if not h:fail(404,"المشفى غير موجود")
    updates=[]
    if data.name is not None:
        name=clean(data.name,150)
        if db.scalar(select(Hospital).where(Hospital.name==name,Hospital.id!=h.id)):
            fail(409,"اسم المشفى مستخدم")
        h.name=name;updates.append("name")
    if data.active is not None and data.active!=h.active:
        if not data.active and db.scalar(select(Department.id).where(Department.hospital_id==h.id,Department.active==True).limit(1)) is not None:
            fail(409,"يجب تعطيل أقسام المشفى الفعالة أولاً بعد إنهاء الاستشارات")
        h.active=data.active;updates.append("active="+str(data.active))
    if updates:
        audit(db,actor.id,"admin_hospital_updated",h.id,", ".join(updates));db.commit()
    return {"ok":True,"updated":updates}

# Executive analytics: administrative counts only; this endpoint never returns patient identifiers.
# Dates mean UTC timestamps. 'to' is inclusive calendar date.
def date_filter(start_date:str,end_date:str):
    try:
        start=date.fromisoformat(start_date) if start_date else None
        end=date.fromisoformat(end_date) if end_date else None
    except ValueError:fail(422,"صيغة التاريخ يجب أن تكون YYYY-MM-DD")
    if start and end and end<start:fail(422,"تاريخ النهاية يسبق تاريخ البداية")
    if start and end and (end-start).days>366*5:fail(422,"الحد الأقصى خمس سنوات")
    return (datetime.combine(start,time.min,tzinfo=timezone.utc) if start else None,
            datetime.combine(end+timedelta(days=1),time.min,tzinfo=timezone.utc) if end else None)

def _utc(v):return v if v.tzinfo else v.replace(tzinfo=timezone.utc)

def generate_analytics(db:Session,from_date:str="",to_date:str="",hospital_id:int|None=None,department_id:int|None=None):
    start,end=date_filter(from_date,to_date)
    if hospital_id is not None and not db.get(Hospital,hospital_id):fail(404,"المشفى غير موجود")
    if department_id is not None:
        dep=db.get(Department,department_id)
        if not dep:fail(404,"القسم غير موجود")
        if hospital_id is not None and dep.hospital_id!=hospital_id:fail(422,"القسم لا يتبع المشفى المختار")
    hospital_map={h.id:h for h in db.scalars(select(Hospital)).all()}
    department_map={d.id:d for d in db.scalars(select(Department)).all()}
    rows=db.scalars(select(Consultation)).all()
    # Filter by original requesting service: a stable, non-duplicating denominator.
    def eligible(c):
        d=department_map.get(c.requester_dept_id)
        if not d:return False
        t=_utc(c.created_at)
        return (not start or t>=start) and (not end or t<end) and (hospital_id is None or d.hospital_id==hospital_id) and (department_id is None or d.id==department_id)
    rows=[c for c in rows if eligible(c)]
    ids=[c.id for c in rows]
    events=db.scalars(select(Event).where(Event.consultation_id.in_(ids)).order_by(Event.created_at,Event.id)).all() if ids else []
    transfers=db.scalars(select(Transfer).where(Transfer.consultation_id.in_(ids))).all() if ids else []
    first_reply={}
    for e in events:
        if e.type=="reply" and e.consultation_id not in first_reply:first_reply[e.consultation_id]=_utc(e.created_at)
    clinical_start, clinical_end, clinical_label = clinical_window()
    # A transfer is counted once per submitted transfer request (acceptance is reported separately).
    def metrics(group):
        n=len(group);times=sorted(max(0,(_utc(first_reply[c.id])-_utc(c.created_at)).total_seconds()/60) for c in group if c.id in first_reply)
        median=round((times[(len(times)-1)//2]+times[len(times)//2])/2,1) if times else None
        return {"total":n,"open":sum(c.status!="closed" for c in group),
                "awaiting_reply":sum(c.status=="active" and c.action_owner_dept_id!=c.requester_dept_id for c in group),
                "awaiting_sender_closure":sum(c.status=="completed" for c in group),
                "closed":sum(c.status=="closed" for c in group),
                "created_current_clinical_day":sum(clinical_start <= aware(c.created_at) < clinical_end for c in group),
                "open_carried_over":sum(c.status!="closed" and aware(c.created_at)<clinical_start for c in group),
                "closed_current_clinical_day":sum(c.closed_at is not None and clinical_start <= aware(c.closed_at) < clinical_end for c in group),
                "urgent":sum(c.priority in ("urgent","emergency") for c in group),
                "emergency":sum(c.priority=="emergency" for c in group),
                "with_first_reply":len(times),"first_reply_median_minutes":median}
    by_hosp={};by_dept={}
    for c in rows:
        d=department_map[c.requester_dept_id]
        by_hosp.setdefault(d.hospital_id,[]).append(c)
        by_dept.setdefault(d.id,[]).append(c)
    hosp_data=[{"hospital_id":hid,"hospital_name":hospital_map[hid].name,**metrics(group)} for hid,group in sorted(by_hosp.items())]
    dept_data=[{"hospital_id":department_map[did].hospital_id,"department_id":did,"department_name":department_map[did].name,**metrics(group)} for did,group in sorted(by_dept.items())]
    return {"generated_at":serial_date(now()),"time_zone":"UTC","clinical_day":{"day":clinical_label,"timezone":str(CLINICAL_TZ),"starts_at":serial_date(clinical_start),"ends_at_exclusive":serial_date(clinical_end)},"date_basis":"consultation_created_at","filters":{"from":from_date,"to":to_date,"hospital_id":hospital_id,"department_id":department_id},
      "overall":{**metrics(rows),"transfers_requested":len(transfers),"transfers_accepted":sum(t.status=="accepted" for t in transfers),
                 "transfers_rejected":sum(t.status=="rejected" for t in transfers),
                 "participating_hospitals":len(by_hosp),"requesting_departments":len(by_dept)},
      "by_hospital":hosp_data,"by_requesting_department":dept_data,
      "definitions":{"total":"عدد الاستشارات التي أنشأتها الجهات الطالبة في الفترة المحددة، وليس عدد كل الاستشارات الواردة إلى المشفى",
                     "open":"الطلبات التي لم تُغلق نهائياً (تشمل المعلقة والمجاب عنها)",
                     "awaiting_reply":"الاستشارات النشطة ومسؤولية الإجراء الحالية على قسم غير القسم الطالب",
                     "awaiting_sender_closure":"أنهى المستقبِل الرد وما زال الإغلاق النهائي لدى القسم الطالب",
                     "first_reply_median_minutes":"وسيط المدة من إنشاء الطلب حتى أول رد طبي مسجل، للطلبات التي تلقت رداً فقط؛ ليس وقت إنهاء الاستشارة",
                     "transfers":"التحويلات مرتبطة بالطلبات الداخلة بالفترة، حتى لو جرى التحويل لاحقاً",
                     "clinical_cohort":"مقاييس اليوم الطبي ضمن مجموعة الاستشارات المُنشأة بالفترة المحددة فقط؛ أزل فلتر التواريخ لرؤية الإجماليات التراكمية"},
      "publication_warning":"للاستخدام الإداري الداخلي فقط؛ النشر الخارجي يتطلب مراجعة الخصوصية والجودة وإخفاء المجموعات الصغيرة."}

@app.get("/api/admin/analytics")
def admin_analytics(req:Request,from_date:str="",to_date:str="",hospital_id:int|None=None,department_id:int|None=None,db:Session=Depends(get_db)):
    actor=get_user(req,db);admin_only(actor)
    result=generate_analytics(db,from_date,to_date,hospital_id,department_id)
    audit(db,actor.id,"analytics_view","aggregate",f"from={from_date};to={to_date};hospital={hospital_id};department={department_id}")
    db.commit()
    return result

@app.get("/api/admin/analytics/export.csv")
def admin_analytics_export(req:Request,from_date:str="",to_date:str="",hospital_id:int|None=None,department_id:int|None=None,db:Session=Depends(get_db)):
    actor=get_user(req,db);admin_only(actor)
    result=generate_analytics(db,from_date,to_date,hospital_id,department_id)
    columns=["hospital_id","hospital_name","department_id","department_name","total","open","awaiting_reply","awaiting_sender_closure","closed","urgent","emergency","with_first_reply","first_reply_median_minutes"]
    stream=io.StringIO();writer=csv.writer(stream);writer.writerow(columns)
    for d in result["by_requesting_department"]:
        h=db.get(Hospital,d["hospital_id"])
        row={"hospital_id":d["hospital_id"],"hospital_name":h.name,"department_id":d["department_id"],"department_name":d["department_name"],**d}
        def esc(value):
            if isinstance(value,str) and value.lstrip().startswith(("=","+","-","@")):return "'"+value
            return value
        writer.writerow([esc(row.get(key,"")) for key in columns])
    audit(db,actor.id,"analytics_export","aggregate",f"from={from_date};to={to_date};hospital={hospital_id};department={department_id}")
    db.commit()
    payload="\ufeff"+stream.getvalue()
    return Response(content=payload,media_type="text/csv; charset=utf-8",headers={"Content-Disposition":"attachment; filename=wasl-aggregate-analytics.csv","X-Content-Type-Options":"nosniff"})

@app.get("/api/admin/audit")
def admin_recent_audit(req:Request,limit:int=50,db:Session=Depends(get_db)):
    actor=get_user(req,db);admin_only(actor)
    if limit<1 or limit>100:fail(422,"العدد بين 1 و100")
    items=db.scalars(select(Audit).order_by(Audit.id.desc()).limit(limit)).all()
    return [{"id":a.id,"actor_id":a.actor_id,"action":a.action,"target":a.target,"at":serial_date(a.created_at)} for a in items]

@app.post("/api/admin/hospitals")
def admin_hospital(data:NewHospital,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);admin_only(user)
    if db.scalar(select(Hospital).where(or_(Hospital.name==data.name,Hospital.code==data.code))):fail(409,"المشفى موجود مسبقاً")
    h=Hospital(name=clean(data.name,150),code=clean(data.code,30));db.add(h);db.flush();audit(db,user.id,"hospital_created",h.id);db.commit()
    return {"id":h.id}

@app.post("/api/admin/departments")
def admin_department(data:NewDepartment,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);admin_only(user)
    h=db.get(Hospital,data.hospital_id)
    if not h:fail(404,"المشفى غير موجود")
    if data.parent_id:
        parent=db.get(Department,data.parent_id)
        if not parent or parent.hospital_id!=h.id:fail(400,"القسم الأب غير صالح")
    if db.scalar(select(Department).where(Department.hospital_id==h.id,Department.name==data.name)):
        fail(409,"القسم موجود مسبقاً")
    d=Department(hospital_id=h.id,name=clean(data.name,140),parent_id=data.parent_id)
    db.add(d);db.flush();audit(db,user.id,"department_created",d.id);db.commit()
    return {"id":d.id}

class HospitalDepartmentEdit(BaseModel):
    name: str|None = Field(default=None, min_length=2, max_length=140)
    parent_id: int|None = None
    active: bool|None = None

class HospitalManagerGrant(BaseModel):
    user_id: int
    active: bool=True

@app.get("/api/hospitals/{hospital_id}/departments")
def hospital_departments(hospital_id:int,req:Request,db:Session=Depends(get_db)):
    user=get_user(req,db);hospital_manager_only(db,user,hospital_id)
    return [department_data(d,db) for d in db.scalars(select(Department).where(Department.hospital_id==hospital_id).order_by(Department.name))]

@app.post("/api/hospitals/{hospital_id}/departments",status_code=201)
def hospital_add_department(hospital_id:int,data:NewDepartment,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);hospital_manager_only(db,user,hospital_id)
    if data.hospital_id!=hospital_id:fail(422,"المشفى المحدد لا يطابق طلب الإنشاء")
    name=clean(data.name,140)
    if len(name)<2:fail(422,"اسم القسم قصير")
    validate_parent(db,hospital_id,data.parent_id)
    if db.scalar(select(Department).where(Department.hospital_id==hospital_id,Department.name==name)):
        fail(409,"القسم موجود مسبقاً في هذا المشفى")
    d=Department(hospital_id=hospital_id,name=name,parent_id=data.parent_id,active=True)
    db.add(d);db.flush();audit(db,user.id,"hospital_dept_created",d.id,"hospital="+str(hospital_id));db.commit()
    return department_data(d,db)

@app.patch("/api/hospitals/{hospital_id}/departments/{department_id}")
def hospital_edit_department(hospital_id:int,department_id:int,data:HospitalDepartmentEdit,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);hospital_manager_only(db,user,hospital_id)
    d=db.get(Department,department_id)
    if not d or d.hospital_id!=hospital_id:fail(404,"القسم غير موجود في هذا المشفى")
    # Require explicit name/parent changes; omitted parent means preserve (use a separate remove_parent action later).
    if data.name is not None:
        name=clean(data.name,140)
        if len(name)<2:fail(422,"اسم القسم قصير")
        if db.scalar(select(Department).where(Department.hospital_id==hospital_id,Department.name==name,Department.id!=d.id)):
            fail(409,"يوجد قسم آخر بنفس الاسم")
        d.name=name
    if data.parent_id is not None:
        validate_parent(db,hospital_id,data.parent_id,d.id)
        d.parent_id=data.parent_id
    if data.active is not None and data.active != d.active:
        if not data.active:
            if db.scalar(select(Department).where(Department.parent_id==d.id,Department.active==True)):
                fail(409,"يجب تعطيل الأقسام الفرعية التابعة أولاً")
            outstanding= db.scalar(select(Consultation.id).where(Consultation.status!='closed',or_(Consultation.requester_dept_id==d.id, Consultation.current_dept_id==d.id,Consultation.action_owner_dept_id==d.id,Consultation.initial_receiver_dept_id==d.id)).limit(1))
            if outstanding is not None:fail(409,"لا يمكن تعطيل قسم لديه استشارات لم تُغلق بعد")
        else:
            if d.parent_id:
                parent=db.get(Department,d.parent_id)
                if not parent.active:fail(409,"فعّل القسم الأب أولاً")
        d.active=data.active
    audit(db,user.id,"hospital_dept_updated",d.id,"hospital="+str(hospital_id))
    db.commit();return department_data(d,db)

@app.post("/api/admin/hospitals/{hospital_id}/managers")
def grant_hospital_manager(hospital_id:int,data:HospitalManagerGrant,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);admin_only(user)
    h=db.get(Hospital,hospital_id);doctor=db.get(User,data.user_id)
    if not h or not doctor:fail(404,"المشفى أو المستخدم غير موجود")
    m=db.scalar(select(HospitalManager).where(HospitalManager.hospital_id==hospital_id,HospitalManager.user_id==doctor.id))
    if m:m.active=data.active
    else:db.add(HospitalManager(hospital_id=hospital_id,user_id=doctor.id,active=data.active))
    audit(db,user.id,"hospital_manager_granted" if data.active else "hospital_manager_revoked",doctor.id,"hospital="+str(hospital_id))
    db.commit();return {"ok":True}

@app.post("/api/admin/users")
def admin_user(data:NewUser,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);admin_only(user)
    username=data.username.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,80}",username):fail(422,"اسم الدخول يجب أن يكون لاتينياً")
    if db.scalar(select(User).where(User.username==username)):fail(409,"اسم الدخول مستخدم")
    u=User(username=username,full_name=clean(data.full_name,140),password_hash=pwd.hash(data.password),is_admin=data.is_admin)
    db.add(u);db.flush();audit(db,user.id,"user_created",u.id);db.commit()
    return {"id":u.id}

@app.get("/api/admin/memberships")
def admin_list_memberships(req:Request,db:Session=Depends(get_db)):
    """Super Admin overview: which user accounts belong to which department, and with
    what role. Passwords are Argon2-hashed and can never be displayed in plain text,
    by design — use POST /api/admin/users/{id}/set-password to assign a new one."""
    actor=get_user(req,db);admin_only(actor)
    rows=db.scalars(select(Membership).where(Membership.active==True)).all()
    users={u.id:u for u in db.scalars(select(User)).all()}
    return [{"user_id":m.user_id,"username":users[m.user_id].username,"full_name":users[m.user_id].full_name,
             "user_active":users[m.user_id].active,"department_id":m.department_id,"role":m.role}
            for m in rows if m.user_id in users]

@app.post("/api/admin/memberships")
def admin_membership(data:NewMembership,req:Request,db:Session=Depends(get_db)):
    """Clinical governance rule: a Doctor/Department-Admin account is tied to exactly
    one department. Super Admin accounts are exempt (they need no department at all).
    Assigning a non-admin account to a new department reassigns it — the previous
    department membership is deactivated, never left active alongside the new one."""
    user=writing_access(req,db);admin_only(user)
    u=db.get(User,data.user_id);d=db.get(Department,data.department_id)
    if not u or not d:fail(404,"المستخدم أو القسم غير موجود")
    existing=db.scalar(select(Membership).where(Membership.user_id==u.id,Membership.department_id==d.id))
    if not u.is_admin:
        others=db.scalars(select(Membership).where(Membership.user_id==u.id,Membership.department_id!=d.id,Membership.active==True)).all()
        for other in others:
            other.active=False
            audit(db,user.id,"membership_reassigned_away",u.id,"dept="+str(other.department_id))
    if existing:
        existing.active=True;existing.role=data.role
    else:db.add(Membership(user_id=u.id,department_id=d.id,role=data.role))
    audit(db,user.id,"membership_saved",u.id,"dept="+str(d.id)+" role="+data.role)
    db.commit();return {"ok":True}

@app.delete("/api/admin/memberships/{user_id}/{department_id}")
def admin_remove_membership(user_id:int,department_id:int,req:Request,db:Session=Depends(get_db)):
    user=writing_access(req,db);admin_only(user)
    m=db.scalar(select(Membership).where(Membership.user_id==user_id,Membership.department_id==department_id))
    if not m:fail(404,"العضوية غير موجودة")
    m.active=False;audit(db,user.id,"membership_revoked",user_id,"dept="+str(department_id));db.commit()
    return {"ok":True}
