"""Creates or replaces the bootstrap admin password. Run interactively from project root."""
import getpass
from sqlalchemy import select
from argon2 import PasswordHasher
from app.db import Base,engine,SessionLocal
from app.models import User
Base.metadata.create_all(engine)
username=input('Admin login (Latin letters): ').strip().lower()
name=input('Admin display name: ').strip()
password=getpass.getpass('New admin password (>=12 chars): ')
if len(password)<12 or not username or not name:raise SystemExit('Invalid input.')
with SessionLocal() as db:
    u=db.scalar(select(User).where(User.username==username))
    if not u:u=User(username=username,full_name=name,password_hash=PasswordHasher().hash(password),is_admin=True);db.add(u)
    else:u.password_hash=PasswordHasher().hash(password);u.is_admin=True;u.active=True
    db.commit()
print('Admin account configured. No clinical access unless assigned department membership.')
