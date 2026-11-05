"""Run: python -m scripts.bootstrap [--demo]  (run from project root)."""
import argparse, os
from sqlalchemy import select
from app.db import Base,engine,SessionLocal
from app.models import Hospital,Department,User,Membership,Consultation,Event,now
from argon2 import PasswordHasher

def add_hospital(db,name,code):
    h=db.scalar(select(Hospital).where(Hospital.code==code))
    if not h:
        h=Hospital(name=name,code=code);db.add(h);db.flush()
    return h

def add_department(db,h,name,parent=None):
    d=db.scalar(select(Department).where(Department.hospital_id==h.id,Department.name==name))
    if not d:
        d=Department(hospital_id=h.id,name=name,parent_id=parent.id if parent else None);db.add(d);db.flush()
    return d

p=argparse.ArgumentParser();p.add_argument('--demo',action='store_true',help='Creates ONLY FAKE users and a fake patient; testing only.')
a=p.parse_args()
Base.metadata.create_all(engine)
with SessionLocal() as db:
    university=add_hospital(db,'المشفى الجامعي بحلب','AUH')
    maternity=add_hospital(db,'مشفى التوليد الجامعي','AMH')
    cardiac=add_hospital(db,'مشفى جراحة القلب','ACH')
    internal=add_department(db,university,'الداخلية العامة')
    nephrology=add_department(db,university,'الداخلية الكلوية',internal)
    cardiology=add_department(db,university,'القلبية',internal)
    obstetrics=add_department(db,maternity,'التوليد')
    gyne=add_department(db,maternity,'الأمراض النسائية')
    anesthesia=add_department(db,maternity,'التخدير')
    cardiac_surg=add_department(db,cardiac,'جراحة القلب')
    icu=add_department(db,cardiac,'العناية المشددة')
    if a.demo:
        password=os.getenv('DEMO_PASSWORD','')
        if len(password)<12:raise SystemExit('Set DEMO_PASSWORD of >=12 chars. NEVER enable demo on real patient server.')
        ph=PasswordHasher()
        for username,name,dept in [('obdoctor','د. طبيب التوليد (تجريبي)',obstetrics),('internaldoctor','د. طبيب الداخلية (تجريبي)',internal),('nephdoctor','د. طبيب الكلوية (تجريبي)',nephrology),('cardiodoctor','د. طبيب القلبية (تجريبي)',cardiology)]:
            u=db.scalar(select(User).where(User.username==username))
            if not u:
                u=User(username=username,full_name=name,password_hash=ph.hash(password))
                db.add(u);db.flush()
            if not db.scalar(select(Membership).where(Membership.user_id==u.id, Membership.department_id==dept.id)):
                db.add(Membership(user_id=u.id,department_id=dept.id,role='department_admin'))
        if not db.scalar(select(Consultation).where(Consultation.code=='WASL-DEMO-001')):
            u=db.scalar(select(User).where(User.username=='obdoctor'))
            c=Consultation(code='WASL-DEMO-001', patient_name='مريضة افتراضية للاختبار',patient_ref='TEST-001',patient_age='29',floor='الثاني',unit='جناح الحمل عالي الخطورة',
             requester_dept_id=obstetrics.id,initial_receiver_dept_id=internal.id,current_dept_id=internal.id,
             action_owner_dept_id=internal.id,created_by=u.id, requested_doctors='د. طبيب التوليد (تجريبي)',
             priority='routine',clinical_summary='قصة افتراضية حصراً لا تتعلق بمريضة حقيقية.',question='استشارة افتراضية للتأكد من سير النظام؟')
            db.add(c);db.flush()
            db.add(Event(consultation_id=c.id,actor_id=u.id,actor_dept_id=obstetrics.id,type='created',body='طلب تجريبي'))
    db.commit()
print('Hospital/department structure created.' + (' FAKE demo users created.' if a.demo else ''))
