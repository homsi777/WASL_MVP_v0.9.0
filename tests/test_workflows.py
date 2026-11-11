import os
import tempfile
from pathlib import Path
DBFILE=Path(tempfile.gettempdir())/'wasl_tests_2026.sqlite'
DBFILE.unlink(missing_ok=True)
os.environ['DATABASE_URL']='sqlite:///'+str(DBFILE)
os.environ['UPLOAD_DIR']=str(Path(tempfile.gettempdir())/'wasl_test_uploads')
from fastapi.testclient import TestClient
from app.main import app,pwd
from app.db import SessionLocal,Base,engine
from app.models import User,Membership,Hospital,Department,Consultation,Event
import pytest

@pytest.fixture()
def setup():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        a=Hospital(name='مشفى التوليد',code='MAT');b=Hospital(name='المشفى الجامعي',code='UNI');db.add_all([a,b]);db.flush()
        obst=Department(hospital_id=a.id,name='التوليد');internal=Department(hospital_id=b.id,name='داخلية عامة');neph=Department(hospital_id=b.id,name='كلية');surgery=Department(hospital_id=b.id,name='جراحة');db.add_all([obst,internal,neph,surgery]);db.flush()
        ids={'ob':obst.id,'in':internal.id,'neph':neph.id,'surg':surgery.id}
        for name,dept_id,role in [('ob',obst.id,'department_admin'),('in',internal.id,'department_admin'),('neph',neph.id,'doctor'),('surg',surgery.id,'doctor')]:
            u=User(username=name,full_name='Doctor '+name,password_hash=pwd.hash('Training-Password-123!'))
            db.add(u);db.flush();db.add(Membership(user_id=u.id,department_id=dept_id,role=role))
        db.commit()
    with TestClient(app) as client:
        yield client,ids

class Actor:
    def __init__(self,client,name,dept):
        self.client=TestClient(app)
        self.client.__enter__()
        r=self.client.post('/api/auth/login',json={'username':name,'password':'Training-Password-123!'})
        assert r.status_code==200,r.text
        self.dept=dept
        self.csrf=r.json()['csrf']
    def call(self,method,path,json=None,**kwargs):
        headers={'X-Department-Id':str(self.dept),'X-CSRF-Token':self.csrf}
        return self.client.request(method,path,json=json,headers=headers,**kwargs)
    def close(self):self.client.__exit__(None,None,None)

def create(ob, in_id):
    return ob.call('POST','/api/consultations',{
      'patient_name':'مريضة تجريبية','patient_ref':'TEST-010','patient_age':'30',
      'receiver_department_id':in_id,'requested_doctors':'د. طبيب اختبار','priority':'urgent','floor':'الثاني',
      'question':'تقييم كُلوي تجريبي؟','clinical_summary':'الحالة افتراضية بالكامل'}).json()['id']

def test_lifecycle_transfer_and_security(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']);intern=Actor(client,'in',ids['in']);neph=Actor(client,'neph',ids['neph']);other=Actor(client,'surg',ids['surg'])
    try:
        c=create(ob,ids['in'])
        assert ob.call('GET','/api/consultations?folder=outgoing').json()['total']==1
        assert intern.call('GET','/api/consultations?folder=incoming').json()['total']==1
        assert other.call('GET',f'/api/consultations/{c}').status_code==403
        assert intern.call('GET',f'/api/consultations/{c}').status_code==200
        dashboard=intern.call('GET','/api/dashboard').json()['incoming']
        assert dashboard['unread']==0 and dashboard['action_required']==1
        r=intern.call('POST',f'/api/consultations/{c}/transfers',{'to_department_id':ids['neph'],'reason':'يحتاج تقييماً كلوياً'})
        assert r.status_code==200,r.text
        transfer=r.json()['transfer_id']
        c0=intern.call('GET',f'/api/consultations/{c}').json()['consultation']
        assert c0['current_dept_id']==ids['in'] and c0['action_owner_dept_id']==ids['neph']
        assert neph.call('POST',f'/api/transfers/{transfer}/decision',{'decision':'accept'}).status_code==200
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==403
        assert neph.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'تمت معاينة الحالة التجريبية'}).status_code==200
        assert neph.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==200
        assert neph.call('POST',f'/api/consultations/{c}/actions',{'action':'close'}).status_code==403
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'followup','body':'يرجى التوضيح'}).status_code==200
        # Old answer cannot be reused to complete the new follow-up request.
        assert neph.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==422
        assert neph.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'إجابة إضافية'}).status_code==200
        assert neph.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==200
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'close','body':'تمت مراجعة الجواب'}).status_code==200
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'note','body':'محاولة تعديل'}).status_code==409
        assert ob.call('GET',f'/print/{c}').status_code==200
        assert 'تقرير استشارة طبية' in ob.call('GET',f'/print/{c}').text
        assert other.call('GET',f'/print/{c}').status_code==403
    finally:
        for actor in (ob,intern,neph,other):actor.close()

def test_info_transfer_reject_and_csrf(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']);intern=Actor(client,'in',ids['in']);neph=Actor(client,'neph',ids['neph'])
    try:
        c=create(ob,ids['in'])
        r=intern.call('POST',f'/api/consultations/{c}/actions',{'action':'request_info','body':'التحاليل؟'})
        assert r.status_code==200
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'غير مسموح'}).status_code==403
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'provide_info','body':'لا تتوفر حالياً'}).status_code==200
        r=intern.call('POST',f'/api/consultations/{c}/transfers',{'to_department_id':ids['neph'],'reason':'يرجى التقييم'})
        tid=r.json()['transfer_id']
        assert neph.call('POST',f'/api/transfers/{tid}/decision',{'decision':'reject','reason':'خارج نطاق الكلوية'}).status_code==200
        assert intern.call('GET',f'/api/consultations/{c}').json()['consultation']['current_dept_id']==ids['in']
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'رد تجريبي'}).status_code==200
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==200
        assert ob.client.post(f'/api/consultations/{c}/actions',json={'action':'close'},headers={'X-Department-Id':str(ids['ob'])}).status_code==403
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'close'}).status_code==200
    finally:
        for actor in (ob,intern,neph):actor.close()

def test_contacts_permissions_and_uploaded_files(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']);intern=Actor(client,'in',ids['in']);other=Actor(client,'surg',ids['surg'])
    try:
        c=create(ob,ids['in'])
        assert other.call('POST',f'/api/contacts/{ids["in"]}',{'doctor_name':'Test','phone':'0933000000'}).status_code==403
        assert intern.call('POST',f'/api/contacts/{ids["in"]}',{'doctor_name':'Consultant Test','phone':'0933000000'}).status_code==200
        assert len(ob.call('GET',f'/api/contacts/{ids["in"]}').json())==1
        files={'file':('lab.pdf',b'%PDF-1.5\nTEST\n%%EOF','application/pdf')}
        response=ob.client.post(f'/api/consultations/{c}/attachments',headers={'X-Department-Id':str(ids['ob']),'X-CSRF-Token':ob.csrf},files=files)
        assert response.status_code==200,response.text
        aid=response.json()['id']
        assert other.call('GET',f'/api/attachments/{aid}').status_code==403
        assert intern.call('GET',f'/api/attachments/{aid}').status_code==200
        bad=ob.client.post(f'/api/consultations/{c}/attachments',headers={'X-Department-Id':str(ids['ob']),'X-CSRF-Token':ob.csrf},files={'file':('a.pdf',b'not a PDF','application/pdf')})
        assert bad.status_code==415
    finally:
        for actor in (ob,intern,other):actor.close()

def test_idempotent_create_and_patient_movement(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']);intern=Actor(client,'in',ids['in'])
    try:
        body={'patient_name':'مريضة تجريبية','patient_ref':'TEST-019','receiver_department_id':ids['in'],'requested_doctors':'د. طبيب اختبار',
              'question':'طلب تجريبي واضح','clinical_summary':'قصة سريرية تجريبية','idempotency_key':'same-client-request-2026'}
        x=ob.call('POST','/api/consultations',body)
        y=ob.call('POST','/api/consultations',body)
        assert x.status_code==201 and y.status_code==201 and x.json()['id']==y.json()['id']
        c=x.json()['id']
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==422
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'patient_returned'}).status_code==409
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'request_assessment','body':'يرجى إحضار المريضة'}).status_code==200
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'patient_arrived'}).status_code==200
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'تمت المعاينة'}).status_code==200
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'patient_returned'}).status_code==200
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==200
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'close'}).status_code==200
    finally:
        ob.close();intern.close()

def test_dashboard_filters_password_change_and_missing_department(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']);intern=Actor(client,'in',ids['in'])
    try:
        c1=create(ob,ids['in'])
        c2=ob.call('POST','/api/consultations',{
          'patient_name':'مريضة وهمية ثانية','patient_ref':'TEST-011',
          'receiver_department_id':ids['in'],'requested_doctors':'د. طبيب اختبار','priority':'routine','floor':'الرابع',
          'unit':'الجناح ج','question':'سؤال تجريبي لا معنى طبي له',
          'clinical_summary':'قصة اختبار مؤلفة'}).json()['id']
        assert c1 != c2
        assert intern.call('GET','/api/dashboard').json()['incoming']['total']==2
        filtered=intern.call('GET','/api/dashboard?floor=الرابع&unit=الجناح%20ج').json()
        assert filtered['incoming']['total']==1 and filtered['incoming']['awaiting_response']==1
        opts=intern.call('GET','/api/dashboard/filter-options').json()
        assert 'الرابع' in opts['floors'] and 'الجناح ج' in opts['units']
        r=intern.call('GET','/api/consultations?unit=الجناح%20ج').json()
        assert r['total']==1 and r['items'][0]['id']==c2
        assert client.get('/api/dashboard').status_code==401
        # Authenticated but no department header should produce 400 (not 500).
        assert intern.client.get('/api/dashboard').status_code==400
        # Self-service password change is Super Admin only; a non-admin account is
        # rejected regardless of whether the current password supplied is correct.
        bad=ob.call('POST','/api/auth/change-password',{'current_password':'nope','new_password':'Even-Better-Password-2027!'})
        assert bad.status_code==403
        still_blocked=ob.call('POST','/api/auth/change-password',{'current_password':'Training-Password-123!','new_password':'Even-Better-Password-2027!'})
        assert still_blocked.status_code==403
        assert ob.call('GET','/api/dashboard').status_code==200
        with SessionLocal() as db:
            db.add(User(username='superadmin_pwtest',full_name='Admin PW Test',password_hash=pwd.hash('Training-Password-123!'),is_admin=True))
            db.commit()
        adm=Actor(client,'superadmin_pwtest',ids['ob'])
        try:
            good=adm.call('POST','/api/auth/change-password',{'current_password':'Training-Password-123!','new_password':'Even-Better-Password-2027!'})
            assert good.status_code==200,good.text
            new=TestClient(app)
            with new:
                assert new.post('/api/auth/login',json={'username':'superadmin_pwtest','password':'Training-Password-123!'}).status_code==401
                assert new.post('/api/auth/login',json={'username':'superadmin_pwtest','password':'Even-Better-Password-2027!'}).status_code==200
        finally:
            adm.close()
    finally:
        ob.close();intern.close()

def test_hospital_department_manager_and_cross_hospital_isolation(setup):
    client,ids=setup
    from app.models import HospitalManager
    from sqlalchemy import select
    with SessionLocal() as db:
        university=db.scalar(select(Hospital).where(Hospital.code=='UNI'))
        maternity=db.scalar(select(Hospital).where(Hospital.code=='MAT'))
        internal=db.scalar(select(User).where(User.username=='in'))
        obstetric=db.scalar(select(User).where(User.username=='ob'))
        db.add(HospitalManager(hospital_id=university.id,user_id=internal.id,active=True))
        db.commit(); uh=university.id; mh=maternity.id
    in_actor=Actor(client,'in',ids['in']); ob_actor=Actor(client,'ob',ids['ob'])
    try:
        assert uh in in_actor.call('GET','/api/directory').json()['managed_hospital_ids']
        assert mh not in in_actor.call('GET','/api/directory').json()['managed_hospital_ids']
        assert ob_actor.call('GET',f'/api/hospitals/{uh}/departments').status_code==403
        assert in_actor.call('POST',f'/api/hospitals/{mh}/departments',{'name':'غير مصرح','hospital_id':mh}).status_code==403
        assert in_actor.call('POST',f'/api/hospitals/{uh}/departments',{'name':'قلب جراحي','hospital_id':mh}).status_code==422
        bad_parent=in_actor.call('POST',f'/api/hospitals/{uh}/departments',{'name':'قسم فرعي خاطئ','hospital_id':uh,'parent_id':ids['ob']})
        assert bad_parent.status_code==422,bad_parent.text
        r=in_actor.call('POST',f'/api/hospitals/{uh}/departments',{'name':'الداخلية الدموية','hospital_id':uh,'parent_id':ids['in']})
        assert r.status_code==201,r.text
        hematology=r.json()['id']
        assert in_actor.call('POST',f'/api/hospitals/{uh}/departments',{'name':'الداخلية الدموية','hospital_id':uh,'parent_id':ids['in']}).status_code==409
        # New department appears as valid destination without restart or database migration.
        assert hematology in [d['id'] for d in in_actor.call('GET','/api/directory').json()['departments']]
        # No user gets automatic clinical access just because they manage the hospital.
        assert in_actor.call('GET',f'/api/contacts/{hematology}').status_code==200 # permitted network directory lookup
        assert in_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{hematology}',{'parent_id':hematology}).status_code==422
        assert in_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{ids["in"]}',{'parent_id':hematology}).status_code==422
        assert in_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{hematology}',{'name':'الأمراض الدموية'}).status_code==200
        assert in_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{hematology}',{'active':False}).status_code==200
        assert hematology not in [d['id'] for d in in_actor.call('GET','/api/directory').json()['departments']]
        assert in_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{hematology}',{'active':True}).status_code==200
        # Make an outstanding consultation to the new department; it cannot be deactivated.
        c=ob_actor.call('POST','/api/consultations',{'patient_name':'مريضة وهمية','patient_ref':'TST-HEM','receiver_department_id':hematology,'requested_doctors':'د. طبيب اختبار','clinical_summary':'حالة افتراضية فقط','question':'استشارة تجريبية فقط'})
        assert c.status_code==201,c.text
        assert in_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{hematology}',{'active':False}).status_code==409
        # Other hospital admins must not mutate university directory.
        assert ob_actor.call('PATCH',f'/api/hospitals/{uh}/departments/{hematology}',{'name':'تعديل من خارج المشفى'}).status_code==403
    finally:
        in_actor.close(); ob_actor.close()

def test_free_text_unit_and_per_consultation_requester(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob'])
    intern=Actor(client,'in',ids['in'])
    try:
        payload={'patient_name':'مريضة وهمية','patient_ref':'DEMO-UNT-15',
                 'receiver_department_id':ids['in'],'clinical_summary':'ملخص سريري تجريبي فقط',
                 'question':'استشارة تجربة الاسم والوحدة',
                 'floor':'الطابق السابع',
                 'unit':'وحدة غير موجودة بالقوائم',
                 'requested_doctors':'د. فاطمة إبراهيم'}
        r=ob.call('POST','/api/consultations',payload)
        assert r.status_code==201,r.text
        c=r.json()['id']
        details=ob.call('GET',f'/api/consultations/{c}')
        assert details.status_code==200,details.text
        doc=details.json()['consultation']
        assert doc['unit']=='وحدة غير موجودة بالقوائم'
        assert doc['requested_doctors']=='د. فاطمة إبراهيم'
        other=payload.copy();other['patient_ref']='DEMO-UNT-16';other['requested_doctors']='د. ياسر عثمان'
        r2=ob.call('POST','/api/consultations',other)
        assert r2.status_code==201
        doc2=ob.call('GET',f"/api/consultations/{r2.json()['id']}").json()['consultation']
        assert doc2['requested_doctors']=='د. ياسر عثمان'
        assert doc['requested_doctors']!='د. ياسر عثمان'
        missing=payload.copy();missing.pop('requested_doctors')
        assert ob.call('POST','/api/consultations',missing).status_code==422
        spaces=payload.copy();spaces['requested_doctors']='    '
        assert ob.call('POST','/api/consultations',spaces).status_code==422
    finally:
        ob.close();intern.close()


def test_complete_requires_fresh_reply_after_info_round_and_no_text_bypass(setup):
    client, ids = setup
    ob = Actor(client, 'ob', ids['ob'])
    intern = Actor(client, 'in', ids['in'])
    try:
        c = create(ob, ids['in'])
        assert intern.call('POST', f'/api/consultations/{c}/actions',
                           {'action': 'reply', 'body': 'جواب أولي طويل وواضح'}).status_code == 200
        assert intern.call('POST', f'/api/consultations/{c}/actions',
                           {'action': 'request_info', 'body': 'أرسل معلومات إضافية'}).status_code == 200
        assert ob.call('POST', f'/api/consultations/{c}/actions',
                       {'action': 'provide_info', 'body': 'معلومات سريرية إضافية تجريبية'}).status_code == 200
        # The previously saved reply is stale. Supplying text in complete must not bypass the guard.
        r = intern.call('POST', f'/api/consultations/{c}/actions',
                        {'action': 'complete', 'body': 'إنهاء دون رد جديد'})
        assert r.status_code == 422, r.text
        assert intern.call('POST', f'/api/consultations/{c}/actions',
                           {'action': 'reply', 'body': 'جواب جديد بعد وصول المعلومات الإضافية'}).status_code == 200
        assert intern.call('POST', f'/api/consultations/{c}/actions',
                           {'action': 'complete'}).status_code == 200
    finally:
        ob.close()
        intern.close()

def test_hourly_roster_weekly_day_override_and_permissions(setup):
    client, ids = setup
    intern=Actor(client,'in',ids['in']); ob=Actor(client,'ob',ids['ob']); other=Actor(client,'surg',ids['surg'])
    try:
        did=ids['in']; date_value='2026-11-10'  # Tuesday, weekday=1
        weekly={'slots':[
            {'doctor_name':'د. أحمد','phone':'0933000000','start':'09:00','end':'15:00','contact_role':'primary'},
            {'doctor_name':'د. محمد','phone':'0933111111','start':'13:00','end':'21:00','contact_role':'primary'},
            {'doctor_name':'د. سامر','phone':'0933222222','start':'21:00','end':'09:00','contact_role':'backup'}]}
        assert other.call('PUT',f'/api/rosters/{did}/weekly/1',weekly).status_code==403
        w=intern.call('PUT',f'/api/rosters/{did}/weekly/1',weekly)
        assert w.status_code==200,w.text
        r=ob.call('GET',f'/api/rosters/{did}?day={date_value}')
        assert r.status_code==200,r.text
        v=r.json();assert v['source']=='weekly' and len(v['slots'])==3 and not v['gaps']
        assert sum(x['start']=='13:00' for x in v['slots'])==1
        override={'slots':[{'doctor_name':'د. طارق','phone':'0933444444','start':'09:00','end':'09:00','contact_role':'primary'}]}
        assert intern.call('PUT',f'/api/rosters/{did}/day/{date_value}',override).status_code==200
        v=ob.call('GET',f'/api/rosters/{did}?day={date_value}').json()
        assert v['source']=='daily' and len(v['slots'])==1 and v['slots'][0]['end_minute']==1440
        assert len(ob.call('GET',f'/api/rosters/{did}?day=2026-11-17').json()['slots'])==3
        assert other.call('DELETE',f'/api/rosters/{did}/day/{date_value}').status_code==403
        assert intern.call('DELETE',f'/api/rosters/{did}/day/{date_value}').status_code==200
        assert ob.call('GET',f'/api/rosters/{did}?day={date_value}').json()['source']=='weekly'
    finally:
        intern.close();ob.close();other.close()

def test_hourly_roster_gaps_invalid_cross_boundary_and_empty_override(setup):
    client, ids=setup
    intern=Actor(client,'in',ids['in']);ob=Actor(client,'ob',ids['ob'])
    try:
        did=ids['in'];d='2026-11-11'
        one={'slots':[{'doctor_name':'د. أحمد','phone':'0933000000','start':'15:00','end':'21:00','contact_role':'primary'}]}
        assert intern.call('PUT',f'/api/rosters/{did}/day/{d}',one).status_code==200
        v=ob.call('GET',f'/api/rosters/{did}?day={d}').json()
        assert v['gaps']==[{'from':'09:00','to':'15:00'},{'from':'21:00','to':'09:00'}]
        invalid={'slots':[{'doctor_name':'د. أحمد','phone':'0933000000','start':'07:00','end':'11:00'}]}
        assert intern.call('PUT',f'/api/rosters/{did}/day/{d}',invalid).status_code==422
        invalid_phone={'slots':[{'doctor_name':'د. أحمد','phone':'ABC','start':'09:00','end':'11:00'}]}
        assert intern.call('PUT',f'/api/rosters/{did}/day/{d}',invalid_phone).status_code==422
        assert intern.call('PUT',f'/api/rosters/{did}/day/{d}',{'slots':[]}).status_code==200
        v=ob.call('GET',f'/api/rosters/{did}?day={d}').json()
        assert v['source']=='daily' and len(v['slots'])==0
        assert v['gaps']==[{'from':'09:00','to':'09:00'}]
    finally:
        intern.close();ob.close()
