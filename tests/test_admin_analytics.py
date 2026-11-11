from sqlalchemy import select
from fastapi.testclient import TestClient
from app.main import app, pwd
from app.db import SessionLocal
from app.models import User, Hospital
from test_workflows import Actor, create, setup


def test_superadmin_dashboard_security_and_csv(setup):
    client,ids=setup
    with SessionLocal() as db:
        db.add(User(username='superadmin',full_name='Admin Trial',password_hash=pwd.hash('Training-Password-123!'),is_admin=True))
        db.commit()
    adm=Actor(client,'superadmin',ids['ob'])
    ob=Actor(client,'ob',ids['ob'])
    intern=Actor(client,'in',ids['in'])
    try:
        assert ob.call('GET','/api/admin/analytics').status_code==403
        assert ob.call('GET','/api/admin/analytics/export.csv').status_code==403
        assert ob.call('GET','/api/admin/audit').status_code==403
        assert client.get('/api/admin/analytics').status_code==401
        c=create(ob,ids['in'])
        body={'patient_name':'SECRET PATIENT TEST', 'patient_ref':'SECRET-ID-123',
              'receiver_department_id':ids['in'],'requested_doctors':'Dr Test',
              'clinical_summary':'PLACEHOLDER sensitive test','question':'TEST only'}
        c2=ob.call('POST','/api/consultations',body).json()['id']
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'reply'}).status_code==200
        assert intern.call('POST',f'/api/consultations/{c}/actions',{'action':'complete'}).status_code==200
        assert ob.call('POST',f'/api/consultations/{c}/actions',{'action':'close'}).status_code==200
        r=adm.call('GET','/api/admin/analytics')
        assert r.status_code==200,r.text
        data=r.json()
        assert data['overall']['total']==2
        assert data['overall']['open']==1
        assert data['overall']['closed']==1
        assert data['overall']['awaiting_reply']==1
        assert data['overall']['with_first_reply']==1
        assert data['overall']['first_reply_median_minutes'] is not None
        assert 'SECRET PATIENT TEST' not in r.text and 'SECRET-ID-123' not in r.text
        fmt=adm.call('GET','/api/admin/analytics/export.csv')
        assert fmt.status_code==200,fmt.text
        assert fmt.headers['content-type'].startswith('text/csv')
        assert fmt.content.startswith(b'\xef\xbb\xbf')
        assert 'SECRET PATIENT TEST' not in fmt.text
        assert adm.call('GET','/api/admin/analytics?from_date=2026-13-01').status_code==422
        assert adm.call('GET','/api/admin/analytics?from_date=2027-01-01&to_date=2026-01-01').status_code==422
        assert adm.call('GET','/api/admin/analytics?from_date=2035-01-01').json()['overall']['total']==0
        assert adm.call('GET',f'/api/admin/analytics?department_id={ids["in"]}').json()['overall']['total']==0
        assert adm.call('GET','/api/admin/audit?limit=100').status_code==200
        assert any(a['action']=='analytics_export' for a in adm.call('GET','/api/admin/audit').json())
    finally:
        adm.close();ob.close();intern.close()


def test_superadmin_user_and_hospital_modification(setup):
    client,ids=setup
    with SessionLocal() as db:
        db.add(User(username='superadmin',full_name='Admin Trial',password_hash=pwd.hash('Training-Password-123!'),is_admin=True));db.commit()
        uid=db.scalar(select(User).where(User.username=='ob')).id
        admin_id=db.scalar(select(User).where(User.username=='superadmin')).id
        university=db.scalar(select(Hospital).where(Hospital.code=='UNI')).id
    adm=Actor(client,'superadmin',ids['ob']);ob=Actor(client,'ob',ids['ob'])
    try:
        assert ob.call('PATCH',f'/api/admin/users/{uid}',{'is_admin':True}).status_code==403
        assert adm.call('PATCH',f'/api/admin/users/{admin_id}',{'is_admin':False}).status_code==409
        assert adm.call('PATCH',f'/api/admin/users/{admin_id}',{'active':False}).status_code==409
        assert adm.call('PATCH',f'/api/admin/users/{uid}',{'full_name':'اسم طبيب جديد'}).status_code==200
        assert adm.call('PATCH',f'/api/admin/users/{uid}',{'active':False}).status_code==200
        assert ob.call('GET','/api/me').status_code==401
        assert adm.call('PATCH',f'/api/admin/hospitals/{university}',{'name':'مشفى الجامعة التجريبي'}).status_code==200
        assert adm.call('PATCH',f'/api/admin/hospitals/{university}',{'active':False}).status_code==409
    finally:adm.close();ob.close()


def test_superadmin_username_change_and_single_department_rule(setup):
    client,ids=setup
    with SessionLocal() as db:
        db.add(User(username='superadmin2',full_name='Admin Trial',password_hash=pwd.hash('Training-Password-123!'),is_admin=True));db.commit()
        ob_id=db.scalar(select(User).where(User.username=='ob')).id
        neph_id=db.scalar(select(User).where(User.username=='neph')).id
    adm=Actor(client,'superadmin2',ids['ob']);ob=Actor(client,'ob',ids['ob']);neph=Actor(client,'neph',ids['neph'])
    try:
        # Only Super Admin may rename a login, the account/history stays the same row.
        assert ob.call('PATCH',f'/api/admin/users/{ob_id}',{'username':'ob_renamed'}).status_code==403
        r=adm.call('PATCH',f'/api/admin/users/{ob_id}',{'username':'ob_renamed'})
        assert r.status_code==200,r.text
        assert adm.call('PATCH',f'/api/admin/users/{neph_id}',{'username':'ob_renamed'}).status_code==409
        new=TestClient(app)
        with new:
            assert new.post('/api/auth/login',json={'username':'ob','password':'Training-Password-123!'}).status_code==401
            assert new.post('/api/auth/login',json={'username':'ob_renamed','password':'Training-Password-123!'}).status_code==200

        # Super Admin resets any account's password directly.
        r=adm.call('POST',f'/api/admin/users/{ob_id}/set-password',{'new_password':'New-Reset-Password-2027!'})
        assert r.status_code==200,r.text
        with new:
            assert new.post('/api/auth/login',json={'username':'ob_renamed','password':'Training-Password-123!'}).status_code==401
            assert new.post('/api/auth/login',json={'username':'ob_renamed','password':'New-Reset-Password-2027!'}).status_code==200

        # A non-admin account is tied to exactly one department: assigning a second
        # department reassigns it instead of accumulating access to both.
        mem=adm.call('GET','/api/admin/memberships').json()
        assert any(m['user_id']==neph_id and m['department_id']==ids['neph'] for m in mem)
        r=adm.call('POST','/api/admin/memberships',{'user_id':neph_id,'department_id':ids['surg'],'role':'doctor'})
        assert r.status_code==200,r.text
        mem=adm.call('GET','/api/admin/memberships').json()
        active_for_neph=[m for m in mem if m['user_id']==neph_id]
        assert len(active_for_neph)==1 and active_for_neph[0]['department_id']==ids['surg']
    finally:
        adm.close();ob.close();neph.close()
