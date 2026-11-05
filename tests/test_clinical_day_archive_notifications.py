from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from sqlalchemy import select
from app import main as m
from app.models import Consultation, Event
from app.db import SessionLocal
from test_workflows import setup, Actor, create


def test_clinical_day_boundary_is_nine_am_local():
    tz=ZoneInfo('Asia/Damascus')
    earlier=datetime(2026,11,2,8,59,59,tzinfo=tz)
    boundary=datetime(2026,11,2,9,0,0,tzinfo=tz)
    start,end,label=m.clinical_window(earlier)
    assert label=='2026-11-01'
    assert start.astimezone(tz).hour==9 and start.astimezone(tz).day==1
    assert end.astimezone(tz).hour==9 and end.astimezone(tz).day==2
    start,end,label=m.clinical_window(boundary)
    assert label=='2026-11-02' and start.astimezone(tz).hour==9


def test_carryover_archiving_and_handover(setup, monkeypatch):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']); internal=Actor(client,'in',ids['in'])
    try:
        old=create(ob,ids['in'])
        cur=create(ob,ids['in'])
        before=datetime(2026,11,1,5,0,tzinfo=timezone.utc) # 08:00 local: previous clinical day
        during=datetime(2026,11,1,6,0,tzinfo=timezone.utc) # 09:00 local: new clinical day
        # Freeze clinical day at 11:00 local Nov 1
        monkeypatch.setattr(m,'now',lambda: datetime(2026,11,1,8,0,tzinfo=timezone.utc))
        with SessionLocal() as db:
            db.get(Consultation,old).created_at=before
            db.get(Consultation,cur).created_at=during
            db.commit()
        dashboard=ob.call('GET','/api/dashboard').json()
        assert dashboard['clinical_day']['current_day']=='2026-11-01'
        assert dashboard['clinical_day']['outgoing_carried']==1
        assert dashboard['clinical_day']['outgoing_created_today']==1
        assert ob.call('GET','/api/consultations?folder=outgoing&scope=carryover').json()['total']==1
        assert ob.call('GET','/api/consultations?folder=outgoing&scope=today').json()['total']==1
        ho=ob.call('GET','/api/handover').json()
        assert ho['total']==1 and ho['items'][0]['consultation']['id']==old
        assert internal.call('GET','/api/handover').json()['total']==1
        assert internal.call('POST',f'/api/consultations/{old}/actions',{'action':'reply','body':'جواب تجريبي'}).status_code==200
        assert internal.call('POST',f'/api/consultations/{old}/actions',{'action':'complete'}).status_code==200
        # Completing answer must NOT archive.
        assert ob.call('GET','/api/consultations?folder=outgoing&scope=archive').json()['total']==0
        assert ob.call('GET','/api/handover').json()['total']==1
        assert ob.call('POST',f'/api/consultations/{old}/actions',{'action':'close'}).status_code==200
        assert ob.call('GET','/api/consultations?folder=outgoing&scope=archive').json()['total']==1
        assert ob.call('GET','/api/consultations?folder=outgoing').json()['total']==1
        assert ob.call('GET','/api/handover').json()['total']==0
        assert internal.call('GET','/api/consultations?folder=incoming&scope=archive').json()['total']==1
        assert internal.call('GET','/api/consultations?folder=incoming').json()['total']==1
        assert ob.call('GET',f'/api/consultations/{old}').json()['consultation']['archived']
        assert ob.call('GET',f'/print/{old}').status_code==200
        # Carry-over does not reset ages or cause a second creation event.
        with SessionLocal() as db:
            assert len(db.scalars(select(Event).where(Event.consultation_id==old,Event.type=='created')).all())==1
    finally:ob.close();internal.close()


def test_department_scoped_notifications_and_read_receipts(setup):
    client,ids=setup
    ob=Actor(client,'ob',ids['ob']); internal=Actor(client,'in',ids['in']); other=Actor(client,'surg',ids['surg'])
    try:
        c=create(ob,ids['in'])
        inbox=internal.call('GET','/api/notifications').json()
        assert inbox['unread_in_page']==1 and inbox['items'][0]['kind']=='new_consultation'
        notification_id=inbox['items'][0]['id']
        assert 'مريضة' not in internal.call('GET','/api/notifications').text
        assert ob.call('GET','/api/notifications').json()['items']==[]
        assert other.call('POST',f'/api/notifications/{notification_id}/read').status_code==404
        assert internal.call('POST',f'/api/notifications/{notification_id}/read').status_code==200
        assert internal.call('POST',f'/api/notifications/{notification_id}/read').status_code==200 # idempotent
        assert internal.call('GET','/api/notifications').json()['unread_in_page']==0
        assert internal.call('POST',f'/api/consultations/{c}/actions',{'action':'reply','body':'إجابة تجريبية'}).status_code==200
        assert ob.call('GET','/api/notifications').json()['unread_in_page']==1
    finally:ob.close();internal.close();other.close()
