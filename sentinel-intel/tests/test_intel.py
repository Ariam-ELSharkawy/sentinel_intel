import sys
sys.path.insert(0,'src')
from fastapi.testclient import TestClient
from intel_service.main import app
client=TestClient(app)
def test_health(): assert client.get('/health').json()['status']=='ok'
def test_mapping():
 r=client.post('/api/v1/map-alert',json={'attack_type':'brute force'}).json(); assert r['techniques'][0]['id']=='T1110'
def test_enrichment_contract():
 r=client.post('/api/v1/enrich',json={'correlation_id':'t1','indicators':[{'type':'ip','value':'185.220.101.1'}]}).json(); item=r['items'][0]; assert item['indicator']['type']=='ip'; assert 'provenance' in item; assert 'reputation' in item
def test_dashboard(): assert client.get('/dashboard').status_code==200
