from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from .models import EnrichRequest
from .service import IntelService
app=FastAPI(title='Sentinel Intel',version='1.0.0'); svc=IntelService()
@app.get('/health')
def health():return {'status':'ok','service':'intel','version':'1.0.0'}
@app.post('/api/v1/enrich')
async def enrich(req:EnrichRequest): return await svc.enrich(req)
@app.post('/api/v1/map-alert')
def map_alert(alert:dict): return {'techniques':svc.mitre.map(alert)}
@app.get('/api/v1/coverage')
def coverage():
 observed=[]
 for x in svc.store.list(100): observed.extend(x['payload'].get('techniques',[]))
 return svc.mitre.coverage(observed)
@app.get('/api/v1/coverage/layer')
def layer():return svc.mitre.layer()
@app.get('/api/v1/indicators')
def indicators(limit:int=100):return {'items':svc.store.list(min(limit,500))}
@app.get('/dashboard',response_class=HTMLResponse)
def dashboard():
 return """<!doctype html><html><head><meta charset="utf-8"><title>Sentinel Intel</title><style>body{font:15px system-ui;background:#08111f;color:#e5eefb;margin:0;padding:32px}main{max-width:1100px;margin:auto}.card{background:#101d31;border:1px solid #25415f;border-radius:12px;padding:18px;margin:12px 0}h1{color:#69d3ff}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric{font-size:30px;font-weight:700}.muted{color:#9eb2c8}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #26415b;text-align:left}.pill{padding:3px 8px;border-radius:20px;background:#173c56}</style></head><body><main><h1>Sentinel Threat Intelligence</h1><p class="muted">Ariam vertical slice · evidence, indicators and ATT&amp;CK coverage</p><div class="grid"><div class="card"><div class="muted">Indicators</div><div id="count" class="metric">—</div></div><div class="card"><div class="muted">ATT&amp;CK coverage</div><div id="coverage" class="metric">—</div></div><div class="card"><div class="muted">Service</div><div class="metric">LIVE</div></div></div><div class="card"><h2>Recent indicators</h2><table><thead><tr><th>Type</th><th>Value</th><th>Reputation</th><th>Mode</th><th>Techniques</th></tr></thead><tbody id="rows"></tbody></table></div></main><script>Promise.all([fetch('/api/v1/indicators').then(r=>r.json()),fetch('/api/v1/coverage').then(r=>r.json())]).then(([a,c])=>{document.querySelector('#count').textContent=a.items.length;document.querySelector('#coverage').textContent=c.covered+'/'+c.total;document.querySelector('#rows').innerHTML=a.items.map(x=>{let p=x.payload;let mode=(p.provenance||[]).map(z=>z.mode).join(', ');return `<tr><td>${x.type}</td><td>${x.value}</td><td><span class="pill">${p.reputation.score}/100</span></td><td>${mode}</td><td>${(p.techniques||[]).join(', ')||'—'}</td></tr>`}).join('')})</script></body></html>"""
