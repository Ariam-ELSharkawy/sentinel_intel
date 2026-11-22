import os, asyncio, httpx
from datetime import datetime, timezone
class Quota:
 def __init__(self,limit=500): self.limit=limit; self.used=0
 def take(self):
  if self.used>=self.limit:return False
  self.used+=1; return True
class Providers:
 def __init__(self): self.vt=Quota(); self.abuse=Quota(); self.timeout=float(os.getenv('PROVIDER_TIMEOUT_SECONDS','4'))
 async def lookup(self,ind):
  tasks=[self.vt_lookup(ind),self.abuse_lookup(ind),self.geo_lookup(ind)]
  return await asyncio.gather(*tasks,return_exceptions=True)
 async def vt_lookup(self,ind):
  key=os.getenv('VT_API_KEY'); now=datetime.now(timezone.utc).isoformat()
  if ind.type not in ('ip','domain','url','hash'): return {},{'provider':'virustotal','mode':'skipped','retrieved_at':now}
  if not key or not self.vt.take(): return {'score':15,'malicious':False,'confidence':0.25,'source':'demo'}, {'provider':'virustotal','mode':'demo','retrieved_at':now}
  try:
   ident=ind.value; endpoint=f'https://www.virustotal.com/api/v3/{"ip_addresses" if ind.type=="ip" else "domains" if ind.type=="domain" else "files"}/{ident}'
   async with httpx.AsyncClient(timeout=self.timeout) as c:
    r=await c.get(endpoint,headers={'x-apikey':key}); r.raise_for_status(); a=r.json().get('data',{}).get('attributes',{}); stats=a.get('last_analysis_stats',{}); mal=int(stats.get('malicious',0)); total=max(sum(stats.values()),1)
   return {'score':round(100*mal/total),'malicious':mal>0,'confidence':min(1,total/80),'source':'virustotal'},{'provider':'virustotal','mode':'live','retrieved_at':now}
  except Exception as e:return {'error':'provider_unavailable'},{'provider':'virustotal','mode':'error','retrieved_at':now}
 async def abuse_lookup(self,ind):
  now=datetime.now(timezone.utc).isoformat(); key=os.getenv('ABUSEIPDB_API_KEY')
  if ind.type!='ip' or not key or not self.abuse.take(): return {'score':10,'malicious':False,'confidence':0.2,'source':'demo'}, {'provider':'abuseipdb','mode':'demo','retrieved_at':now}
  try:
   async with httpx.AsyncClient(timeout=self.timeout) as c:
    r=await c.get('https://api.abuseipdb.com/api/v2/check',params={'ipAddress':ind.value,'maxAgeInDays':90},headers={'Key':key,'Accept':'application/json'}); r.raise_for_status(); d=r.json()['data']; score=int(d.get('abuseConfidenceScore',0))
   return {'score':score,'malicious':score>=50,'confidence':0.9,'source':'abuseipdb'},{'provider':'abuseipdb','mode':'live','retrieved_at':now}
  except Exception:return {'error':'provider_unavailable'},{'provider':'abuseipdb','mode':'error','retrieved_at':now}
 async def geo_lookup(self,ind):
  now=datetime.now(timezone.utc).isoformat()
  if ind.type!='ip':return {},{'provider':'geoip','mode':'skipped','retrieved_at':now}
  return {'country':None,'asn':None,'organization':None},{'provider':'geoip','mode':'demo','retrieved_at':now}
