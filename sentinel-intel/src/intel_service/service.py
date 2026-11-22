import hashlib, os
from datetime import datetime, timezone, timedelta
from .db import Store
from .providers import Providers
from .mitre import Mitre
class IntelService:
 def __init__(self):self.store=Store(ttl=int(os.getenv('CACHE_TTL_SECONDS','86400')));self.providers=Providers();self.mitre=Mitre()
 async def enrich(self,req):
  items=[]
  for ind in req.indicators:
   key=hashlib.sha256(f'{ind.type}:{ind.value}'.encode()).hexdigest(); cached=self.store.get(key); errors=[]
   if cached and cached[1]: payload=cached[0]; payload['freshness']={'cached':True,'expires_at':(datetime.now(timezone.utc)+timedelta(seconds=self.store.ttl)).isoformat()}; items.append(payload);continue
   results=await self.providers.lookup(ind); reps=[x for x,_ in results if isinstance(x,dict) and 'score' in x]; rep=max(reps,key=lambda x:x['score'],default={'score':0,'malicious':False,'confidence':0,'source':'none'}); score=int(rep['score']); geo=next((x for x,_ in results if isinstance(x,dict) and 'country' in x),{})
   prov=[p for _,p in results]; techniques=[]
   if score>=70:techniques=['T1071.001']
   payload={'indicator':ind.model_dump(),'reputation':{'score':score,'malicious':score>=50,'confidence':max(float(x.get('confidence',0)) for x in reps) if reps else 0,'sources':[x.get('source') for x in reps]},'geo':geo,'techniques':techniques,'history':[],'freshness':{'cached':False,'expires_at':(datetime.now(timezone.utc)+timedelta(seconds=self.store.ttl)).isoformat()},'provenance':prov,'errors':errors}
   self.store.put(key,payload);self.store.record(ind.type,ind.value,payload);items.append(payload)
  return {'correlation_id':req.correlation_id,'generated_at':datetime.now(timezone.utc).isoformat(),'items':items}
