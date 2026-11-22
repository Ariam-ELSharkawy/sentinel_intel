import json, re
class Mitre:
 def __init__(self,path='data/mitre_attack.json'):
  with open(path) as f:self.data=json.load(f)
  self.byid={x['id']:x for x in self.data['techniques']}
  self.alias={'brute force':'T1110','credential stuffing':'T1110','scan':'T1046','scanning':'T1046','sql injection':'T1190','exploit':'T1190','powershell':'T1059.001','command shell':'T1059.003','phishing':'T1566','web request':'T1071.001'}
 def map(self,alert):
  ids=set(alert.get('techniques',[]))
  text=' '.join(str(alert.get(k,'')) for k in ('attack_type','rule_id','description','source')).lower()
  for k,v in self.alias.items():
   if k in text:ids.add(v)
  return [self.byid[i] for i in sorted(ids) if i in self.byid]
 def coverage(self,observed=None):
  obs=set(observed or [])
  rows=[]
  for x in self.data['techniques']:rows.append({**x,'covered':x['id'] in obs})
  return {'version':self.data['version'],'total':len(rows),'covered':len([r for r in rows if r['covered']]),'techniques':rows}
 def layer(self,observed=None):
  obs=set(observed or []); return {'name':'Sentinel Intel Coverage','version':'4.9','domain':'enterprise-attack','techniques':[{'techniqueID':x['id'],'score':100 if x['id'] in obs else 0} for x in self.data['techniques']]}
