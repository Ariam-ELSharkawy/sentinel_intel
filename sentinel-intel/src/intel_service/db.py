import json, os, sqlite3
from datetime import datetime, timezone, timedelta
class Store:
 def __init__(self,path=None,ttl=86400):
  self.path=path or os.getenv('DATABASE_PATH','./data/intel.db'); self.ttl=ttl; os.makedirs(os.path.dirname(self.path) or '.',exist_ok=True); self.init()
 def conn(self): return sqlite3.connect(self.path)
 def init(self):
  with self.conn() as c:
   c.execute('CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, payload TEXT NOT NULL, expires REAL NOT NULL)')
   c.execute('CREATE TABLE IF NOT EXISTS indicators (type TEXT, value TEXT, first_seen TEXT, last_seen TEXT, count INTEGER, payload TEXT, PRIMARY KEY(type,value))')
 def get(self,key):
  with self.conn() as c:
   row=c.execute('SELECT payload,expires FROM cache WHERE key=?',(key,)).fetchone()
  if not row:return None
  return json.loads(row[0]), row[1]>datetime.now(timezone.utc).timestamp()
 def put(self,key,payload):
  exp=(datetime.now(timezone.utc)+timedelta(seconds=self.ttl)).timestamp()
  with self.conn() as c:c.execute('INSERT OR REPLACE INTO cache VALUES(?,?,?)',(key,json.dumps(payload),exp))
 def record(self,typ,val,payload):
  now=datetime.now(timezone.utc).isoformat()
  with self.conn() as c:
   c.execute("""INSERT INTO indicators VALUES(?,?,?,?,?,?) ON CONFLICT(type,value) DO UPDATE SET last_seen=?,count=count+1,payload=?""",(typ,val,now,now,1,json.dumps(payload),now,json.dumps(payload)))
 def list(self,limit=100):
  with self.conn() as c: rows=c.execute('SELECT type,value,first_seen,last_seen,count,payload FROM indicators ORDER BY last_seen DESC LIMIT ?',(limit,)).fetchall()
  return [dict(type=r[0],value=r[1],first_seen=r[2],last_seen=r[3],count=r[4],payload=json.loads(r[5])) for r in rows]
