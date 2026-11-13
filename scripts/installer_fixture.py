"""Disposable CI controller and locally signed release, never a production service."""
import datetime,hashlib,hmac,http.server,json,os,pathlib,ssl,subprocess,sys,tarfile
ROOT=pathlib.Path('/installer-fixture')
TOKEN='a'*256;DOWNLOAD='b'*64
def prepare():
 ROOT.mkdir(mode=0o700)
 subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-keyout',str(ROOT/'controller.key'),'-out',str(ROOT/'controller.crt'),'-days','1','-subj','/CN=Minging Installer CI','-addext','subjectAltName=IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(ROOT/'release.key')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 public=subprocess.check_output(['openssl','pkey','-in',str(ROOT/'release.key'),'-pubout']).decode()
 installer=pathlib.Path('/workspace/deploy/install.sh').read_text().replace('@@RELEASE_PUBLIC_KEY@@',public.strip())
 (ROOT/'install.sh').write_text(installer)
 package=ROOT/'minging-agent-linux-amd64.tar.gz'
 with tarfile.open(package,'w:gz') as tar:
  tar.add('/workspace/.local/runtime/minging-agent-amd64',arcname='minging-agent')
  for name in ['minging-agent.service','minging-agent.openrc']:tar.add('/workspace/deploy/'+name,arcname=name)
 (ROOT/'SHA256SUMS').write_text(hashlib.sha256(package.read_bytes()).hexdigest()+'  '+package.name+'\n')
 subprocess.run(['openssl','dgst','-sha256','-sign',str(ROOT/'release.key'),'-out',str(ROOT/'SHA256SUMS.sig'),str(ROOT/'SHA256SUMS')],check=True)
 config={'server_id':1,'controller':'https://127.0.0.1:24560','token':TOKEN,'listen':'127.0.0.1:24442','controller_ips':['127.0.0.1/32'],'state_directory':'/var/lib/minging-agent','tls_directory':'/etc/minging-agent/tls'}
 (ROOT/'agent.json').write_text(json.dumps(config));(ROOT/'download.token').write_text(DOWNLOAD)
 config['controller']='https://127.0.0.1:24561';(ROOT/'unhealthy.json').write_text(json.dumps(config))
 for name in ['agent.json','unhealthy.json','download.token','controller.key','release.key']:os.chmod(ROOT/name,0o600)

class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def respond(self,status,body):
  self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_GET(self):self.handle_request()
 def do_POST(self):self.handle_request()
 def handle_request(self):
  if self.path.startswith('/agent-releases/'):
   name=self.path.split('/')[-1]
   if self.headers.get('X-Mnet-Install')!=DOWNLOAD or name not in ['SHA256SUMS','SHA256SUMS.sig','minging-agent-linux-amd64.tar.gz']:self.respond(403,b'denied');return
   self.respond(200,(ROOT/name).read_bytes());return
  raw=self.rfile.read(int(self.headers.get('Content-Length','0')))
  message='mnet-agent-v1\n'+self.command+'\n'+self.path+'\n'+self.headers.get('X-Mnet-Time','')+'\n'+self.headers.get('X-Mnet-Nonce','')+'\n'+hashlib.sha256(raw).hexdigest()
  signature=hmac.new(TOKEN.encode(),message.encode(),hashlib.sha256).hexdigest()
  if not hmac.compare_digest(self.headers.get('X-Mnet-Signature',''),signature):self.respond(401,b'denied');return
  if self.path=='/api/agent/config':
   now=datetime.datetime.now(datetime.timezone.utc)
   self.respond(200,json.dumps({'protocol_version':1,'server_id':1,'revision':'c'*64,'issued_at':now.isoformat(),'valid_until':(now+datetime.timedelta(seconds=60)).isoformat(),'inbounds':[]}).encode())
  elif self.path in ['/api/agent/enroll','/api/agent/report']:self.respond(200,b'{"ok":true}')
  else:self.respond(404,b'unknown fixture endpoint')

if sys.argv[1]=='prepare':prepare()
else:
 server=http.server.ThreadingHTTPServer(('127.0.0.1',24560),Handler)
 tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(ROOT/'controller.crt',ROOT/'controller.key')
 server.socket=tls.wrap_socket(server.socket,server_side=True);server.serve_forever()
