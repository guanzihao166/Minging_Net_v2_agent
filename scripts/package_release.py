"""Reproducible signed Linux packages, with complete vendored corresponding source.
Signing keys belong outside the repository. No credentials enter any archive.
"""
from pathlib import Path
import argparse, gzip, hashlib, io, json, os, subprocess, tarfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

parser=argparse.ArgumentParser()
parser.add_argument('--key',required=True)
parser.add_argument('--output',required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
keypath=Path(args.key).resolve()
if keypath.is_relative_to(root):raise SystemExit('Signing key must be stored outside the repository')
if not keypath.exists():
 keypath.parent.mkdir(parents=True,exist_ok=True)
 private=rsa.generate_private_key(public_exponent=65537,key_size=3072)
 keypath.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
else: private=serialization.load_pem_private_key(keypath.read_bytes(),password=None)
public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
pin=root/'deploy/release-signing.pub'
if pin.exists():
 if pin.read_bytes().replace(b'\r\n',b'\n')!=public:raise SystemExit('Signing key differs from the pinned release key')
else:pin.write_bytes(public)
output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=True)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip())
version='0.3.4+'+commit[:12]+('.dirty' if dirty else '')
stamp=int(subprocess.check_output(['git','show','-s','--format=%ct','HEAD'],cwd=root,text=True).strip())
def archive(path,items):
 with path.open('wb') as target,gzip.GzipFile(fileobj=target,mode='wb',mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as bundle:
  for name,data,mode in sorted(items):
   info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.mtime=stamp;info.uid=info.gid=0
   bundle.addfile(info,io.BytesIO(data))
subprocess.run(['go','mod','vendor'],cwd=root,check=True)
for arch in ['amd64','arm64']:
 binary=root/'.local/bin'/('minging-agent-'+arch)
 binary.parent.mkdir(parents=True,exist_ok=True)
 subprocess.run(['go','build','-mod=vendor','-buildvcs=false','-tags','with_gvisor','-trimpath','-ldflags','-s -w -X main.version='+version,'-o',str(binary),'./cmd/agent'],cwd=root,env={**os.environ,'GOOS':'linux','GOARCH':arch,'CGO_ENABLED':'0'},check=True)
 items=[('minging-agent',binary.read_bytes(),0o755),('LICENSE',(root/'LICENSE').read_bytes(),0o644),('README.md',(root/'README.md').read_bytes(),0o644)]
 for name in ['minging-agent.service','minging-agent.openrc']:items.append((name,(root/'deploy'/name).read_bytes().replace(b'\r\n',b'\n'),0o644))
 archive(output/('minging-agent-linux-'+arch+'.tar.gz'),items)
source=[]
for folder in ['cmd','internal','deploy','scripts','third_party','vendor']:
 for path in (root/folder).rglob('*'):
  if path.is_file() and '__pycache__' not in path.parts and (folder=='vendor' or not path.name.endswith(('.key','.pem','.db'))):
   source.append((path.relative_to(root).as_posix(),path.read_bytes(),0o755 if path.suffix in ['.sh','.openrc'] else 0o644))
for name in ['go.mod','go.sum','LICENSE','README.md']:source.append((name,(root/name).read_bytes(),0o644))
source.append(('RELEASE.json',json.dumps({'version':version,'commit':commit,'dirty':dirty,'go':subprocess.check_output(['go','version'],text=True).strip(),'build':'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -buildvcs=false -tags with_gvisor -trimpath -ldflags "-s -w -X main.version='+version+'" -o minging-agent ./cmd/agent'},indent=2).encode(),0o644))
archive(output/'minging-agent-source.tar.gz',source)
checksums=''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n' for path in sorted(output.glob('minging-agent-*.tar.gz'))).encode()
(output/'SHA256SUMS').write_bytes(checksums)
(output/'SHA256SUMS.sig').write_bytes(private.sign(checksums,padding.PKCS1v15(),hashes.SHA256()))
script=(root/'deploy/install.sh').read_text(encoding='utf-8').replace('@@RELEASE_PUBLIC_KEY@@',public.decode().strip()).replace('@@RELEASE_DOWNLOAD_BASE@@','https://github.com/guanzihao166/Minging_Net_v2_agent/releases/download/v0.3.4')
(output/'agent-install.sh').write_text(script,encoding='utf-8',newline='\n')
private.public_key().verify((output/'SHA256SUMS.sig').read_bytes(),checksums,padding.PKCS1v15(),hashes.SHA256())
print(json.dumps({'version':version,'corresponding_source':'included with vendored dependencies','files':[{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(output.iterdir()) if p.is_file()]},indent=2))
