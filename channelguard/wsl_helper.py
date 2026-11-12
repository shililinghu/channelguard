"""Executed by Linux Python via stdin-fed JSON; never prints proxy credentials."""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.parse


def command(args, **kwargs):
    return subprocess.run(args,capture_output=True,text=True,timeout=45,**kwargs)


def inspect():
    pid=command(['systemctl','--user','show','openclaw-gateway.service','-p','MainPID','--value'])
    number=int(pid.stdout.strip() or '0')
    if not number:raise RuntimeError('OpenClaw gateway service is not running')
    process=Path('/proc')/str(number)
    node=str((process/'exe').resolve())
    if not Path(node).name.startswith('node'):raise RuntimeError('Unexpected gateway runtime')
    route=json.loads(command(['ip','-j','-4','route','show','default']).stdout)
    host=next(r['gateway'] for r in route if r.get('gateway'))
    client=json.loads(command(['ip','-j','-4','route','get',host]).stdout)[0]['prefsrc']
    if not ipaddress.ip_address(host).is_private or not ipaddress.ip_address(client).is_private:
        raise RuntimeError('WSL private network not found')
    environment=dict(v.split(b'=',1) for v in (process/'environ').read_bytes().split(b'\0') if b'=' in v)
    return {'pid':number,'node':node,'host':host,'peer':client,
            'proxy_configured':b'HTTPS_PROXY' in environment,'service':'openclaw-gateway.service'}


def env_text(proxy):
    if any(x in proxy for x in ('\n','\r','"','%','\\')):raise ValueError('Invalid proxy value')
    keys=['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']
    return ''.join(key+'='+proxy+'\n' for key in keys)+'NO_PROXY=localhost,127.0.0.1,::1\nno_proxy=localhost,127.0.0.1,::1\nNODE_USE_ENV_PROXY=1\n'


def wait_ready():
    deadline=time.monotonic()+15
    while True:
        try:
            state=inspect()
            if state['proxy_configured']:return state
        except (RuntimeError,FileNotFoundError,ProcessLookupError):
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError('Gateway did not become ready with proxy environment')
        time.sleep(0.2)


def main(payload):
    action=payload.get('action','inspect')
    state=inspect()
    if action=='inspect':return state
    home=Path.home();config=home/'.config/channelguard';config.mkdir(mode=0o700,parents=True,exist_ok=True)
    env=config/'openclaw.env'
    drop=home/'.config/systemd/user/openclaw-gateway.service.d/70-channelguard.conf'
    if action=='configure':
        proxy=payload['proxy'];parsed=urllib.parse.urlsplit(proxy)
        if parsed.scheme!='http' or parsed.hostname!=state['host'] or not parsed.password:
            raise ValueError('Proxy does not match the detected WSL host')
        watched=home/'.openclaw/openclaw.json'
        before=hashlib.sha256(watched.read_bytes()).hexdigest() if watched.exists() else None
        old={p:p.read_bytes() if p.exists() else None for p in (env,drop)}
        backup=config/('backup-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        backup.mkdir(mode=0o700)
        for path,content in old.items():
            if content is not None:
                target=backup/path.name;target.write_bytes(content);target.chmod(0o600)
        try:
            env.write_text(env_text(proxy));env.chmod(0o600)
            drop.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            drop.write_text('[Service]\nEnvironmentFile='+str(env)+'\n');drop.chmod(0o600)
            if command(['systemctl','--user','daemon-reload']).returncode:raise RuntimeError('Service reload failed')
            if command(['systemctl','--user','restart','openclaw-gateway.service']).returncode:raise RuntimeError('Gateway restart failed')
            state=wait_ready()
        except Exception:
            for path,content in old.items():
                if content is None:path.unlink(missing_ok=True)
                else:path.write_bytes(content);path.chmod(0o600)
            command(['systemctl','--user','daemon-reload'])
            command(['systemctl','--user','restart','openclaw-gateway.service'])
            raise
        state.update(config_unchanged=before==(hashlib.sha256(watched.read_bytes()).hexdigest() if watched.exists() else None),
                     backup=str(backup),environment_file=str(env),dropin=str(drop))
        return state
    if action in ('verify','probe'):
        environment=dict(v.split(b'=',1) for v in (Path('/proc')/str(state['pid'])/'environ').read_bytes().split(b'\0') if b'=' in v)
        decoded={k.decode():v.decode() for k,v in environment.items()}
        if action=='probe':
            decoded.update(dict(line.split('=',1) for line in env_text(payload['proxy']).splitlines()))
        state['verification_source']='proposed_proxy' if action=='probe' else 'live_gateway_environment'
        # Execute with the live service's actual environment and exact Node binary.
        script="""const urls=['https://myip.ipip.net','https://ip.3322.net'];
const result=[];for(const url of urls){try{const r=await fetch(url,{signal:AbortSignal.timeout(10000)});result.push({url,status:r.status,body:(await r.text()).slice(0,600)});}catch(e){result.push({url,error:e.name});}}console.log(JSON.stringify(result));"""
        result=command([state['node'],'--input-type=module','-e',script],env=decoded)
        if result.returncode:raise RuntimeError('Node egress verification failed')
        state['checks']=json.loads(result.stdout)
        return state
    raise ValueError('Unknown action')


if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception as exc:
        print(json.dumps({'error':type(exc).__name__,'message':str(exc) if isinstance(exc,(RuntimeError,ValueError)) else 'WSL integration failed'}))
        sys.exit(1)
