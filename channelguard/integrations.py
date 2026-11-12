from __future__ import annotations
import ipaddress
import base64
import json
import secrets
import subprocess
from urllib.parse import quote
from .bridge import ProxyBridge
from .engine import resource_root
from .system import HIDDEN
from .presets import values


def wsl_call(distro='Ubuntu', action='inspect', **payload):
    script=(resource_root()/'channelguard'/'wsl_helper.py')
    if not script.exists():script=resource_root()/'wsl_helper.py'
    encoded=base64.b64encode(script.read_bytes()).decode('ascii')
    loader="import base64;exec(base64.b64decode('"+encoded+"'))"
    result=subprocess.run(['wsl.exe','-d',distro,'--','python3','-c',loader],
        input=json.dumps(dict(action=action,**payload)),capture_output=True,text=True,encoding='utf-8',
        timeout=95,creationflags=HIDDEN)
    try:data=json.loads(result.stdout)
    except ValueError:raise RuntimeError('无法检查 WSL OpenClaw 服务。确认 Ubuntu 已启动且安装了 Python 3。')
    if result.returncode or data.get('error'):raise RuntimeError(data.get('message','WSL 接入失败。'))
    return data


class OpenClawIntegration:
    def __init__(self,store,engines):
        self.store,self.engines=store,engines
        self.bridge=None
        self.network=None

    def prepare(self,channel,network,distro='Ubuntu'):
        state=wsl_call(distro)
        # Never expose a listener on a LAN / public interface.
        addresses={ip for c in network.get('configs',[]) if 'wsl' in c.get('InterfaceAlias','').lower()
                   for ip in values(c.get('IPv4'))}
        if state['host'] not in addresses or not ipaddress.ip_address(state['host']).is_private:
            raise RuntimeError('未找到匹配的 WSL 专用虚拟网卡。当前只支持 WSL2 NAT 接入。')
        config=self.store.data.setdefault('integrations',{}).setdefault('openclaw',{})
        password=config.get('password') or secrets.token_hex(24)
        previous=self.bridge
        if previous and (previous.host,state['peer'])==(state['host'],self.network['peer']) and config.get('channel_id')==channel['id']:
            return state
        if previous:previous.close();self.bridge=None
        try:
            self.bridge=ProxyBridge(state['host'],config.get('port',0),state['peer'],password,
                lambda:self.engines.active.get(channel['id']))
        except OSError as exc:raise RuntimeError('WSL 接入端口无法监听。没有更改防火墙或 OpenClaw 配置。') from exc
        config.update(password=password,port=self.bridge.port,host=state['host'],peer=state['peer'],
                      distro=distro,channel_id=channel['id'],enabled=True)
        self.network=state
        return state

    def configure(self,channel,network,distro='Ubuntu'):
        self.prepare(channel,network,distro)
        config=self.store.data['integrations']['openclaw']
        proxy=f"http://cg-wsl:{quote(config['password'],safe='')}@{config['host']}:{config['port']}"
        probe=wsl_call(distro,'probe',proxy=proxy)
        if not any(row.get('status')==200 for row in probe.get('checks',[])):
            raise RuntimeError('WSL 无法通过所选信道联网；OpenClaw 服务配置未更改。')
        # No credentials in command line, reports or global system environment.
        state=wsl_call(distro,'configure',proxy=proxy)
        state['verification']=wsl_call(distro,'verify')
        return state

    def close(self):
        if self.bridge:self.bridge.close();self.bridge=None
