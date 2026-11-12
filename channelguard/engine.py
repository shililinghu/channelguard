from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import quote
import requests
import yaml
from .config import channel_config,router_config
from .storage import atomic_write,dpapi
from .system import HIDDEN,is_admin,scan_network,list_guards,firewall_rule_name

def resource_root():
    return Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parent.parent))

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]

def session():
    result = requests.Session()
    result.trust_env = False
    return result

class Engines:
    def __init__(self, store, job):
        self.store,self.job = store,job
        self.active = {}
        self.router = None
        self.core = resource_root()/'vendor'/'mihomo.exe'
        if not self.core.is_file():
            raise RuntimeError('缺少 vendor/mihomo.exe，请完整解压程序目录。')
        self.runtime = store.root/'runtime'
        self.runtime.mkdir(exist_ok=True)

    def core_path(self, identity):
        if len(identity)!=32 or any(c not in '0123456789abcdef' for c in identity):
            raise ValueError('信道标识无效。')
        return self.store.root/'engines'/identity/'mihomo.exe'

    def prepare_core(self, identity):
        """A stable, distinct executable path lets external VPNs exclude only one channel."""
        target=self.core_path(identity)
        if identity in self.active:return target
        target.parent.mkdir(parents=True,exist_ok=True)
        digest=hashlib.sha256(self.core.read_bytes()).hexdigest()
        if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest()!=digest:
            temporary=target.with_suffix('.new')
            shutil.copy2(self.core,temporary)
            os.replace(temporary,target)
        atomic_write(target.parent/'channelguard-owned-core.json',json.dumps({'channel_id':identity,'sha256':digest}).encode())
        return target

    def start_config(self, identity, config, api_port, secret, core=None):
        core=core or self.core
        folder = self.runtime/identity
        folder.mkdir(exist_ok=True)
        path = folder/'config.yaml'
        atomic_write(path,yaml.safe_dump(config,allow_unicode=True,sort_keys=False).encode('utf-8'))
        # Validate locally before creating any listeners / routes.
        check = subprocess.run([str(core),'-t','-d',str(folder),'-f',str(path)],
                               capture_output=True,creationflags=HIDDEN,timeout=25)
        if check.returncode:
            path.unlink(missing_ok=True)
            # Don't leak passwords / raw node fields from third-party error output.
            raise RuntimeError('底层配置校验失败。请检查节点字段、协议和网卡名称；未启用此配置。')
        log = open(folder/'engine.log','ab',buffering=0)
        try:
            process = subprocess.Popen([str(core),'-d',str(folder),'-f',str(path)],
                                       stdout=log,stderr=log,creationflags=HIDDEN,cwd=str(resource_root()/'vendor'))
            self.job.add(process)
        finally:
            log.close()
        runtime = dict(process=process,api_port=api_port,secret=secret,folder=folder,core=core)
        for _ in range(50):
            if process.poll() is not None:
                self.stop_runtime(runtime)
                raise RuntimeError('网络引擎启动失败，可能是端口被占用、网卡不可用或 TUN 与现有 VPN 冲突。')
            try:
                with session() as http:
                    response = http.get(f'http://127.0.0.1:{api_port}/version',headers={'Authorization':'Bearer '+secret},timeout=.3)
                    if response.ok:
                        if config.get('bind-address')=='[::1]':
                            from .loopback import LoopbackCompat
                            try:runtime['loopback']=LoopbackCompat(config['mixed-port'])
                            except Exception:
                                self.stop_runtime(runtime)
                                raise RuntimeError('本地兼容转接端口不可用，信道未接管。')
                        return runtime
            except requests.RequestException:
                pass
            time.sleep(.1)
        self.stop_runtime(runtime)
        raise RuntimeError('网络引擎启动超时，已停止并清理此实例。')

    def start(self,channel):
        if channel['id'] in self.active:
            return self.active[channel['id']]
        from .presets import require_ready,require_interface
        require_ready(channel)
        if channel.get('interface'):require_interface(channel,scan_network())
        port,api_port = free_port(),free_port()
        while api_port == port:
            api_port = free_port()
        username,password,secret = 'cg',secrets.token_hex(20),secrets.token_hex(24)
        config = channel_config(channel,port,api_port,username,password,secret)
        runtime = self.start_config(channel['id'],config,api_port,secret,self.prepare_core(channel['id']))
        runtime.update(port=port,username=username,password=password,channel=copy.deepcopy(channel),
                       browsers=[],apps=[],started=time.time())
        self.active[channel['id']] = runtime
        self.write_browser_manifest(channel,runtime)
        return runtime

    def write_browser_manifest(self, channel, runtime, native_browser=None):
        data = dict(channel=channel,port=runtime['port'],username=runtime['username'],password=runtime['password'],
                    data_root=str(self.store.root))
        if native_browser:data['native_browser']=str(Path(native_browser).resolve())
        atomic_write(runtime['folder']/'browser.dpapi', dpapi(json.dumps(data,ensure_ascii=False).encode()))

    @staticmethod
    def stop_runtime(runtime):
        bridge=runtime.pop('loopback',None)
        if bridge:bridge.close()
        p = runtime['process']
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)
        for name in ('config.yaml','browser.dpapi'):
            (runtime['folder']/name).unlink(missing_ok=True)

    def stop(self, channel_id):
        runtime = self.active.get(channel_id)
        if not runtime:
            return
        if self.router:
            self.stop_router()
        # Leave local proxy endpoints unavailable: never reconfigure apps to direct.
        (runtime['folder']/'browser.dpapi').unlink(missing_ok=True)
        for browser in runtime['browsers']:
            if browser.poll() is None:
                try:
                    browser.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    import psutil
                    try:
                        tree=psutil.Process(browser.pid).children(recursive=True)
                        for child in reversed(tree):
                            try:child.terminate()
                            except psutil.Error:pass
                    except psutil.Error:pass
                    browser.terminate()
                    browser.wait(timeout=3)
        self.stop_runtime(runtime)
        del self.active[channel_id]

    def start_router(self, channels, global_channel=None):
        if not is_admin():
            raise RuntimeError('TUN 分流需要管理员权限。请先点击「管理员重启」。')
        if self.router:
            raise RuntimeError('TUN 已运行。修改分配后先停用再启用。')
        info=scan_network()
        if any(route['DestinationPrefix'] in ('0.0.0.0/1','128.0.0.0/1') for route in info.get('routes',[])):
            raise RuntimeError('检测到现有 VPN 拆分路由。请先手动断开该 VPN，再启用 TUN。')
        guards={rule['Name'] for rule in list_guards() if str(rule.get('Enabled','')).lower() in ('1','true')}
        conflicted=[app['path'] for channel in channels if channel['id'] in self.active for app in channel.get('apps',[])
                    if firewall_rule_name(app['path']) in guards]
        if conflicted or (global_channel and guards):
            raise RuntimeError('存在「只许本地代理」的直连阻断规则，不能与 TUN 接入混用。请先在设置与恢复中移除相关规则。')
        port,secret = free_port(),secrets.token_hex(24)
        # Other owned cores must bypass this router, otherwise their outbound TCP loops back into themselves.
        core_paths=list(dict.fromkeys([str(self.core)]+[str(r['core']) for r in self.active.values()]))
        config = router_config(channels,self.active,port,secret,global_channel,core_paths)
        self.router = self.start_config('router',config,port,secret)
        self.router['global_channel']=global_channel

    def stop_router(self):
        if self.router:
            self.stop_runtime(self.router)
            self.router = None

    def stop_all(self):
        self.stop_router()
        for channel_id in list(self.active):
            self.stop(channel_id)

    def rebind(self,channel):
        """Preserve the proxy endpoint and child apps while changing physical/VPN binding."""
        from .presets import require_interface
        require_interface(channel,scan_network())
        runtime=self.active[channel['id']]
        self.stop_runtime(runtime)
        config=channel_config(channel,runtime['port'],runtime['api_port'],runtime['username'],runtime['password'],runtime['secret'])
        replacement=self.start_config(channel['id'],config,runtime['api_port'],runtime['secret'],runtime['core'])
        runtime.update(replacement,channel=copy.deepcopy(channel),started=time.time())
        self.write_browser_manifest(channel,runtime)
        return runtime

    def pause(self,channel_id):
        """Close transport without killing apps; their fixed proxy becomes unavailable."""
        runtime=self.active.get(channel_id)
        if runtime:self.stop_runtime(runtime)

    def proxy(self,channel_id):
        runtime = self.active[channel_id]
        return f"http://{runtime['username']}:{runtime['password']}@127.0.0.1:{runtime['port']}"

    def connections(self,channel_id):
        runtime = self.active[channel_id]
        with session() as http:
            result = http.get(f"http://127.0.0.1:{runtime['api_port']}/connections",
                              headers={'Authorization':'Bearer '+runtime['secret']},timeout=3)
            result.raise_for_status()
            return result.json()

    def launch_browser(self, channel_id, url='', native_browser=None):
        runtime = self.active[channel_id]
        if any(p.poll() is None for p in runtime['browsers']):
            raise RuntimeError('这条信道的浏览器已运行，请切换到现有窗口；不同信道可同时打开。')
        if native_browser and not Path(native_browser).is_file():raise ValueError('浏览器文件不存在。')
        self.write_browser_manifest(runtime['channel'],runtime,native_browser)
        runtime['native_browser']=native_browser
        args = [sys.executable]
        if not getattr(sys,'frozen',False):
            args += [str(resource_root()/'main.py')]
        args += ['--browser-worker',str(runtime['folder']/'browser.dpapi')]
        if url:
            args += ['--url',url]
        log = open(runtime['folder']/'browser.log','ab',buffering=0)
        try:
            p = subprocess.Popen(args,creationflags=HIDDEN,stdout=log,stderr=log)
            self.job.add(p)
            runtime['browsers'].append(p)
        finally:
            log.close()
        return p

    def launch_app(self,channel_id,path,arguments=None):
        runtime = self.active[channel_id]
        if not Path(path).is_file():
            raise ValueError('程序文件不存在。')
        from .browser import is_chromium_browser
        if is_chromium_browser(path):
            process=self.launch_browser(channel_id,next((a for a in (arguments or []) if a.startswith(('http://','https://'))),''),path)
            runtime.setdefault('launches',{})[str(Path(path).resolve()).casefold()]=(process,'专用浏览器会话 · 固定信道代理')
            return process
        environment = os.environ.copy()
        proxy = self.proxy(channel_id)
        for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):
            environment[key] = proxy
        for key in ('NO_PROXY','no_proxy'):
            environment[key] = ''
        # TZ is inherited metadata, not a guarantee that an arbitrary Windows app obeys it.
        environment['TZ'] = runtime['channel']['timezone']
        p = subprocess.Popen([path]+(arguments or []),env=environment,cwd=str(Path(path).parent),creationflags=0)
        self.job.add(p)
        runtime['apps'].append(p)
        runtime.setdefault('launches',{})[str(Path(path).resolve()).casefold()]=(p,'代理变量启动 · 应用是否遵守待实测')
        return p
