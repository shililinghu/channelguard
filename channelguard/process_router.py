"""Explicit full-path native process routing, independent of proxy environment variables."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import psutil
from .storage import atomic_write,dpapi
from .system import HIDDEN

def image_path(path):
    result=str(Path(path).resolve())
    if Path(result).suffix.casefold()!='.exe' or not Path(result).is_file():
        raise ValueError('请选择已存在的 EXE 文件。')
    if any(c in result for c in '*?;,\n\r') or len(result.encode('utf-8'))>=1000:
        raise ValueError('程序路径包含规则分隔符或过长，无法安全接管。')
    return result

def folder_pattern(path):
    root=Path(path).resolve()
    broad=[Path(root.anchor)]+[Path(os.environ.get(key,default)).resolve() for key,default in (
        ('WINDIR','C:/Windows'),('USERPROFILE','C:/Users'),('ProgramFiles','C:/Program Files'),
        ('ProgramFiles(x86)','C:/Program Files (x86)'),('LOCALAPPDATA','C:/Users/Default/AppData/Local'),('APPDATA','C:/Users/Default/AppData/Roaming'))]
    if not root.is_dir() or root in broad or len(root.parts)<2 or any(x in str(root) for x in '*?;,\n\r'):
        raise ValueError('目录规则需要具体应用或游戏库目录，不能选择磁盘根目录、Windows 或用户根目录。')
    return str(root).rstrip('\\/')+'\\*'

def make_plan(channels,runtimes,root):
    proxies=[];rules={}
    forbidden=Path(root).resolve()/'engines'
    owned=[forbidden,Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parents[1]))/'vendor',Path(sys.executable).resolve()]
    for channel in channels:
        identity=channel['id'];runtime=runtimes.get(identity)
        ready=bool(runtime and runtime['process'].poll() is None and not channel.get('monitor_paused'))
        if ready:
            proxies.append(dict(channel_id=identity,port=runtime['port'],username=runtime['username'],password=runtime['password']))
        for app in channel.get('apps',[]):
            path=Path(app['path']).resolve()
            if any(path==p or path.is_relative_to(p) for p in owned):raise ValueError('网络内核和分流宿主不能作为待分流应用。')
            # Updaters may replace the launcher; keep an existing game/service folder covered.
            patterns=[image_path(path)] if path.is_file() else []
            for value in app.get('routing_roots',[]):
                folder=Path(value).resolve()
                if any(p==folder or p.is_relative_to(folder) for p in owned):raise ValueError('目录范围包含分流宿主或网络内核，会造成网络循环。请选择更具体的应用目录。')
                if folder.is_dir():patterns.append(folder_pattern(folder))
            for pattern in patterns:
                key=pattern.casefold()
                if key in rules and rules[key]['channel_id']!=identity:raise ValueError('同一程序或目录不能分配到不同信道。')
                rules[key]=dict(pattern=pattern,channel_id=identity,blocked=not ready)
    # Specific EXEs override directory rules, then more specific directories first.
    ordered=sorted(rules.values(),key=lambda r:('*' in r['pattern'],-len(r['pattern']),r['pattern'].casefold()))
    if len(proxies)>32 or len(ordered)>4000:raise ValueError('系统分流规则数量超过当前内核容量。')
    bypass=[str(forbidden)+'\\*',str(owned[1])+'\\*',str(Path(sys.executable).resolve())]
    return dict(proxies=proxies,rules=ordered,bypass_patterns=bypass)

class Flow(C.Structure):
    _fields_=[('id',C.c_uint64),('pid',C.c_uint32),('proxy_id',C.c_uint32),('rule_id',C.c_uint32),
              ('age_ms',C.c_uint32),('sent',C.c_uint64),('received',C.c_uint64),('port',C.c_uint16),
              ('udp',C.c_uint8),('ipv6',C.c_uint8),('destination',C.c_uint8*16),('name',C.c_char*40),('host',C.c_char*64)]

class NativeRouter:
    def __init__(self,folder):
        folder=Path(folder).resolve()
        metadata=json.loads((folder/'PROVENANCE.json').read_text(encoding='utf-8'))
        for name,digest in metadata['files'].items():
            if hashlib.sha256((folder/name).read_bytes()).hexdigest()!=digest:
                raise RuntimeError('系统分流组件校验失败，请重新解压完整发行包。')
        self.directory=os.add_dll_directory(str(folder))
        self.dll=C.CDLL(str(folder/'ChannelGuardRoute.dll'))
        self.configs={};self.proxy_settings={};self.rules={};self.running=False;self.failure=None
        for name,args,result in [
            ('AddProxyConfig',[C.c_int,C.c_char_p,C.c_uint16,C.c_char_p,C.c_char_p,W.BOOL],C.c_uint32),
            ('EditProxyConfig',[C.c_uint32,C.c_int,C.c_char_p,C.c_uint16,C.c_char_p,C.c_char_p,W.BOOL],W.BOOL),
            ('AddRule',[C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_int,C.c_int,C.c_uint32,W.BOOL],C.c_uint32),
            ('EditRule',[C.c_uint32,C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_int,C.c_int,C.c_uint32,W.BOOL],W.BOOL),
            ('DeleteRule',[C.c_uint32],W.BOOL),('MoveRuleToPosition',[C.c_uint32,C.c_uint32],W.BOOL),
            ('GetFlows',[C.POINTER(Flow),C.c_uint32],C.c_uint32),('Start',[],W.BOOL),('Stop',[],W.BOOL),
            ('SetTrafficLoggingEnabled',[W.BOOL],None)]:
            function=getattr(self.dll,'ProxyBridge_'+name);function.argtypes=args;function.restype=result
        self.log_type=C.CFUNCTYPE(None,C.c_char_p)
        def log(message):
            # Never retain raw messages: only extract the driver error number.
            import re
            found=re.search(rb'Failed to open WinDivert \((\d+)\)',message or b'')
            if found:self.failure=int(found[1])
        self.log=self.log_type(log)
        self.dll.ProxyBridge_SetLogCallback.argtypes=[self.log_type]
        self.dll.ProxyBridge_SetLogCallback(self.log)
        self.dll.ProxyBridge_SetTrafficLoggingEnabled(False)

    def apply(self,plan):
        by_channel={}
        for proxy in plan['proxies']:
            identity=proxy['channel_id'];args=(1,b'127.0.0.1',int(proxy['port']),proxy['username'].encode(),proxy['password'].encode(),False)
            if not 1<=args[2]<=65535:raise ValueError('本地代理端口无效。')
            if identity not in self.configs:
                value=self.dll.ProxyBridge_AddProxyConfig(*args)
                if not value:raise RuntimeError('系统分流代理配置失败。')
                self.configs[identity]=value
            elif self.proxy_settings.get(identity)!=args:
                if not self.dll.ProxyBridge_EditProxyConfig(self.configs[identity],*args):raise RuntimeError('系统分流代理更新失败。')
            self.proxy_settings[identity]=args
            by_channel[identity]=self.configs[identity]
        wanted=set()
        bypass=[dict(pattern=p,channel_id=None,blocked=False,bypass=True) for p in plan.get('bypass_patterns',[])]
        for position,rule in enumerate(bypass+plan['rules'],1):
            pattern=rule['pattern'];wanted.add(pattern)
            config=by_channel.get(rule['channel_id'],0)
            action=1 if rule.get('bypass') else 2 if rule['blocked'] or not config else 0
            args=(pattern.encode('utf-8'),b'*',b'*',b'',2,action,config,False)
            if pattern in self.rules:
                if not self.dll.ProxyBridge_EditRule(self.rules[pattern],*args):raise RuntimeError('系统规则更新失败。')
            else:
                value=self.dll.ProxyBridge_AddRule(*args)
                if not value:raise RuntimeError('系统规则创建失败。')
                self.rules[pattern]=value
            self.dll.ProxyBridge_MoveRuleToPosition(self.rules[pattern],position)
        for pattern in list(self.rules):
            if pattern not in wanted:self.dll.ProxyBridge_DeleteRule(self.rules.pop(pattern))

    def start(self):
        if not self.dll.ProxyBridge_Start():
            raise RuntimeError('系统分流驱动未启动，错误码 '+str(self.failure or '未知')+'；应用尚未接管。')
        self.running=True

    def flows(self):
        values=(Flow*400)();count=self.dll.ProxyBridge_GetFlows(values,400)
        channels={value:key for key,value in self.configs.items()}
        patterns={value:key for key,value in self.rules.items()}
        return [dict(id=x.id,pid=x.pid,channel_id=channels.get(x.proxy_id),protocol='UDP' if x.udp else 'TCP',
                     age_ms=x.age_ms,destination_ip=socket.inet_ntop(socket.AF_INET6 if x.ipv6 else socket.AF_INET,bytes(x.destination)[:16 if x.ipv6 else 4]),
                     matched_pattern=patterns.get(x.rule_id,''),
                     destination=bytes(x.host).decode('utf-8',errors='replace'),port=x.port,sent=x.sent,received=x.received,
                     application=bytes(x.name).decode('utf-8',errors='replace')) for x in values[:count]]

    def close(self):
        if self.running:self.dll.ProxyBridge_Stop();self.running=False

class ProcessRouting:
    def __init__(self,store,engines):
        self.store,self.engines=store,engines
        self.folder=store.root/'process-routing';self.folder.mkdir(exist_ok=True)
        self.manifest=self.folder/'control.dpapi';self.status_path=self.folder/'status.json'
        self.token=secrets.token_hex(24);self.enabled=False;self.last_plan=None

    def publish(self):
        data=make_plan(self.store.data['channels'],self.engines.active,self.store.root)
        data.update(enabled=self.enabled,token=self.token,parent_pid=os.getpid(),parent_created=psutil.Process().create_time(),updated=time.time())
        atomic_write(self.manifest,dpapi(json.dumps(data,ensure_ascii=False).encode()))

    def start(self):
        if self.engines.router:raise RuntimeError('请先停用 TUN；两种系统接入不能同时运行。')
        if not any(c.get('apps') for c in self.store.data['channels']):raise ValueError('先添加要接管的应用。')
        self.token=secrets.token_hex(24)
        self.enabled=True;self.publish()
        args=[] if getattr(sys,'frozen',False) else [str(Path(__file__).resolve().parents[1]/'main.py')]
        args+=['--process-worker',str(self.manifest)]
        parameters=subprocess.list2cmdline(args)
        # Only this narrow worker is elevated; the GUI and channel cores remain standard-user processes.
        result=C.windll.shell32.ShellExecuteW(None,'runas',sys.executable,parameters,None,0)
        if result<=32:
            self.enabled=False;self.publish();raise RuntimeError('未取得系统分流权限；应用仍使用原网络。')
        self.store.data['process_routing']={'enabled':True};self.store.save()

    def status(self):
        try:
            result=json.loads(self.status_path.read_text(encoding='utf-8'))
            if result.get('token')!=self.token:return {'state':'starting' if self.enabled else 'stopped'}
            if result.get('state')=='error':return result
            if time.time()-result.get('at',0)>5:
                if self.enabled and result.get('state')=='running':return {'state':'error','message':'系统分流辅助进程失联，应用可能恢复系统网络；请重新开启并验证。'}
                return {'state':'starting' if self.enabled else 'stopped'}
            if not self.enabled and result.get('state')=='running':return {'state':'stopping'}
            return result
        except (OSError,ValueError):return {'state':'starting' if self.enabled else 'stopped'}

    def stop(self):
        self.enabled=False;self.publish()
        self.store.data['process_routing']={'enabled':False};self.store.save()

    def close(self):
        self.enabled=False
        if self.manifest.exists():self.publish()
