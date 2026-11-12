"""Elevated driver host. No GUI automation, arbitrary commands, or global routing changes."""
from pathlib import Path
import json
import os
import sys
import time
import psutil
from .engine import resource_root
from .process_router import NativeRouter
from .storage import atomic_write,dpapi
from .system import is_admin,powershell,ps_quote

def relay_firewall(name,install):
    if install:
        exe=ps_quote(sys.executable)
        # Relay packets retain the original destination as their apparent source.
        # Permit only the host program's two relay ports, never its other listeners.
        script=f"New-NetFirewallRule -Name {ps_quote(name+'-TCP')} -DisplayName 'ChannelGuard TCP relay' -Group 'ChannelGuardRelay' -Direction Inbound -Action Allow -Enabled True -Profile Any -Program {exe} -Protocol TCP -LocalPort 34010 | Out-Null;"
        script+=f"New-NetFirewallRule -Name {ps_quote(name+'-UDP')} -DisplayName 'ChannelGuard UDP relay' -Group 'ChannelGuardRelay' -Direction Inbound -Action Allow -Enabled True -Profile Any -Program {exe} -Protocol UDP -LocalPort 34011 | Out-Null"
    else:
        script=f"Get-NetFirewallRule -Name {ps_quote(name+'-*')} -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
    powershell(script)

def run_worker(manifest_path):
    manifest_path=Path(manifest_path).resolve()
    base=Path(os.environ['LOCALAPPDATA'])/'ChannelGuard'
    if not manifest_path.is_relative_to(base.resolve()) or manifest_path.name!='control.dpapi':
        raise ValueError('系统分流控制文件必须位于本用户的 ChannelGuard 数据目录。')
    status_path=manifest_path.parent/'status.json'
    native=None;token=None;rule_name=None
    def status(state,**extra):
        atomic_write(status_path,json.dumps(dict(state=state,at=time.time(),sample_monotonic=time.monotonic(),token=token,worker_pid=os.getpid(),**extra),ensure_ascii=False).encode())
    try:
        if not is_admin():raise RuntimeError('系统分流需要管理员权限，当前未接管应用。')
        data=json.loads(dpapi(manifest_path.read_bytes(),True));token=data['token']
        parent=psutil.Process(data['parent_pid'])
        if abs(parent.create_time()-data['parent_created'])>.01:raise RuntimeError('控制进程已更换。')
        # Refuse concurrent instances before touching any firewall rules or driver handles.
        import socket
        for port,kind in ((34010,socket.SOCK_STREAM),(34011,socket.SOCK_DGRAM)):
            with socket.socket(socket.AF_INET,kind) as probe:probe.bind(('0.0.0.0',port))
        native=NativeRouter(resource_root()/'vendor/process_router')
        plan={key:data.get(key,[]) for key in ('proxies','rules','bypass_patterns')}
        native.apply(plan)
        rule_name='ChannelGuardRelay-'+token[:20]
        relay_firewall(rule_name,True)
        native.start()
        last=plan;last_read=time.time()
        while True:
            try:
                current=json.loads(dpapi(manifest_path.read_bytes(),True))
            except (OSError,ValueError):
                if not parent.is_running() or time.time()-last_read>20:break
                time.sleep(.05);continue
            last_read=time.time()
            if current.get('token')!=token or not current.get('enabled'):break
            if not parent.is_running() or abs(parent.create_time()-data['parent_created'])>.01:break
            if time.time()-current.get('updated',0)>20:
                status('error',message='控制台心跳中断，系统分流即将退出；应用将恢复系统网络。');break
            plan={key:current.get(key,[]) for key in ('proxies','rules','bypass_patterns')}
            if plan!=last:native.apply(plan);last=plan
            status('running',rule_count=len(native.rules),flows=native.flows(),blocked=sum(r['blocked'] for r in last['rules']))
            time.sleep(.5)
        native.close();native=None
        status('stopped',message='系统接管已停止，新连接使用系统网络。')
    except Exception as exc:
        message=str(exc) if isinstance(exc,(RuntimeError,ValueError)) else '系统分流启动失败（'+type(exc).__name__+'），未验证接管。'
        status('error',message=message)
    finally:
        if native:native.close()
        if rule_name:
            try:relay_firewall(rule_name,False)
            except Exception:status('error',message='分流已停止；临时中继防火墙规则未能清理，请在设置中检查。')
