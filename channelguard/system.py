from __future__ import annotations
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import psutil

HIDDEN = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

def powershell(script, timeout=25):
    command = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();$OutputEncoding=[Console]::OutputEncoding;$ErrorActionPreference='Stop';" + script
    p = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                       capture_output=True, encoding='utf-8', errors='replace', timeout=timeout, creationflags=HIDDEN)
    if p.returncode:
        raise RuntimeError(p.stderr.strip()[-1500:] or 'PowerShell 执行失败')
    return p.stdout.strip()

def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"

def split_windows_arguments(text):
    if not text.strip():return []
    shell=ctypes.windll.shell32
    shell.CommandLineToArgvW.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype=ctypes.POINTER(wintypes.LPWSTR)
    count=ctypes.c_int()
    pointer=shell.CommandLineToArgvW('placeholder.exe '+text,ctypes.byref(count))
    if not pointer:raise ctypes.WinError()
    try:return [pointer[i] for i in range(1,count.value)]
    finally:ctypes.windll.kernel32.LocalFree(pointer)

def is_admin():
    return bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == 'nt' else False

def scan_network():
    script = r"""
    $adapters=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,ifIndex,LinkSpeed,@{n='Guid';e={$_.InterfaceGuid.ToString()}},@{n='Hardware';e={[bool]$_.HardwareInterface}});
    $configs=@(Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceIndex,@{n='IPv4';e={[string[]]@($_.IPv4Address.IPAddress)}},@{n='Gateway';e={[string[]]@($_.IPv4DefaultGateway.NextHop)}},@{n='Dns';e={[string[]]@($_.DNSServer | ForEach-Object {$_.ServerAddresses} | Select-Object -Unique)}});
    $routes=@(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1')} | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric);
    $proxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';
    @{adapters=$adapters;configs=$configs;routes=$routes;system_proxy=@{enabled=[bool]$proxy.ProxyEnable;server=$proxy.ProxyServer};environment=@{timezone=[TimeZoneInfo]::Local.Id;culture=(Get-Culture).Name}} | ConvertTo-Json -Depth 6 -Compress
    """
    info = json.loads(powershell(script))
    names = {}
    owned_pids=set()
    for p in psutil.process_iter(['name', 'pid','exe']):
        if any(s in (p.info['name'] or '').lower() for s in ('clash', 'mihomo', 'xray', 'sing-box', 'openvpn')):
            names[p.pid] = p.info['name']
            exe=p.info.get('exe')
            if exe and ((Path(exe).parent.name=='vendor' and (Path(exe).parent/'mihomo-release.json').exists())
                        or (Path(exe).parent/'channelguard-owned-core.json').exists()):
                owned_pids.add(p.pid)
    listeners = []
    try:
        for c in psutil.net_connections('tcp'):
            if c.status == 'LISTEN' and c.laddr and (c.pid in names or c.laddr.port in (7890, 7897, 1080, 10808, 10809)):
                listeners.append(dict(host=c.laddr.ip, port=c.laddr.port, process=names.get(c.pid, '未知程序'),pid=c.pid,owned=c.pid in owned_pids))
    except (psutil.AccessDenied, OSError):
        pass
    info['listeners'] = listeners
    return info

def running_apps():
    items = {}
    for p in psutil.process_iter(['name', 'exe', 'pid']):
        try:
            path = p.info['exe']
            if path and not path.lower().startswith(str(Path(os.environ.get('WINDIR', 'C:/Windows'))).lower()):
                items[path.lower()] = dict(name=p.info['name'], path=path, pid=p.pid)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return sorted(items.values(), key=lambda v: v['name'].lower())

def secure_folder(path):
    """Remove inherited permissions, grant current SID and SYSTEM only."""
    sid = powershell('[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value')
    result = subprocess.run(['icacls.exe', str(path), '/inheritance:r', '/grant:r',
                             f'*{sid}:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'],
                            capture_output=True, creationflags=HIDDEN, timeout=15)
    if result.returncode:
        raise RuntimeError('无法限制数据目录权限，拒绝创建含凭据的运行配置。')

class ChildJob:
    """Close all owned engine / browser processes if GUI dies (Windows Job Object)."""
    def __init__(self):
        self.handle = None
        if os.name != 'nt':
            return
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_ = [('ProcessTime',ctypes.c_int64),('JobTime',ctypes.c_int64),('Flags',w.DWORD),
                        ('Min',ctypes.c_size_t),('Max',ctypes.c_size_t),('Active',w.DWORD),
                        ('Affinity',ctypes.c_size_t),('Priority',w.DWORD),('Scheduling',w.DWORD)]
        class Io(ctypes.Structure):
            _fields_ = [(n,ctypes.c_uint64) for n in ('ReadOps','WriteOps','OtherOps','ReadBytes','WriteBytes','OtherBytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('Basic',Basic),('Io',Io),('ProcessMemory',ctypes.c_size_t),('JobMemory',ctypes.c_size_t),
                        ('PeakProcess',ctypes.c_size_t),('PeakJob',ctypes.c_size_t)]
        k = ctypes.windll.kernel32
        k.CreateJobObjectW.restype = w.HANDLE
        k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        k.CloseHandle.argtypes = [w.HANDLE]
        self.handle = k.CreateJobObjectW(None, None)
        info = Extended()
        info.Basic.Flags = 0x2000
        if not self.handle or not k.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError()

    def add(self, process):
        if self.handle and not ctypes.windll.kernel32.AssignProcessToJobObject(self.handle, int(process._handle)):
            process.terminate()
            raise RuntimeError('无法纳管子进程，已取消启动以避免程序退出后残留连接。')

    def close(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

def elevate(args):
    parameters = subprocess.list2cmdline(args)
    result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, parameters, None, 0)
    if result <= 32:
        raise RuntimeError('未取得管理员权限，当前网络设置未修改。')

def firewall_rule_name(path):
    import hashlib
    return 'ChannelGuard-' + hashlib.sha256(str(Path(path).resolve()).lower().encode()).hexdigest()[:20]

def install_guard(path):
    if not is_admin():
        raise RuntimeError('应用直连阻断需要以管理员身份启动本工具。')
    program = str(Path(path).resolve())
    if not Path(program).is_file() or Path(program).suffix.lower() != '.exe':
        raise ValueError('请选择实际的 .exe 程序。')
    name = firewall_rule_name(program)
    # Direct non-loopback traffic is denied. Proxy transport is owned by mihomo, not this executable.
    script = "$profiles=@(Get-NetFirewallProfile);if (@($profiles | Where-Object {-not $_.Enabled}).Count -gt 0) {throw '请先启用全部 Windows 防火墙配置文件'};"
    script += f"$r=Get-NetFirewallRule -Name {ps_quote(name)} -ErrorAction SilentlyContinue;"
    script += f"if (-not $r) {{New-NetFirewallRule -Name {ps_quote(name)} -DisplayName {ps_quote('ChannelGuard 本地代理限定 '+Path(program).name)} -Group 'ChannelGuard' -Direction Outbound -Action Block -Enabled True -Profile Any -Program {ps_quote(program)} -RemoteAddress @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::/128','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') | Out-Null}}"
    powershell(script)
    return name

def remove_guard(name):
    if not name.startswith('ChannelGuard-') or len(name) != 33:
        raise ValueError('不是本工具创建的防火墙规则。')
    powershell(f"Get-NetFirewallRule -Name {ps_quote(name)} -ErrorAction SilentlyContinue | Remove-NetFirewallRule")

def list_guards():
    result = powershell("@(Get-NetFirewallRule -Group 'ChannelGuard' -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Enabled) | ConvertTo-Json -Compress")
    data = json.loads(result) if result else []
    return data if isinstance(data,list) else [data]
