"""Discover real local exits and prepare channel profiles without changing system routes."""
from __future__ import annotations
import copy
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from .storage import new_channel

WINDOWS_TIMEZONES = {
    'China Standard Time':'Asia/Shanghai','Tokyo Standard Time':'Asia/Tokyo',
    'Singapore Standard Time':'Asia/Singapore','Pacific Standard Time':'America/Los_Angeles',
    'Eastern Standard Time':'America/New_York','Central Standard Time':'America/Chicago',
    'Mountain Standard Time':'America/Denver','GMT Standard Time':'Europe/London',
    'W. Europe Standard Time':'Europe/Berlin','India Standard Time':'Asia/Kolkata','UTC':'UTC',
}

def values(value):
    if isinstance(value,dict):value=value.get('value',[])
    if value is None:return []
    return value if isinstance(value,list) else [value]

def local_host(host):
    if host in ('0.0.0.0','127.0.0.1','localhost'):return '127.0.0.1'
    if host in ('::','::1'):return '::1'
    try:return host if ipaddress.ip_address(host).is_loopback else None
    except ValueError:return None

def probe_proxy(host,port,timeout=.7):
    """Only loopback handshakes. Never connect to a remote destination or send stored credentials."""
    host=local_host(host)
    if not host:return dict(state='unsupported',detail='自动识别仅探测本机回环代理。')
    try:
        with socket.create_connection((host,int(port)),timeout=timeout) as connection:
            connection.settimeout(timeout);connection.sendall(b'\x05\x02\x00\x02')
            response=connection.recv(2)
            if len(response)==2 and response[0]==5:
                if response[1]==0:return dict(state='ready',protocol='socks5',detail='SOCKS5 握手成功；互联网出口尚待检测。')
                if response[1]==2:return dict(state='auth',protocol='socks5',detail='SOCKS5 需要用户名和密码，请编辑此信道。')
                return dict(state='unknown',detail='SOCKS5 未接受本机无认证接入。')
    except (OSError,ValueError):pass
    try:
        with socket.create_connection((host,int(port)),timeout=timeout) as connection:
            connection.settimeout(timeout)
            # A closed loopback target identifies CONNECT support without any remote DNS / traffic.
            connection.sendall(b'CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n')
            response=connection.recv(1024).split(b'\r\n',1)[0]
            match=re.match(rb'HTTP/1\.[01] (\d{3})',response)
            if match:
                code=int(match[1])
                if code==407:return dict(state='auth',protocol='http',detail='HTTP 代理需要认证，请编辑此信道。')
                if code in (200,502,503,504):return dict(state='ready',protocol='http',detail='识别到 HTTP CONNECT 代理响应；互联网出口尚待检测。')
                return dict(state='unknown',detail='端口返回 HTTP，但尚未确认可作为代理。')
    except (OSError,ValueError):pass
    return dict(state='offline',detail='代理握手未成功；可能尚未启动、需要认证或使用其他协议。')

def inspect_local_proxies(info,exclude_pids=()):
    result=copy.deepcopy(info)
    endpoints={}
    for listener in info.get('listeners',[]):
        if listener.get('pid') in exclude_pids or listener.get('owned'):continue
        # OpenVPN's management port is not a browser / application proxy.
        if 'openvpn' in listener.get('process','').lower():continue
        host=local_host(listener.get('host',''))
        if host and host!='::1':
            endpoints[(host,int(listener['port']))]=dict(listener,host=host)
    # Include configured loopback proxy even when its switch is off; label offline honestly.
    raw=info.get('system_proxy',{}).get('server') or ''
    for endpoint in raw.split(';'):
        match=re.fullmatch(r'(?:(?:https?|socks)=)?(127\.\d+\.\d+\.\d+|localhost):(\d+)',endpoint.strip(),re.I)
        if match:
            key=('127.0.0.1' if match[1].lower()=='localhost' else match[1],int(match[2]))
            endpoints.setdefault(key,dict(host=key[0],port=key[1],process='系统已配置代理',configured=True))
    entries=list(endpoints.values())[:24]
    def inspect(entry):return dict(entry,probe=probe_proxy(entry['host'],entry['port']))
    with ThreadPoolExecutor(max_workers=6) as pool:result['proxy_candidates']=list(pool.map(inspect,entries))
    return result

def system_environment(info):
    env=info.get('environment',{})
    return WINDOWS_TIMEZONES.get(env.get('timezone'),'UTC'),env.get('culture') or 'en-US'

def candidates(info):
    timezone,locale=system_environment(info)
    def profile(key,name,kind,readiness,detail,**kwargs):
        channel=new_channel(name)
        channel.update(timezone=timezone,locale=locale,latitude=0,longitude=0,**kwargs)
        channel['discovery']=dict(key=key,kind=kind,managed=True,readiness=readiness,detail=detail,
                                  environment_source='继承 Windows 时区和语言；尚未按出口所在地校准',
                                  environment_defaults=dict(timezone=timezone,locale=locale))
        return channel
    system_ready=bool(info.get('routes'))
    output=[profile('system','系统默认信道','system','ready' if system_ready else 'offline',
                    '跟随当前 Windows 路由，包括现有 VPN；可启动，实际出口待检测。' if system_ready else '尚未发现系统默认出口路由。')]
    configs={c['InterfaceAlias']:c for c in info.get('configs',[])}
    routed={r['InterfaceAlias'] for r in info.get('routes',[])}
    for adapter in info.get('adapters',[]):
        name=adapter['Name'];description=adapter.get('InterfaceDescription','');text=(name+' '+description).lower()
        if any(word in text for word in ('wsl','hyper-v','vethernet','virtualbox','vmware','docker','loopback','channelguard')):continue
        physical=adapter.get('Hardware',False) or any(word in text for word in ('wi-fi','wifi','wlan','802.11','realtek pcie','ethernet connection'))
        vpn=any(word in text for word in ('vpn','tap-windows','wireguard','wintun','atrust','vnic','tunnel'))
        if not physical and not vpn:continue
        connected=str(adapter.get('Status','')).lower()=='up'
        config=configs.get(name,{})
        addresses=values(config.get('IPv4'))
        has_ip=any(ip and not str(ip).startswith('169.254.') for ip in addresses)
        route=bool(values(config.get('Gateway'))) or name in routed
        ready=connected and has_ip and route
        wifi=any(word in text for word in ('wi-fi','wifi','wlan','802.11'))
        kind='vpn' if vpn and not physical else ('wifi' if wifi else 'ethernet')
        if not connected:readiness,detail='offline','网卡尚未连接，连接后重新识别即可使用。'
        elif not has_ip:readiness,detail='offline','尚未获得可用的 IPv4 地址。'
        elif not route:readiness,detail='route_pending','连接已启用，但尚未发现默认出口路由，不能确认可独立上网。'
        else:readiness,detail='ready','连接及出口路由已发现；网卡绑定后的互联网可达性仍需检测。'
        key='adapter:'+str(adapter.get('Guid') or adapter.get('ifIndex') or name)
        output.append(profile(key,('VPN · ' if kind=='vpn' else 'Wi-Fi · ' if kind=='wifi' else '有线 · ')+name,
                              kind,readiness,detail,interface=name))
    for proxy in info.get('proxy_candidates',[]):
        probe=proxy.get('probe',{});protocol=probe.get('protocol')
        label='SOCKS5' if protocol=='socks5' else 'HTTP' if protocol=='http' else '代理'
        node=dict(name=f"{proxy['process']} 本机入口",type=protocol or 'http',server=proxy['host'],port=proxy['port'])
        output.append(profile(f"proxy:{proxy['host']}:{proxy['port']}",f"{proxy['process']} · {label} {proxy['port']}",
                              'proxy',probe.get('state','unknown'),probe.get('detail','代理协议待确认。'),node=node))
    output.append(profile('future-vps','海外 VPS · 待接入','template','needs_node',
                          '已预设独立浏览器、拒绝定位和防泄露策略；导入真实节点后才能启动。',
                          setup_required='先编辑这条信道，填写代理地址或导入海外 VPS 的客户端节点。'))
    kind_order={'system':0,'wifi':1,'ethernet':2,'vpn':3,'proxy':4,'template':5}
    output.sort(key=lambda c:(0 if c['discovery']['readiness']=='ready' else 2 if c['discovery']['kind']=='template' else 1,
                              kind_order.get(c['discovery']['kind'],9)))
    return output

def reconcile(store,info,active_ids=()):
    """Idempotent, preserve IDs / user changes / assignments; never invent usable overseas exits."""
    channels=store.data['channels'];desired=candidates(info)
    suppressed=set(store.data.get('discovery_suppressed',[]));changed=False;added=[]
    # Upgrade the untouched v0.1 default in place, retaining its browser profile identity.
    if not any(c.get('discovery',{}).get('key')=='system' for c in channels):
        legacy=next((c for c in channels if c['name']=='本地信道' and not c.get('interface') and not c.get('node') and not c.get('notes')),None)
        if legacy:
            if (legacy.get('timezone'),legacy.get('locale'))==('Asia/Shanghai','zh-CN'):
                legacy.update(timezone=desired[0]['timezone'],locale=desired[0]['locale'])
            legacy['discovery']=copy.deepcopy(desired[0]['discovery'])
            legacy['name']='系统默认信道';changed=True
    existing={c.get('discovery',{}).get('key'):c for c in channels if c.get('discovery',{}).get('key')}
    for candidate in desired:
        key=candidate['discovery']['key'];current=existing.get(key)
        if current is None:
            if key not in suppressed:channels.append(candidate);added.append(candidate['name']);changed=True
            continue
        if not current.get('discovery',{}).get('managed',True) or current['id'] in active_ids:continue
        # Node credentials, app assignments, environment choices and notes are never overwritten.
        current_node=current.get('node')
        previous_defaults=current['discovery'].get('environment_defaults',{})
        patch=dict(name=candidate['name'],discovery=copy.deepcopy(candidate['discovery']),interface=candidate['interface'])
        for field in ('timezone','locale'):
            if current.get(field)==previous_defaults.get(field):patch[field]=candidate[field]
        if any(patch.get(field,current.get(field))!=candidate[field] for field in ('timezone','locale')):
            patch['discovery']['environment_source']='已保留原有时区或语言；尚未按出口所在地校准'
        if current['discovery'].get('kind')=='proxy' and candidate['discovery']['readiness']=='ready' and current_node and not current_node.get('username'):
            patch['node']=dict(current_node,type=candidate['node']['type'])
        if any(current.get(k)!=v for k,v in patch.items()):current.update(patch);changed=True
    present={candidate['discovery']['key'] for candidate in desired}
    for current in channels:
        discovery=current.get('discovery',{})
        if discovery.get('managed') and discovery.get('key') not in present and current['id'] not in active_ids:
            updated=dict(discovery,readiness='offline',detail='本次扫描未发现此出口；配置已保留。')
            if discovery!=updated:current['discovery']=updated;changed=True
    if changed:store.save()
    return added

def require_ready(channel):
    if channel.get('setup_required'):raise ValueError(channel['setup_required'])
    discovery=channel.get('discovery',{})
    if discovery.get('managed') and discovery.get('readiness') not in ('ready',None):
        raise ValueError(discovery.get('detail','出口尚未就绪。')+' 请先修正，再点击「重新识别并预设」。')

def require_interface(channel, info):
    name=channel.get('interface')
    if not name:return
    adapter=next((a for a in values(info.get('adapters',[])) if a.get('Name')==name),None)
    if not adapter or str(adapter.get('Status','')).lower()!='up':
        raise ValueError(f'所选网卡「{name}」尚未连接，不能启动。请先连接该网络或选择其他信道。')


def readiness_label(channel):
    state=channel.get('discovery',{}).get('readiness')
    if channel.get('setup_required'):return '待导入节点'
    return {'ready':'可接入 · 待实测','offline':'未连接 / 握手未成功','route_pending':'待出口路由',
            'auth':'待填写认证','unknown':'待确认协议','unsupported':'暂不支持自动接入','needs_node':'待导入节点'}.get(state,'未启动')
