"""Generate minimal owned mihomo configs; never execute imported subscriptions."""
from __future__ import annotations
import copy
import ipaddress
import re
from urllib.parse import urlsplit, unquote
from zoneinfo import ZoneInfo
import yaml

SUPPORTED = {'http','socks5','ss','vmess','vless','trojan','hysteria2','tuic','wireguard','ssh'}
DROP_FIELDS = {'dialer-proxy', 'interface-name', 'routing-mark', 'tfo', 'smux'}

def validate_channel(channel):
    if not re.fullmatch('[a-f0-9]{32}',channel.get('id','')):
        raise ValueError('信道标识无效。')
    if not channel.get('name','').strip():
        raise ValueError('请填写信道名称。')
    if len(channel['name']) > 60:
        raise ValueError('信道名称最多 60 个字符。')
    ZoneInfo(channel['timezone'])
    if not re.fullmatch(r'[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*', channel['locale']):
        raise ValueError('语言格式示例：zh-CN、en-US、ja-JP。')
    if channel.get('geo') not in ('deny','fixed'):
        raise ValueError('定位策略无效。')
    if not (-90 <= float(channel['latitude']) <= 90 and -180 <= float(channel['longitude']) <= 180):
        raise ValueError('定位经纬度超出范围。')
    doh = urlsplit(channel['doh'])
    if doh.scheme != 'https' or not doh.hostname or doh.fragment or doh.username:
        raise ValueError('DNS 必须是 HTTPS DoH 地址，不能包含认证信息或 #。')
    bootstrap=urlsplit(channel.get('bootstrap_doh','https://1.1.1.1/dns-query'))
    if bootstrap.scheme!='https' or not bootstrap.hostname or bootstrap.fragment or bootstrap.username:
        raise ValueError('引导 DNS 必须是 HTTPS DoH 地址。')
    try:ipaddress.ip_address(bootstrap.hostname)
    except ValueError:raise ValueError('引导 DNS 地址请使用 IP，例如 https://1.1.1.1/dns-query，避免解析循环；证书需支持该 IP。')
    node=channel.get('node')
    if node and channel.get('interface'):
        try:loopback=ipaddress.ip_address(node.get('server','')).is_loopback
        except ValueError:loopback=node.get('server','').lower()=='localhost'
        if loopback:raise ValueError('本机代理的最终网卡由原代理软件管理。请选「跟随系统路由」，或直接导入远端节点后再绑定网卡。')
    country = channel.get('expected_country', '').strip()
    if country and not re.fullmatch('[A-Za-z]{2}', country):
        raise ValueError('预期国家使用两位代码，例如 US、JP、SG。')
    if channel.get('node'):
        validate_node(channel['node'])
    for app in channel.get('apps',[]):
        if any(c in app['path'] for c in (',','\n','\r')):
            raise ValueError('应用路径不能包含逗号或换行（底层规则格式限制）。')

def validate_node(node):
    if not isinstance(node,dict) or node.get('type') not in SUPPORTED:
        raise ValueError('暂不支持这个节点类型。支持 HTTP / SOCKS5 / SS / VMess / VLESS / Trojan / Hysteria2 / TUIC / WireGuard / SSH。')
    if not node.get('server') or not isinstance(node['server'],str) or any(x in node['server'] for x in ('\n','\r','/','@')):
        raise ValueError('节点需要独立的 server 地址，不要在 server 中填写 URL。')
    if not 1 <= int(node.get('port',0)) <= 65535:
        raise ValueError('节点端口必须为 1—65535。')
    if node.get('skip-cert-verify') or node.get('insecure'):
        raise ValueError('此节点关闭了证书验证。请修复证书后导入，第一版不允许跳过 TLS 校验。')
    if node.get('type') in ('http','socks5') and bool(node.get('username')) != bool(node.get('password')):
        raise ValueError('代理用户名和密码需要同时填写。')

def normalize_node(node):
    validate_node(node)
    result = {k:copy.deepcopy(v) for k,v in node.items() if k not in DROP_FIELDS}
    result['name'] = 'CG-EXIT'
    result['port'] = int(result['port'])
    result['udp'] = False
    result['ip-version'] = 'ipv4'
    return result

def parse_nodes(text):
    if len(text.encode('utf-8')) > 2_000_000:
        raise ValueError('导入文件超过 2 MB。请仅导入节点部分。')
    document = yaml.safe_load(text)
    if not isinstance(document,(dict,list)):
        raise ValueError('请选择 Clash/Mihomo YAML 节点配置。')
    nodes = document.get('proxies', [document] if 'type' in document else []) if isinstance(document,dict) else document
    if not isinstance(nodes,list) or not nodes:
        raise ValueError('文件中没有静态 proxies 节点。第一版不执行订阅里的 providers、规则或脚本。')
    output, errors = [], []
    for index,node in enumerate(nodes[:500]):
        try:
            validate_node(node)
            output.append(copy.deepcopy(node))
        except (ValueError,TypeError) as exc:
            errors.append(f'节点 {index+1}：{exc}')
    if not output:
        raise ValueError('\n'.join(errors[:6]))
    return output,errors

def proxy_url_node(url):
    parsed = urlsplit(url.strip())
    if parsed.scheme not in ('socks5','socks5h','http','https') or not parsed.hostname or not parsed.port:
        raise ValueError('格式示例：socks5://127.0.0.1:1080 或 http://127.0.0.1:7897')
    node = dict(name=parsed.hostname,type='socks5' if parsed.scheme.startswith('socks') else 'http',
                server=parsed.hostname, port=parsed.port)
    if node['server'].lower()=='localhost':node['server']='127.0.0.1'
    if parsed.scheme == 'https':
        node['tls'] = True
    if parsed.username:
        node['username'] = unquote(parsed.username)
        node['password'] = unquote(parsed.password or '')
    validate_node(node)
    return node

def channel_config(channel, port, api_port, username, password, secret):
    validate_channel(channel)
    node = normalize_node(channel['node']) if channel.get('node') else dict(name='CG-EXIT', type='direct', udp=False, **{'ip-version':'ipv4'})
    interface = channel.get('interface','')
    if interface:
        node['interface-name'] = interface
    result = {
        'mixed-port':port, 'bind-address':'127.0.0.1', 'allow-lan':False,
        'authentication':[f'{username}:{password}'], 'skip-auth-prefixes':[],
        'mode':'rule','log-level':'warning','ipv6':False,
        'external-controller':f'127.0.0.1:{api_port}','secret':secret,
        'find-process-mode':'off','profile':{'store-selected':False,'store-fake-ip':False},
        'geodata-mode':False,'geo-auto-update':False,
        'dns': {'enable':True,'listen':'127.0.0.1:0','ipv6':False,'enhanced-mode':'redir-host',
                'default-nameserver':[channel.get('bootstrap_doh','https://1.1.1.1/dns-query')],
                'proxy-server-nameserver':[channel.get('bootstrap_doh','https://1.1.1.1/dns-query')],
                'nameserver':[channel['doh']+'#CG-EXIT'], 'use-hosts':False,'use-system-hosts':False},
        'proxies':[node], 'rules':['NETWORK,UDP,REJECT','IP-CIDR6,::/0,REJECT,no-resolve','MATCH,CG-EXIT'],
    }
    if interface:
        result['interface-name'] = interface
    if channel.get('native_udp'):
        if node['type'] in ('http','ssh'):
            raise ValueError('此信道协议不支持 UDP，请使用支持 UDP 的节点。')
        node['udp']=True
        # Explicit IPv6 loopback avoids external VPN IPv4 bind redirection.
        # The GUI exposes an authenticated-core shim on IPv4 loopback only.
        result.update({'allow-lan':True,'bind-address':'[::1]'})
        result['rules']=['IP-CIDR6,::/0,REJECT,no-resolve','MATCH,CG-EXIT']
    return result

def router_config(channels, runtimes, api_port, secret, global_channel=None, bypass_paths=None):
    """TUN is opt-in; per-process DNS cannot be inferred from Windows DNS service."""
    proxies,rules = [],[]
    assigned = set()
    for channel in channels:
        runtime = runtimes.get(channel['id'])
        if not runtime:
            continue
        target = 'CG-'+channel['id']
        proxies.append(dict(name=target,type='socks5',server='127.0.0.1',port=runtime['port'],
                            username=runtime['username'],password=runtime['password'],udp=False))
        for app in channel.get('apps',[]):
            path = app['path']
            if path.casefold() in assigned:
                raise ValueError('同一个程序路径只能分配给一条信道。')
            assigned.add(path.casefold())
            rules.extend([f'AND,((PROCESS-PATH,{path}),(NETWORK,UDP)),REJECT',
                          f'AND,((PROCESS-PATH,{path}),(IP-CIDR6,::/0)),REJECT',
                          f'PROCESS-PATH,{path},{target}'])
    if not proxies or (not assigned and not global_channel):
        raise ValueError('先启动至少一条已分配应用的信道。')
    if global_channel:
        target='CG-'+global_channel
        if not any(p['name']==target for p in proxies):
            raise ValueError('全局信道尚未启动。')
        rules=['NETWORK,UDP,REJECT','IP-CIDR6,::/0,REJECT,no-resolve','MATCH,'+target]
    bypass=[]
    for path in bypass_paths or []:
        if any(character in path for character in (',','\n','\r')):
            raise ValueError('TUN 模式的程序解压路径不能包含逗号或换行。')
        bypass.append(f'PROCESS-PATH,{path},DIRECT')
    dns_channel=next(c for c in channels if c['id']==global_channel) if global_channel else next(c for c in channels if c['id'] in runtimes)
    bootstrap=dns_channel.get('bootstrap_doh','https://1.1.1.1/dns-query')
    return {
        'mode':'rule','log-level':'warning','allow-lan':False,'ipv6':True,
        'external-controller':f'127.0.0.1:{api_port}','secret':secret,'find-process-mode':'always',
        'geodata-mode':False,'geo-auto-update':False,
        'tun':{'enable':True,'device':'ChannelGuardTUN','stack':'mixed','auto-route':True,
               'auto-detect-interface':True,'strict-route':True,
               'dns-hijack':['any:53','tcp://any:53'],'mtu':1500},
        'dns':{'enable':True,'listen':'127.0.0.1:0','enhanced-mode':'fake-ip','ipv6':False,
               'fake-ip-range':'198.18.0.1/16','default-nameserver':[bootstrap],
               'nameserver':[dns_channel['doh']+'#'+('CG-'+global_channel if global_channel else proxies[0]['name'])],
               'proxy-server-nameserver':[bootstrap]},
        'proxies':proxies,'rules':bypass+(rules if global_channel else rules+['MATCH,DIRECT']),
    }
