from __future__ import annotations
import datetime
import ipaddress
import json
from pathlib import Path
import time
import requests
from .engine import session
from .storage import atomic_write

def diagnose(engines,channel):
    runtime = engines.active.get(channel['id'])
    if not runtime or runtime['process'].poll() is not None:
        raise RuntimeError('先启动这条信道。')
    report = {'channel_id':channel['id'],'channel_name':channel['name'],
              'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'configuration':{'interface':channel['interface'] or '跟随系统路由','timezone':channel['timezone'],
                               'locale':channel['locale'],'geo':channel['geo'],'doh':channel['doh'],
                               'node_type':channel['node']['type'] if channel.get('node') else 'direct'},
              'checks':[],'ip':None,'country':None,'asn':None}
    proxy = engines.proxy(channel['id'])
    with session() as http:
        http.proxies.update(http=proxy,https=proxy)
        started = time.monotonic()
        try:
            response = http.get('https://api.ipify.org?format=json',timeout=(7,12))
            response.raise_for_status()
            actual = str(ipaddress.ip_address(response.json()['ip']))
            report['ip'] = actual
            report['latency_ms'] = round((time.monotonic()-started)*1000)
            report['checks'].append(dict(name='HTTPS 出口',status='observed',detail=f'{actual} · {report["latency_ms"]} ms（整次请求耗时）'))
        except (requests.RequestException,ValueError,KeyError):
            report['checks'].append(dict(name='HTTPS 出口',status='failed',detail='通过本信道连接失败或超时；未改用系统直连。'))
        if report['ip']:
            try:
                # Query observed IP explicitly: a second request may use another NAT egress.
                response = http.get('https://ipwho.is/'+report['ip'],timeout=(5,8))
                response.raise_for_status()
                data = response.json()
                if not data.get('success'):
                    raise ValueError('lookup failed')
                report['country'] = data.get('country_code')
                report['asn'] = data.get('connection',{}).get('asn')
                report['isp'] = data.get('connection',{}).get('isp')
                report['ip_timezone'] = data.get('timezone',{}).get('id')
                expected = channel.get('expected_country','').upper().strip()
                mismatch = bool(expected and report['country'] != expected)
                report['checks'].append(dict(name='IP 归属地',status='warning' if mismatch else 'observed',
                    detail=f"{report['country']} · ASN {report['asn']} · {report.get('isp','')}"+('；与预期国家不一致' if mismatch else '；数据库结果仅供参考')))
                if report.get('ip_timezone') != channel['timezone']:
                    report['checks'].append(dict(name='时区一致性',status='warning',detail=f"信道：{channel['timezone']}；IP 库：{report.get('ip_timezone') or '未知'}。同一国家可有多个时区，请人工确认。"))
            except (requests.RequestException,ValueError,KeyError):
                report['checks'].append(dict(name='IP 归属地 / ASN',status='unknown',detail='查询服务不可用，未推断国家或 IP 类型。'))
    report['checks'] += [
        dict(name='DNS 路径',status='configured',detail='信道独立 DNS，目标 DoH 通过本信道出口；代理服务器域名通过所配置的直接加密引导 DoH 解析。尚未完成外部 DNS 泄露验证。'),
        dict(name='IPv6 / UDP',status='configured',detail='本信道引擎拒绝 IPv6 目标和 UDP；浏览器关闭 QUIC。未接入本工具的流量不在此范围。'),
        dict(name='浏览器时区 / 定位 / WebRTC',status='unknown',detail='打开专用浏览器首页进行实测；配置本身不代表检测通过。'),
        dict(name='VPS / 代理识别',status='unknown',detail='ASN 可查询；机房 / VPN 分类尚未接入数据库，不承诺不可识别。'),
        dict(name='断线保护范围',status='configured',detail='专用浏览器固定本地代理且无直连后备。普通应用需遵守代理设置或安装直连阻断；TUN 自身不等于崩溃后阻断。'),
    ]
    atomic_write(engines.store.root/'reports'/(channel['id']+'-network.json'),json.dumps(report,ensure_ascii=False,indent=2).encode('utf-8'))
    return report
