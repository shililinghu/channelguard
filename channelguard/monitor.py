"""Network identity observation and explicit physical/VPN role reconciliation."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from zoneinfo import ZoneInfo
from .engine import session
from .presets import candidates

LOCALES={'CN':'zh-CN','US':'en-US','GB':'en-GB','JP':'ja-JP','SG':'en-SG',
         'DE':'de-DE','FR':'fr-FR','CA':'en-CA','AU':'en-AU','HK':'zh-HK','TW':'zh-TW','KR':'ko-KR'}


def fingerprint(info):
    data={key:info.get(key,[]) for key in ('adapters','configs','routes')}
    # Ignore link-speed fluctuations, timestamps, ordering and owned listener ports.
    data['adapters']=[{k:a.get(k) for k in ('Name','Guid','Status','Hardware','InterfaceDescription')}
                      for a in data['adapters']]
    for key in data:data[key]=sorted(data[key],key=lambda x:json.dumps(x,sort_keys=True))
    return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()


def binding(channel, info):
    role=channel.get('network_role')
    if role not in ('direct','vpn'):return channel.get('interface',''),None
    kind='wifi' if role=='direct' else 'vpn'
    available=[c for c in candidates(info) if c['discovery']['kind']==kind
               and c['discovery']['readiness']=='ready']
    if any(c['interface']==channel.get('interface') for c in available):return channel['interface'],None
    if len(available)==1:return available[0]['interface'],'网卡发生变化，已重新绑定同类出口'
    return None,'对应出口未连接或存在多个候选，请重新初始化'


def observe(proxy):
    def get(url):
        with session() as client:
            client.proxies={'http':proxy,'https':proxy}
            try:
                r=client.get(url,timeout=(4,6));r.raise_for_status()
                found=re.search(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',r.text)
                if not found or not ipaddress.ip_address(found[0]).is_global:raise ValueError('No public IP')
                trace=dict(line.split('=',1) for line in r.text.splitlines() if '=' in line)
                return {'url':url,'ip':found[0],'country':trace.get('loc')}
            except Exception as exc:return {'url':url,'error':type(exc).__name__}
    urls=['https://www.cloudflare.com/cdn-cgi/trace','https://myip.ipip.net']
    with ThreadPoolExecutor(max_workers=2) as pool:checks=list(pool.map(get,urls))
    ips=list(dict.fromkeys(row['ip'] for row in checks if row.get('ip')))
    result={'reachable':bool(ips),'ips':ips,'checks':checks}
    if not ips:return result
    with session() as client:
        client.proxies={'http':proxy,'https':proxy}
        try:
            r=client.get('https://ipwho.is/'+ips[0],timeout=(4,6));r.raise_for_status();data=r.json()
            if not data.get('success') or data.get('ip')!=ips[0]:raise ValueError('Mismatched lookup')
            timezone=data.get('timezone',{}).get('id');ZoneInfo(timezone)
            result.update(country=data.get('country_code'),region=data.get('region'),city=data.get('city'),
                          timezone=timezone,asn=data.get('connection',{}).get('asn'),isp=data.get('connection',{}).get('isp'))
        except Exception:result['country']=next((c['country'] for c in checks if c.get('country')),None)
    return result


def environment_patch(observation):
    """Use validated observed metadata only. Unknown regions retain user locale."""
    patch={}
    if observation.get('timezone'):
        ZoneInfo(observation['timezone']);patch['timezone']=observation['timezone']
    country=observation.get('country')
    if country:
        patch['expected_country']=country
        if country in LOCALES:patch['locale']=LOCALES[country]
    return patch
