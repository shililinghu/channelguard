"""Evidence-based EXE attribution and sampled payload rates.

No global adapter totals, process disk-I/O counters, or configured rules are
treated as proof of a process's network usage. Different counter sources are
kept separate because they often describe the same bytes.
"""
from __future__ import annotations
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import statistics
import time
import secrets
import psutil
from .engine import session
from .tcp_stats import TcpStats
from .system import powershell,ps_quote


def canonical(path):
    return os.path.normcase(os.path.abspath(path)) if path else ''


def ip(value):
    try:return str(ipaddress.ip_address(str(value).split('%')[0]))
    except ValueError:return str(value)


def loopback(value):
    try:return ipaddress.ip_address(ip(value)).is_loopback
    except ValueError:return False


def endpoint(value):
    return f'[{value[0]}]:{value[1]}' if value and ':' in value[0] else f'{value[0]}:{value[1]}' if value else '无远端（监听或 UDP 绑定）'


def percentile(values, fraction):
    if not values:return None
    values=sorted(values);index=(len(values)-1)*fraction;lo=int(index);hi=min(lo+1,len(values)-1)
    return values[lo]+(values[hi]-values[lo])*(index-lo)


def select_processes(records, path, children):
    selected={pid:row for pid,row in records.items() if canonical(row.get('exe'))==canonical(path)}
    if children:
        while True:
            added={pid:row for pid,row in records.items() if pid not in selected and row.get('ppid') in selected
                   and row['created']>=selected[row['ppid']]['created']}
            if not added:break
            selected.update(added)
    return selected


def expected_channels(path, channels):
    exact=[];folders=[]
    for channel in channels:
        for app in channel.get('apps',[]):
            if canonical(app['path'])==canonical(path):exact.append(channel['name'])
            for root in app.get('routing_roots',[]):
                if canonical(path).startswith(canonical(root).rstrip('\\/')+os.sep):folders.append(channel['name'])
    return list(dict.fromkeys(exact or folders))


def read_core(identity, runtime):
    try:
        with session() as http:
            response=http.get(f"http://127.0.0.1:{runtime['api_port']}/connections",
                              headers={'Authorization':'Bearer '+runtime['secret']},timeout=(.5,1))
            response.raise_for_status();data=response.json()
        rows=data.get('connections') or []
        return identity,rows[:2000],time.monotonic(),('连接超过 2000 条，列表已截断' if len(rows)>2000 else '')
    except Exception as exc:
        # Request exception text can include authentication. Retain only type.
        return identity,[],time.monotonic(),'连接 API 不可用（'+type(exc).__name__+'）'


def core_owner(metadata, processes, sockets, channel_id, proxy_ports, is_tun=False):
    """Return evidence scope, never join solely on destination or process basename."""
    path=canonical(metadata.get('processPath'))
    matches=[row for row in processes.values() if path and canonical(row['exe'])==path]
    if matches:return '完整程序路径',None
    if is_tun:return None,None
    try:source_port=int(metadata.get('sourcePort',0))
    except (ValueError,TypeError):return None,None
    for connection in sockets:
        if (connection['protocol'].casefold()==str(metadata.get('network','')).casefold()
            and ip(connection['local'][0])==ip(metadata.get('sourceIP',''))
            and connection['local'][1]==source_port and connection['remote']
            and loopback(connection['remote'][0]) and connection['remote'][1]==proxy_ports.get(channel_id)):
            return '本地源地址和端口 ↔ 已知信道入口',connection['pid']
    return None,None


class RateHistory:
    def __init__(self):
        self.previous={};self.history={};self.totals={};self.started=time.monotonic()

    def update(self, counters, now):
        result={}
        for source in ('系统分流', '信道内核', 'Windows TCP'):
            current=counters.get(source,{})
            previous=self.previous.get(source,{})
            up=down=0.;matched=reset=0;up_bytes=down_bytes=0
            for key,row in current.items():
                before=previous.get(key)
                if not before or row['at']<=before['at']:continue
                du,dd=row['up']-before['up'],row['down']-before['down']
                if du<0 or dd<0:reset+=1;continue
                elapsed=row['at']-before['at']
                up+=du/elapsed;down+=dd/elapsed;up_bytes+=du;down_bytes+=dd;matched+=1
            self.previous[source]=current
            history=self.history.setdefault(source,deque(maxlen=1800))
            totals=self.totals.setdefault(source,dict(up=0,down=0))
            if matched:
                history.append(dict(at=now,up=up,down=down,up_bytes=up_bytes,down_bytes=down_bytes))
                totals['up']+=up_bytes;totals['down']+=down_bytes
            recent=[x for x in history if now-x['at']<=60]
            result[source]=dict(up=up if matched else None,down=down if matched else None,
                comparable_flows=matched,visible_flows=len(current),new_flows=len(set(current)-set(previous)),
                disappeared_flows=len(set(previous)-set(current)),resets=reset,samples=len(recent),
                down_p50=percentile([x['down'] for x in recent],.5),down_p95=percentile([x['down'] for x in recent],.95),
                up_peak=max((x['up'] for x in recent),default=None),down_peak=max((x['down'] for x in recent),default=None),
                observed_upload=totals['up'],observed_download=totals['down'],
                quiet_samples=sum(x['up']==0 and x['down']==0 for x in recent))
        return result


class AppInspector:
    def __init__(self, path, engines, routing, channels, children=True, enable_tcp=False):
        self.path=str(Path(path).resolve());self.engines=engines;self.routing=routing
        self.channels=channels;self.children=children;self.enable_tcp=enable_tcp
        self.tcp=TcpStats();self.history=RateHistory()
        self.tcp_previous={}
        self.last_snapshot=None

    def capture(self):
        records={};denied=0;warnings=[]
        for process in psutil.process_iter(['pid','ppid','exe','name','create_time'],ad_value=None):
            row=process.info
            if not row.get('exe') or row.get('create_time') is None:
                denied+=1;continue
            records[process.pid]=dict(pid=process.pid,ppid=row.get('ppid'),exe=row['exe'],name=row.get('name'),created=row['create_time'])
        processes=select_processes(records,self.path,self.children)
        sockets=[]
        try:
            for connection in psutil.net_connections(kind='inet'):
                if connection.pid not in processes or not connection.laddr:continue
                sockets.append(dict(pid=connection.pid,protocol='TCP' if connection.type==socket.SOCK_STREAM else 'UDP',
                    local=[connection.laddr.ip,connection.laddr.port],remote=[connection.raddr.ip,connection.raddr.port] if connection.raddr else [],
                    state=connection.status))
        except (psutil.Error,OSError) as exc:warnings.append('系统连接表读取失败：'+type(exc).__name__)
        valid={}
        for pid,row in processes.items():
            try:
                current=psutil.Process(pid)
                if abs(current.create_time()-row['created'])<.01 and canonical(current.exe())==canonical(row['exe']):valid[pid]=row
            except (psutil.Error,OSError):pass
        processes=valid;sockets=[s for s in sockets if s['pid'] in valid]
        channels=list(self.channels());names={c['id']:c['name'] for c in channels}
        active={identity:r for identity,r in list(self.engines.active.items()) if r['process'].poll() is None}
        ports={identity:r['port'] for identity,r in active.items()}
        native=self.routing.status()
        native_fresh=(native.get('state')=='running' and 0<=time.time()-native.get('at',0)<=5)
        if not native_fresh:warnings.append('系统分流没有新鲜的运行证据；不会把 EXE 分配设置当成实际接管。')
        flows=[];counters={source:{} for source in ('系统分流','信道内核','Windows TCP')};observed=set();native_matches=[]
        raw_native=native.get('flows',[]) if native_fresh else []
        if len(raw_native)>=400:warnings.append('系统分流活动流达到 400 条上限，可能漏掉连接（包括 UDP）。')
        for flow in raw_native:
            pid=flow.get('pid')
            if pid not in processes:continue
            age=flow.get('age_ms',0xFFFFFFFF)
            if age!=0xFFFFFFFF and time.time()-age/1000 < processes[pid]['created']-.2:
                warnings.append('丢弃早于当前 PID 创建时间的旧分流记录。');continue
            identity=flow.get('channel_id');destination=flow.get('destination_ip') or flow.get('destination','')
            native_matches.append((pid,flow.get('protocol'),destination,flow.get('port')))
            if identity:observed.add(identity)
            confidence='已观察转发' if age!=0xFFFFFFFF else '已观察 PID 转发（创建时间未知）'
            flows.append(dict(source='系统分流',pid=pid,channel_id=identity,channel=names.get(identity,'未知映射'),
                destination=endpoint([flow.get('destination',''),flow.get('port',0)]),protocol=flow.get('protocol'),
                evidence=confidence,detail='规则：'+flow.get('matched_pattern','')+'；不能据此证明所有连接或公网出口'))
            key=f"{native.get('token')}:{flow.get('id')}:{pid}:{processes[pid]['created']}"
            counters['系统分流'][key]=dict(up=flow.get('sent',0),down=flow.get('received',0),at=native.get('sample_monotonic',native['at']))
        interfaces={}
        try:
            for name,addresses in psutil.net_if_addrs().items():
                for address in addresses:
                    if address.family in (socket.AF_INET,socket.AF_INET6):interfaces.setdefault(ip(address.address),[]).append(name)
        except (psutil.Error,OSError):warnings.append('无法将本地源 IP 对应到网卡。')
        tcp_rows=[];tcp_current={}
        for connection in sockets:
            remote=connection['remote'];identity=None
            matches=[f for f in native_matches if remote and f==(connection['pid'],connection['protocol'],ip(remote[0]),remote[1])]
            if remote and loopback(remote[0]):
                identity=next((i for i,p in ports.items() if p==remote[1]),None)
            if identity:
                detail='已连接已知信道入口；需内核/分流证据确认转发，未证明公网出口'
                evidence='已观察入口';channel=names.get(identity,identity)
            elif matches:
                detail='系统连接四元组与分流目的地址一致；端到端出口仍未验证'
                evidence='分流交叉关联';channel='见系统分流记录'
            else:
                detail='本地源网卡：'+(' / '.join(interfaces.get(ip(connection['local'][0]),[])) or '未知')
                evidence='仅系统连接';channel='无法确认（可能经 VPN / 其他代理）' if remote and not loopback(remote[0]) else '无信道证据'
            flows.append(dict(source='Windows 连接表',pid=connection['pid'],channel_id=identity,channel=channel,
                protocol=connection['protocol'],destination=endpoint(remote),evidence=evidence,
                detail=endpoint(connection['local'])+' → '+endpoint(remote)+' · '+connection['state']+'；'+detail))
            if connection['protocol']=='TCP' and remote and connection['state']=='ESTABLISHED':
                stats=self.tcp.read(connection,self.enable_tcp)
                key=json.dumps([connection['pid'],processes[connection['pid']]['created'],connection['local'],remote])
                stamp=time.monotonic();previous=self.tcp_previous.get(key);path=stats.get('path')
                window={}
                if path:
                    tcp_current[key]=(stamp,path)
                    if previous and stamp>previous[0]:
                        delta={name:path[name]-previous[1][name] for name in ('PktsRetrans','Timeouts','SumRtt','CountRtt')}
                        if all(value>=0 for value in delta.values()):
                            window=dict(seconds=stamp-previous[0],retransmitted_segments=delta['PktsRetrans'],
                                retransmission_timeouts=delta['Timeouts'],rtt_samples=delta['CountRtt'],
                                mean_rtt_ms=delta['SumRtt']/delta['CountRtt'] if delta['CountRtt'] else None)
                scope='本机代理 / 中继段，不能视作远端 RTT' if loopback(remote[0]) or matches else '该 TCP 端点；VPN / 服务端转发后的链路未知'
                tcp_rows.append(dict(pid=connection['pid'],destination=endpoint(remote),scope=scope,window=window,**stats))
                data=stats.get('data')
                if data:
                    counters['Windows TCP'][key]=dict(up=data['ThruBytesAcked'],down=data['ThruBytesReceived'],at=stamp)
        self.tcp_previous=tcp_current
        queries=list(active.items()) if processes else []
        if processes and self.engines.router and self.engines.router['process'].poll() is None:queries.append(('__tun__',self.engines.router))
        if queries:
            with ThreadPoolExecutor(max_workers=4) as pool:core_results=list(pool.map(lambda pair:read_core(*pair),queries))
        else:core_results=[]
        cross=0;core_unattributed=0
        for identity,connections,stamp,error in core_results:
            if error:warnings.append(names.get(identity,'TUN')+'：'+error)
            for connection in connections:
                metadata=connection.get('metadata') or {}
                owner,pid=core_owner(metadata,processes,sockets,identity,ports,identity=='__tun__')
                if not owner:
                    if any(ip(f[2])==ip(metadata.get('destinationIP','')) and f[3]==int(metadata.get('destinationPort') or 0)
                           for f in native_matches):cross+=1
                    core_unattributed+=1;continue
                ids=[i for i in names if 'CG-'+i in (connection.get('chains') or [])] if identity=='__tun__' else [identity]
                if len(ids)==1:observed.add(ids[0])
                actual=ids[0] if len(ids)==1 else None
                if identity=='__tun__' and not actual:label='TUN 内核：'+(' → '.join(connection.get('chains') or []) or '未知出口')
                else:label=names.get(actual,'未知信道')
                flows.append(dict(source='信道内核',pid=pid,channel_id=actual,channel=label,protocol=metadata.get('network'),
                    destination=endpoint([metadata.get('host') or metadata.get('destinationIP',''),metadata.get('destinationPort',0)]),
                    evidence='已观察内核转发',detail=owner+'；链：'+(' → '.join(connection.get('chains') or []) or '无')+'；未证明该 EXE 的公网出口'))
                if connection.get('id'):
                    counters['信道内核'][identity+':'+connection['id']]=dict(up=connection.get('upload',0),down=connection.get('download',0),at=stamp)
        now=time.monotonic()
        report=dict(time=datetime.datetime.now().astimezone().isoformat(timespec='seconds'),path=self.path,
            include_children=self.children,processes=list(processes.values()),unreadable_processes=denied,
            configured_channels=expected_channels(self.path,channels),observed_channels=[dict(id=i,name=names.get(i,i)) for i in sorted(observed)],
            native_state=native.get('state','unknown'),flows=flows,tcp=tcp_rows,rates=self.history.update(counters,now),
            core_destination_correlations=cross,unattributed_core_connections=core_unattributed,warnings=list(dict.fromkeys(warnings)),
            elapsed=round(now-self.history.started,1),
            limitations=[
                '结论只覆盖采样中可见的连接，不承诺整个 EXE 只使用一条信道；配置分配不是实际路径证据。',
                '速率为相邻快照同一流的有效载荷增量；新出现、已结束和两次采样之间的短连接会漏计，是已观察流的下限。',
                '三个来源可能记录同一批字节，分别展示，不能相加；系统分流流量以本地转发为界，不能证明远端已收到。',
                '未归属的内核连接可能属于其他应用，不能计入所选 EXE；仅目的地址相同的连接只作辅助关联。',
                'UDP 绑定表通常没有远端；系统 DNS 服务、WSL / 虚拟机、受保护进程及其他驱动流量可能无法归属。',
                '空闲或零吞吐不等于断网；连接消失不等于异常断线；TCP 重传不等于精确丢包率。',
                '公网出口、网络最大带宽和业务响应成功率不能从任意 EXE 的被动连接表直接获知。',
            ])
        self.last_snapshot=report
        return report


def route_evidence(snapshot):
    """Read OS candidate routes for observed remote IPs; never call them actual egress."""
    addresses=[]
    for flow in snapshot.get('flows',[]):
        if flow['source']!='Windows 连接表':continue
        # Parse only the endpoint emitted by endpoint(), never accept shell text.
        text=flow['destination']
        candidate=text[1:text.index(']')] if text.startswith('[') else text.rpartition(':')[0]
        try:address=ipaddress.ip_address(candidate.split('%')[0])
        except ValueError:continue
        if not address.is_loopback and not address.is_unspecified:addresses.append(str(address))
    addresses=list(dict.fromkeys(addresses))[:12]
    if not addresses:return {'routes':[],'note':'没有可供核查的非回环远端 IP；UDP 绑定可能不提供远端。'}
    script='$items=@();foreach($remote in @('+','.join(ps_quote(x) for x in addresses)+')) {'
    script+="try {$found=@(Find-NetRoute -RemoteIPAddress $remote -ErrorAction Stop);$items+=@{remote=$remote;rows=@($found | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,DestinationPrefix,NextHop,RouteMetric)}} catch {$items+=@{remote=$remote;error='无法查询候选路由'}}};@{routes=$items}|ConvertTo-Json -Depth 6 -Compress"
    try:result=json.loads(powershell(script,timeout=20))
    except Exception as exc:return {'routes':[],'note':'候选路由查询不可用（'+type(exc).__name__+'）'}
    result['note']='仅是查询时 Windows 为诊断进程计算的候选路由；逐应用 VPN、代理、绑定网卡或驱动重定向可能不同，不能证明该 EXE 的实际出口。最多核查 12 个 IP。'
    return result


def bounded_body(response, limit, cancel, deadline):
    data=bytearray()
    for chunk in response.iter_content(16384):
        if cancel.is_set():raise InterruptedError('检测已停止')
        if time.monotonic()>deadline:raise TimeoutError('采样时间上限')
        if len(data)+len(chunk)>limit:raise ValueError('响应超过本次检测上限')
        data.extend(chunk)
    return bytes(data)


def reference_probe(engines, channel_id, transfer, cancel):
    """Independent requests, never attributed to the selected EXE."""
    runtime=engines.active.get(channel_id)
    if not runtime or runtime['process'].poll() is not None:raise RuntimeError('参考信道未运行。')
    proxy=engines.proxy(channel_id)
    report=dict(channel_id=channel_id,time=datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
        scope='诊断进程通过指定信道发出的独立 HTTPS 请求；不是所选 EXE 的业务测速或公网出口证明。',samples=[],transfer={})
    sites=(('Cloudflare','https://www.cloudflare.com/cdn-cgi/trace'),('ipify','https://api.ipify.org?format=json'))
    for _ in range(3):
        for name,url in sites:
            if cancel.is_set():break
            started=time.monotonic();sample=dict(site=name,success=False)
            try:
                with session() as http:
                    http.proxies.update(http=proxy,https=proxy)
                    with http.get(url,timeout=(3,4),stream=True,allow_redirects=False,headers={'Cache-Control':'no-cache'}) as response:
                        response.raise_for_status()
                        if response.status_code!=200:raise ValueError('非预期 HTTP 状态')
                        data=bounded_body(response,8192,cancel,started+8).decode('utf-8')
                value=json.loads(data)['ip'] if name=='ipify' else next(line[3:] for line in data.splitlines() if line.startswith('ip='))
                sample.update(success=True,ip=str(ipaddress.ip_address(value)))
            except InterruptedError:break
            except Exception as exc:sample['error']=type(exc).__name__
            sample['request_ms']=round((time.monotonic()-started)*1000,1);report['samples'].append(sample)
    durations=[x['request_ms'] for x in report['samples'] if x['success']]
    report['summary']=dict(attempts=len(report['samples']),successes=len(durations),
        failure_ratio=(sum(not x['success'] for x in report['samples'])/len(report['samples']) if report['samples'] else None),
        p50_ms=percentile(durations,.5),p95_ms=percentile(durations,.95),
        exits=sorted({x['ip'] for x in report['samples'] if x.get('ip')}))
    report['per_site']={}
    for name,_ in sites:
        values=[x['request_ms'] for x in report['samples'] if x['site']==name and x['success']]
        report['per_site'][name]=dict(request_ms=values,
            mean_adjacent_difference_ms=statistics.mean(abs(b-a) for a,b in zip(values,values[1:])) if len(values)>1 else None)
    if transfer and not cancel.is_set():
        for direction,size in (('download',4*1024*1024),('upload',256*1024)):
            if cancel.is_set():break
            started=time.monotonic()
            try:
                with session() as http:
                    http.proxies.update(http=proxy,https=proxy)
                    headers={'Accept-Encoding':'identity','Cache-Control':'no-cache'}
                    if direction=='download':
                        response=http.get(f'https://speed.cloudflare.com/__down?bytes={size}&cg={secrets.token_hex(6)}',timeout=(3,5),stream=True,allow_redirects=False,headers=headers)
                    else:
                        headers['Content-Type']='application/octet-stream'
                        response=http.post('https://speed.cloudflare.com/__up',data=b'\0'*size,timeout=(3,5),stream=True,allow_redirects=False,headers=headers)
                    with response:
                        if response.status_code!=200:raise ValueError('非预期 HTTP 状态')
                        body=bounded_body(response,size if direction=='download' else 8192,cancel,started+12)
                        if direction=='download' and len(body)!=size:raise ValueError('收到的字节数与请求不符')
                    elapsed=time.monotonic()-started
                report['transfer'][direction]=dict(success=True,bytes=size,seconds=round(elapsed,3),bytes_per_second=size/elapsed)
            except InterruptedError:break
            except Exception as exc:report['transfer'][direction]=dict(success=False,error=type(exc).__name__)
    report['cancelled']=cancel.is_set()
    report['limitations']=[
        '公网 IP 来自两家 HTTPS 服务对诊断请求的观察；多 IP 可能是 NAT 出口池，不能据此认定 EXE 泄漏或路径改变。',
        '请求耗时含 DNS / 连接 / TLS / 服务端处理，不是 ICMP ping 或游戏延迟；失败率不是丢包率。',
        '每站最多 3 次请求，小样本不能判定长期稳定性。延迟波动按同站相邻成功请求差值计算。',
        '吞吐为单次小文件的有效载荷 / 完整请求耗时（包含建连及确认）；不是线路峰值、承诺带宽或所选 EXE 的速度。',
        '显式使用信道代理并忽略系统代理环境变量；失败不切换直连。HTTPS 保持证书验证。',
    ]
    return report
