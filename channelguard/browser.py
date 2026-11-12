from __future__ import annotations
import html
import json
import os
from pathlib import Path
import sys
import time
from .engine import resource_root
from .storage import atomic_write,dpapi

HOME = 'https://channelguard.local/'

def is_chromium_browser(path):
    return Path(path).name.casefold() in {'quark.exe','chrome.exe','msedge.exe','brave.exe','vivaldi.exe','chromium.exe'}

def browser_executable(playwright=None):
    packaged = resource_root()/'browser'/'chrome.exe'
    if packaged.exists():
        return str(packaged)
    if playwright is not None:
        existing = Path(playwright.chromium.executable_path)
    else:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            existing = Path(p.chromium.executable_path)
    if existing.exists():
        return str(existing)
    raise RuntimeError('缺少配套 Chromium。请下载完整压缩包并完整解压。')

def home_html(channel):
    document = r'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>信道检测 · ChannelGuard</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e4ecfa;font:16px 'Microsoft YaHei',sans-serif}main{max-width:1000px;margin:70px auto;padding:0 30px}.eyebrow{color:#66d7c0;font-size:12px;letter-spacing:3px}h1{font-size:36px;margin:12px 0}p{color:#9aaec9;line-height:1.85}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:28px 0}.card{background:#131e30;border:1px solid #26364c;border-radius:16px;padding:24px}.label{font-size:12px;color:#95aaca}.value{font-size:21px;margin-top:10px;overflow-wrap:anywhere}button,a{display:inline-block;background:#58d5bb;color:#09241e;border:0;border-radius:8px;padding:12px 18px;margin:6px 8px 6px 0;cursor:pointer;text-decoration:none;font:14px 'Microsoft YaHei'}a{background:#23354d;color:#d9e7f9}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px Consolas,monospace;color:#b9cae1;line-height:1.8}.muted{font-size:13px}#netstatus{color:#f4c775}footer{margin:30px 0;color:#7085a1;font-size:12px}</style>
<main><div class="eyebrow">CHANNELGUARD / MANAGED ENVIRONMENT</div><h1>__NAME__</h1><p>这是由信道工具管理的独立浏览器。Cookie 与登录状态按信道保存。<br>下面显示此页面实际读取的环境；出口和 WebRTC 需要点击检测后才有结果。</p>
<div class="grid"><div class="card"><div class="label">页面实际时区</div><div class="value" id="tz"></div></div><div class="card"><div class="label">页面实际语言</div><div class="value" id="lang"></div></div><div class="card"><div class="label">出口 IP（尚未检测）</div><div class="value" id="ip">等待检测</div></div><div class="card"><div class="label">定位策略</div><div class="value">__GEO__</div></div></div>
<button id="test" onclick="testNetwork()">检测出口与 WebRTC</button><button onclick="testGeo()">验证定位权限</button><a href="https://browserleaks.com/dns" target="_blank" rel="noopener">完整 DNS 检测</a><a href="https://browserleaks.com/webrtc" target="_blank" rel="noopener">外部 WebRTC 检测</a>
<p class="muted">点击网络检测会通过本信道访问 Cloudflare、IPIP 和 IP 归属地服务，并向 Google STUN 发起 WebRTC 测试。外部检测由对应网站提供；本工具不把未知结果标记为通过。</p><div class="card"><div id="netstatus">尚未进行网络检测</div><pre id="details"></pre></div><footer>第一版提供环境管理和连接检测，不承诺无法被网站识别。DNS、IPv6 的完整泄露验证需要额外检测。</footer></main>
<script>
const report={observed_at:new Date().toISOString(),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,languages:navigator.languages,location_policy:'__GEOKEY__',webrtc:{status:'untested'},network:{status:'untested'}};
tz.textContent=report.timezone;lang.textContent=report.languages.join(', ');
function show(){details.textContent=JSON.stringify(report,null,2);if(window.__cgReport)window.__cgReport(report).catch(()=>{});}show();
async function testNetwork(){document.getElementById('test').disabled=true;netstatus.textContent='检测中…';report.observed_at=new Date().toISOString();
try{const data=await window.__cgNetworkProbe();if(!data?.reachable||!data.ips?.length)throw Error('出口未验证');ip.textContent=data.ips.join(', ');report.network={status:'observed',ip:data.ips[0],ips:data.ips,checks:data.checks};}catch(e){report.network={status:'failed',error:String(e)};ip.textContent='连接失败';}
try{const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});const candidates=[];pc.onicecandidate=e=>{if(e.candidate)candidates.push(e.candidate.toJSON());};pc.createDataChannel('check');await pc.setLocalDescription(await pc.createOffer());await new Promise(resolve=>{const timer=setTimeout(resolve,6000);pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete'){clearTimeout(timer);resolve();}}});pc.close();report.webrtc={status:'observed',candidates,note:candidates.length?'请检查候选地址是否为非预期出口；候选为空也不代表完整防泄露证明。':'本次未观察到 ICE 候选地址；仍需结合外部测试。'};}catch(e){report.webrtc={status:'failed',error:String(e)};}
netstatus.textContent=report.network.status==='observed'?'出口已观察；DNS / IPv6 仍需独立验证':'出口检测未成功，不能确认联网状态';show();document.getElementById('test').disabled=false;}
function testGeo(){navigator.geolocation.getCurrentPosition(p=>{report.geolocation={status:'allowed',latitude:p.coords.latitude,longitude:p.coords.longitude,accuracy:p.coords.accuracy};show();},e=>{report.geolocation={status:'denied_or_unavailable',code:e.code,message:e.message};show();},{timeout:5000});}
</script></html>'''
    return document.replace('__NAME__',html.escape(channel['name'])).replace('__GEO__','拒绝网页定位' if channel['geo']=='deny' else '指定位置（由信道配置）').replace('__GEOKEY__',channel['geo'])

def launch_context(playwright,manifest,headless=False):
    channel = manifest['channel']
    profile = Path(manifest['data_root'])/'profiles'/channel['id']
    if manifest.get('native_browser'):
        import hashlib
        profile=profile/('native-'+hashlib.sha256(manifest['native_browser'].casefold().encode()).hexdigest()[:16])
    profile.mkdir(parents=True,exist_ok=True)
    args = ['--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--webrtc-ip-handling-policy=disable_non_proxied_udp','--proxy-bypass-list=<-loopback>',
            '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
            '--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn', '--no-first-run']
    kwargs = dict(user_data_dir=str(profile),executable_path=manifest.get('native_browser') or browser_executable(playwright),headless=headless,
                  proxy={'server':f"http://127.0.0.1:{manifest['port']}",
                         'username':manifest['username'],'password':manifest['password'],'bypass':''},
                  timezone_id=channel['timezone'],locale=channel['locale'],
                  accept_downloads=True,ignore_https_errors=False,args=args,
                  permissions=['geolocation'] if channel['geo']=='fixed' else [])
    if channel['geo']=='fixed':
        kwargs['geolocation'] = {'latitude':float(channel['latitude']),'longitude':float(channel['longitude']),'accuracy':100}
    context = playwright.chromium.launch_persistent_context(**kwargs)
    if channel['geo']=='deny':
        # Empty permissions means prompt in Chromium. Deny using supported browser permission API,
        # applied per browser context, including new origins; do not change Windows location settings.
        cdp = context.new_cdp_session(context.pages[0] if context.pages else context.new_page())
        cdp.send('Browser.setPermission',{'permission':{'name':'geolocation'},'setting':'denied'})
    def home(route):
        if route.request.url.rstrip('/') == HOME.rstrip('/'):
            route.fulfill(status=200,content_type='text/html; charset=utf-8',body=home_html(channel))
        else:
            route.fulfill(status=404,body='Not found')
    context.route(HOME+'**',home)
    report_path = Path(manifest['data_root'])/'reports'/(channel['id']+'-browser.json')
    def save_report(source,data):
        if source['frame'].url != HOME or not isinstance(data,dict):
            return
        if len(json.dumps(data)) > 100_000:
            return
        result = dict(data,channel_id=channel['id'],source='managed-browser-page',saved_at=time.time())
        atomic_write(report_path,json.dumps(result,ensure_ascii=False,indent=2).encode('utf-8'))
    def network_probe(source):
        if source['frame'].url != HOME:return {'reachable':False,'ips':[]}
        from urllib.parse import quote
        from .monitor import observe
        proxy=f"http://{quote(manifest['username'],safe='')}:{quote(manifest['password'],safe='')}@127.0.0.1:{manifest['port']}"
        return observe(proxy)
    context.expose_binding('__cgNetworkProbe',network_probe)
    context.expose_binding('__cgReport',save_report)
    return context

def browser_worker(manifest_path,url=''):
    from playwright.sync_api import sync_playwright
    path = Path(manifest_path)
    manifest = json.loads(dpapi(path.read_bytes(),True))
    try:
        with sync_playwright() as playwright:
            context = launch_context(playwright,manifest)
            pages = context.pages
            page = pages[0] if pages else context.new_page()
            page.goto(HOME,wait_until='domcontentloaded')
            if url.startswith(('https://','http://')):
                context.new_page().goto(url,wait_until='domcontentloaded',timeout=20000)
            while context.pages and path.exists():
                try:
                    context.pages[0].wait_for_timeout(500)
                except Exception:
                    break
            context.close()
    except Exception as exc:
        # Keep errors useful without exposing node credentials or raw proxy URL.
        error = {'status':'browser_failed','error_type':type(exc).__name__,
                 'hint':'浏览器启动或连接失败。检查浏览器文件、配置目录占用及信道引擎。','saved_at':time.time()}
        atomic_write(Path(manifest['data_root'])/'reports'/(manifest['channel']['id']+'-error.json'),json.dumps(error).encode())
        raise
