"""Build reviewed, pinned MIT process relay against the official signed WinDivert SDK."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
source=ROOT/'build/thirdparty/ProxyBridge-cb897b017a88'
sdk=ROOT/'build/thirdparty/windivert/WinDivert-2.2.2-A'
vendor=ROOT/'vendor' if (ROOT/'vendor').is_dir() else ROOT.parent/'_internal/vendor'
destination=vendor/'process_router'
native=destination/'source'
native.mkdir(parents=True,exist_ok=True)
if source.is_dir():shutil.copy2(ROOT/'native_children.c',native/'cg_children.c')
if (ROOT/'native_udp.c').is_file():shutil.copy2(ROOT/'native_udp.c',native/'cg_udp.c')
for path in (source/'Windows/src').glob('*'):
    if path.is_file() and path.suffix in ('.c','.h'):shutil.copy2(path,native/path.name)
proxy=native/'pb_proxy.c'
text=proxy.read_text(encoding='utf-8')
text=text.replace('if (g_proxy_config_count > 0)\n        return &g_proxy_configs[0];','if (config_id == 0 && g_proxy_config_count > 0)\n        return &g_proxy_configs[0];')
proxy.write_text(text,encoding='utf-8')
rules=native/'pb_rules.c';text=rules.read_text(encoding='utf-8')
if 'cg_ancestor_rule' not in text:
    text=text.replace('#include "pb_internal.h"','#include "pb_internal.h"\nRuleAction cg_ancestor_rule(DWORD, UINT32, const UINT8*, UINT16, BOOL, UINT32*);',1)
    text=text.replace('RuleAction action = match_rule_v6(process_name, dest_ip6, dest_port, is_udp, &proxy_config_id);',
        'RuleAction action = match_rule_v6(process_name, dest_ip6, dest_port, is_udp, &proxy_config_id);\n    if (action==RULE_ACTION_DIRECT) action=cg_ancestor_rule(pid,0,dest_ip6,dest_port,is_udp,&proxy_config_id);')
    text=text.replace('RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp, &proxy_config_id);',
        'RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp, &proxy_config_id);\n    if (action==RULE_ACTION_DIRECT) action=cg_ancestor_rule(pid,dest_ip,NULL,dest_port,is_udp,&proxy_config_id);')
text=text.replace("if (cfg == NULL || cfg->host[0] == '\\0' || cfg->port == 0)\n            return RULE_ACTION_DIRECT;", "if (cfg == NULL || cfg->host[0] == '\\0' || cfg->port == 0)\n            return RULE_ACTION_BLOCK;")
text=text.replace('if (is_udp && cfg->type == PROXY_TYPE_HTTP)\n            return RULE_ACTION_DIRECT;','if (is_udp && cfg->type == PROXY_TYPE_HTTP)\n            return RULE_ACTION_BLOCK;')
text=text.replace('if (action==RULE_ACTION_DIRECT) action=cg_ancestor_rule','if (action==RULE_ACTION_DIRECT && g_tl_rule_id==0) action=cg_ancestor_rule')
rules.write_text(text,encoding='utf-8')
core=native/'ProxyBridge.c';text=core.read_text(encoding='utf-8')
text=text.replace('g_fw_thread = CreateThread(NULL, 0, fw_ensure_thread, NULL, 0, NULL);','/* ChannelGuard owns temporary, port-limited relay firewall rules. */')
core.write_text(text,encoding='utf-8')
relay=native/'pb_relay.c';text=relay.read_text(encoding='utf-8')
text=text.replace('DWORD WINAPI udp_relay_server(LPVOID arg)','DWORD WINAPI legacy_udp_relay_server(LPVOID arg)')
relay.write_text(text,encoding='utf-8')
for name in ('WinDivert.dll','WinDivert64.sys','WinDivert.lib'):
    original=sdk/'x64'/name;target=destination/name
    if original.is_file() and (not target.exists() or original.read_bytes()!=target.read_bytes()):shutil.copy2(original,target)
if sdk.is_dir():shutil.copy2(sdk/'include/windivert.h',native/'windivert.h')
if source.is_dir():shutil.copy2(source/'LICENSE',destination/'ProxyBridge-LICENSE.txt')
for name in ('LICENSE','LGPL','GPL'):
    if (sdk/name).exists():shutil.copy2(sdk/name,destination/(name+'-WinDivert.txt'))
compiler=Path(os.environ.get('CG_MSVC_ROOT',r'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207'))
windows=Path(r'C:\Program Files (x86)\Windows Kits\10')
sdkver=os.environ.get('CG_WINDOWS_SDK_VERSION','10.0.22621.0')
env=os.environ.copy()
env['PATH']=str(compiler/'bin/HostX64/x64')+os.pathsep+env['PATH']
env['INCLUDE']=os.pathsep.join(map(str,[compiler/'include',windows/'Include'/sdkver/'ucrt',windows/'Include'/sdkver/'shared',windows/'Include'/sdkver/'um',native]))
env['LIB']=os.pathsep.join(map(str,[compiler/'lib/x64',windows/'Lib'/sdkver/'ucrt/x64',windows/'Lib'/sdkver/'um/x64',destination]))
files=[p.name for p in native.glob('*.c')]
objects=ROOT/'build/native-objects';objects.mkdir(parents=True,exist_ok=True)
command=[str(compiler/'bin/HostX64/x64/cl.exe'),'/nologo','/O2','/MT','/utf-8','/GS','/guard:cf',
         '/DFD_SETSIZE=1024','/D_CRT_SECURE_NO_WARNINGS','/D_WINSOCK_DEPRECATED_NO_WARNINGS','/DPROXYBRIDGE_EXPORTS','/DNDEBUG','/LD',
         '/Fo'+str(objects)+os.sep,*files,'/link','/DYNAMICBASE','/NXCOMPAT','/guard:cf','WinDivert.lib','ws2_32.lib','iphlpapi.lib','/IMPLIB:'+str(objects/'ChannelGuardRoute.lib'),'/OUT:'+str(destination/'ChannelGuardRoute.dll')]
subprocess.run(command,cwd=native,env=env,check=True)
metadata={'repository':'https://github.com/InterceptSuite/ProxyBridge','commit':'cb897b017a88a142ec803c3af138b0ad75c2ae12',
    'changes':['Missing proxy ID fails closed instead of selecting another channel','Missing proxy and unsupported UDP use BLOCK','Removed automatic broad inbound firewall rule','Ancestor matching with parent creation-time validation; explicit DIRECT bypass stops inheritance','Independent SOCKS UDP associations per client; validate owner, channel and destination on replies; bounded to 256 sessions'],
    'windivert_version':'2.2.2-A','windivert_archive_sha256':'63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15',
    'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.glob('*') if p.suffix in ('.dll','.sys')}}
(destination/'PROVENANCE.json').write_text(json.dumps(metadata,indent=2))
print('Native routing backend built',destination)
