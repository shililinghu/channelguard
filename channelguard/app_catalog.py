"""Discover the requested installed apps; only paths and launcher metadata are read."""
from pathlib import Path
import json
import os
import re
from .system import powershell
from .process_router import image_path,folder_pattern

CATALOG=[('QQ',r'^QQ$',('qq.exe',)),('微信',r'^(微信|WeChat|Weixin)$',('weixin.exe','wechat.exe')),
    ('飞书',r'^(飞书|Feishu|Lark)$',('feishu.exe','lark.exe')),
    ('MiniMax Design',r'^MiniMax Design$',('minimax design.exe',)),
    ('Steam',r'^Steam$',('steam.exe',)),('STOVE',r'^STOVE$',('stove.exe',)),
    ('MuMu',r'MuMu.*(模拟器|安卓设备)|^MuMu$',('mumunxmain.exe','mumuplayer.exe')),
    ('UU远程',r'^UU远程$',('gameviewer.exe',)),('雷神加速器',r'^雷神加速器$',('leigod_launcher.exe','leigod.exe')),
    ('夸克',r'^夸克$',('quark.exe',)),('明日方舟',r'明日方舟|Arknights',('arknights.exe',))]

def shortcuts():
    script=r'''
    $shell=New-Object -ComObject WScript.Shell;
    $roots=@([Environment]::GetFolderPath('Desktop'),"$env:PUBLIC\Desktop","$env:APPDATA\Microsoft\Windows\Start Menu\Programs","$env:ProgramData\Microsoft\Windows\Start Menu\Programs");
    $items=@(foreach ($root in $roots) {if (Test-Path -LiteralPath $root) {
      Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue |
      Where-Object {$_.Name -match 'QQ|微信|WeChat|Weixin|飞书|Feishu|Lark|MiniMax|Steam|STOVE|MuMu|UU远程|雷神|夸克|明日方舟|Arknights'} |
      ForEach-Object {$link=$shell.CreateShortcut($_.FullName);@{name=$_.BaseName;path=$link.TargetPath;arguments=$link.Arguments}}
    }});ConvertTo-Json -InputObject $items -Depth 3 -Compress
    '''
    return json.loads(powershell(script))

def discover_requested_apps(entries=None):
    entries=shortcuts() if entries is None else entries
    installed=[];missing=[]
    for label,pattern,names in CATALOG:
        choices=[x for x in entries if re.search(pattern,x.get('name',''),re.I) and Path(x.get('path','')).is_file()
                 and Path(x['path']).name.casefold() in names]
        if label=='明日方舟':
            # Common launcher-installed location; do not scan personal documents or game saves.
            for drive in ('C:','D:','E:','F:'):
                p=Path(drive+'/Game/ark/Hypergryph Launcher/games/Arknights/Arknights.exe')
                if p.is_file():choices.append(dict(name=label,path=str(p),arguments=''))
        if not choices:missing.append(label);continue
        # The current MiniMax version and actual UU bin are preferable to updater stubs.
        chosen=next((x for x in choices if 'current' in Path(x['path']).parts),choices[0])
        if label=='MuMu':chosen=next((x for x in choices if '模拟器' in x['name']),chosen)
        exe=Path(image_path(chosen['path']));folder=exe.parent
        if label=='MiniMax Design' and folder.name.casefold()=='current':folder=folder.parent
        if label=='STOVE' and folder.name.casefold()=='stove' and folder.parent.name.casefold()=='stove':folder=folder.parent
        if label=='MuMu' and folder.name.casefold()=='nx_main':folder=folder.parent
        if label=='UU远程' and folder.name.casefold()=='bin':folder=folder.parent
        if label=='明日方舟':folder=exe.parents[2]
        roots=[str(folder)]
        if label=='Steam':
            library=folder/'steamapps/libraryfolders.vdf'
            if library.is_file():
                for raw in re.findall(r'"path"\s+"([^"]+)"',library.read_text(encoding='utf-8',errors='replace')):
                    common=Path(raw.replace('\\\\','\\'))/'steamapps/common'
                    if common.is_dir() and not common.is_relative_to(folder):roots.append(str(common))
        if label=='MuMu':
            hypervisor=Path(os.environ.get('ProgramFiles','C:/Program Files'))/'MuMuNxVbox'
            if hypervisor.is_dir():roots.append(str(hypervisor))
        for root in roots:folder_pattern(root)
        installed.append(dict(label=label,path=str(exe),arguments=chosen.get('arguments',''),routing_roots=roots,source='installed-app-catalog'))
    return dict(installed=installed,missing=missing)

def assign_many(store,channel_id,apps):
    target=store.channel(channel_id)
    checked=[]
    for app in apps:
        item=dict(app,path=image_path(app['path']))
        for root in item.get('routing_roots',[]):folder_pattern(root)
        checked.append(item)
    # Validate every path before the first mutation; an explicit reassignment wins.
    paths={x['path'].casefold() for x in checked}
    for channel in store.data['channels']:
        channel['apps']=[x for x in channel.get('apps',[]) if x['path'].casefold() not in paths]
    target['apps'].extend(checked);store.save()
    return len(checked)
