"""Reproducible one-directory Windows bundle. Never includes user data / node credentials."""
from __future__ import annotations
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parent
from channelguard import __version__ as VERSION
OUT=ROOT/'release'/(VERSION+'-staging' if '--staging' in sys.argv else VERSION)

def copy_source(destination):
    destination.mkdir(parents=True,exist_ok=True)
    for name in ('main.py','build.py','build_native.py','native_children.c','native_udp.c','requirements.txt','README.md','LICENSE','KNOWN_LIMITATIONS.txt'):
        if (ROOT/name).exists():shutil.copy2(ROOT/name,destination/name)
    for name in ('channelguard','tests','docs'):
        shutil.copytree(ROOT/name,destination/name,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','debug_browser.py'))

def main():
    from playwright.sync_api import sync_playwright
    from PIL import Image,ImageDraw
    icon=ROOT/'build'/'channelguard.ico';icon.parent.mkdir(exist_ok=True)
    image=Image.new('RGBA',(256,256),'#102536');draw=ImageDraw.Draw(image)
    draw.rounded_rectangle((45,36,211,220),radius=42,fill='#59d5b8')
    draw.rounded_rectangle((68,60,188,196),radius=29,fill='#102536')
    draw.line([(91,130),(118,157),(169,100)],fill='#59d5b8',width=17)
    image.save(icon,sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])
    with sync_playwright() as p:
        browser_folder=Path(p.chromium.executable_path).parent
    if not browser_folder.joinpath('chrome.exe').exists():raise RuntimeError('Install Playwright Chromium before building')
    command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--console' if '--debug-console' in sys.argv else '--windowed','--onedir','--name','ChannelGuard',
             '--icon',str(icon),'--distpath',str(OUT),'--workpath',str(ROOT/'build'/'pyinstaller'),
             '--specpath',str(ROOT/'build'),'--collect-all','playwright','--collect-all','tzdata',
             '--add-data',str(ROOT/'vendor')+';vendor','--add-data',str(ROOT/'docs')+';docs',
             '--add-data',str(icon)+';assets','--add-data',str(ROOT/'channelguard'/'wsl_helper.py')+';.',
             '--exclude-module','tkinter','--exclude-module','numpy',
             '--exclude-module','matplotlib','--exclude-module','pandas','--exclude-module','IPython',str(ROOT/'main.py')]
    environment=os.environ.copy()
    # Do not accidentally bundle ICU / Windows CRT shims from unrelated developer apps in PATH.
    windows=Path(environment.get('WINDIR','C:/Windows'))
    environment['PATH']=os.pathsep.join(map(str,[Path(sys.base_prefix),Path(sys.base_prefix)/'DLLs',windows/'System32',windows]))
    environment['SETUPTOOLS_USE_DISTUTILS']='stdlib'
    subprocess.run(command,cwd=ROOT,check=True,env=environment)
    folder=OUT/'ChannelGuard'
    (folder/'初始化工具.cmd').write_text('@echo off\r\nstart "" "%~dp0ChannelGuard.exe" --initialize\r\n',encoding='ascii')
    internal=folder/'_internal'
    import PySide6
    qt=Path(PySide6.__file__).parent
    # Use the newest app-local MSVC redistributables required by Qt, also compatible with Python.
    for name in ('VCRUNTIME140.dll','VCRUNTIME140_1.dll','MSVCP140.dll','MSVCP140_1.dll','MSVCP140_2.dll'):
        if (qt/name).exists():shutil.copy2(qt/name,internal/name)
    shutil.copytree(browser_folder,folder/'_internal'/'browser',dirs_exist_ok=True)
    copy_source(folder/'source')
    shutil.copytree(ROOT/'docs',folder/'docs',dirs_exist_ok=True)
    shutil.copytree(ROOT/'THIRD_PARTY_NOTICES',folder/'THIRD_PARTY_NOTICES',dirs_exist_ok=True)
    for name in ('README.md','KNOWN_LIMITATIONS.txt','LICENSE'):
        shutil.copy2(ROOT/name,folder/name)
    metadata={name:importlib.metadata.version(name) for name in ('PySide6-Essentials','playwright','PyInstaller','requests','PyYAML','psutil','tzdata')}
    (folder/'BUILD.json').write_text(json.dumps({'version':VERSION,'architecture':'windows-x64','python':sys.version,'packages':metadata,
                                               'mihomo':json.loads((ROOT/'vendor'/'mihomo-release.json').read_text()),'build_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2),encoding='utf-8')
    print('Bundle ready:',folder,flush=True)

def archive():
    folder=OUT/'ChannelGuard'
    checksums=[]
    for path in sorted(folder.rglob('*')):
        if path.is_file() and path.name!='SHA256SUMS.txt':
            checksums.append(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.relative_to(folder).as_posix())
    (folder/'SHA256SUMS.txt').write_text('\n'.join(checksums)+'\n',encoding='utf-8')
    destination=OUT/f'ChannelGuard-{VERSION}-win64.zip'
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path in sorted(folder.rglob('*')):
            if path.is_file():archive.write(path,Path('ChannelGuard')/path.relative_to(folder))
    digest=hashlib.sha256(destination.read_bytes()).hexdigest()
    (OUT/(destination.name+'.sha256')).write_text(digest+'  '+destination.name+'\n',encoding='utf-8')
    print(destination,'bytes',destination.stat().st_size,'sha256',digest,flush=True)

if __name__=='__main__':
    if '--archive-only' in sys.argv:archive()
    else:main()
