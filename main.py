from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def main():
    parser=argparse.ArgumentParser(description='ChannelGuard / 信道护航')
    parser.add_argument('--data-dir')
    parser.add_argument('--browser-worker')
    parser.add_argument('--process-worker')
    parser.add_argument('--url',default='')
    parser.add_argument('--wait-parent',type=int)
    parser.add_argument('--self-test',metavar='OUTPUT_JSON')
    parser.add_argument('--smoke-ui',metavar='OUTPUT_PNG')
    parser.add_argument('--initialize',action='store_true',help='打开初始化向导')
    args=parser.parse_args()
    if args.process_worker:
        from channelguard.process_worker import run_worker
        run_worker(args.process_worker);return
    if args.browser_worker:
        from channelguard.browser import browser_worker
        browser_worker(args.browser_worker,args.url);return
    if args.wait_parent:
        import psutil
        for _ in range(100):
            if not psutil.pid_exists(args.wait_parent):break
            time.sleep(.1)
    if args.self_test:
        from channelguard.storage import dpapi,new_channel
        from channelguard.engine import resource_root
        from channelguard.browser import browser_executable
        from channelguard.config import channel_config
        import yaml
        result={'dpapi':dpapi(dpapi(b'channelguard-self-test'),True)==b'channelguard-self-test',
                'browser_exists':Path(browser_executable()).is_file(),'config_generation':bool(channel_config(new_channel(),17777,17778,'u','p','s'))}
        from channelguard.process_router import NativeRouter
        native=NativeRouter(resource_root()/'vendor/process_router');native.close()
        result['native_backend_hash_and_abi_ready']=True
        core=resource_root()/'vendor'/'mihomo.exe'
        p=subprocess.run([str(core),'-v'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
        result['core']=p.stdout.decode(errors='replace').strip();result['core_ok']=p.returncode==0
        from PySide6 import QtCore
        result['qt']=QtCore.qVersion()
        # Exercise the bundled Node driver, Chromium, authenticated proxy, and fail-closed path.
        import tempfile,http.server,threading
        from channelguard.storage import Store
        from channelguard.system import ChildJob
        from channelguard.engine import Engines
        from channelguard.browser import launch_context,HOME
        from playwright.sync_api import sync_playwright
        class Target(http.server.BaseHTTPRequestHandler):
            calls=0
            def do_GET(self):
                Target.calls+=1
                body=b'ChannelGuard packaged relay'
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*_):pass
        with tempfile.TemporaryDirectory(prefix='channelguard-package-test-') as temporary:
            job=ChildJob();engines=Engines(Store(Path(temporary)),job)
            target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
            threading.Thread(target=target.serve_forever,daemon=True).start()
            try:
                channel=new_channel('Packaged verification');channel.update(timezone='Asia/Tokyo',locale='ja-JP')
                runtime=engines.start(channel)
                manifest=dict(channel=channel,port=runtime['port'],username=runtime['username'],password=runtime['password'],data_root=temporary)
                with sync_playwright() as playwright:
                    context=launch_context(playwright,manifest,headless=True)
                    try:
                        page=context.pages[0];page.goto(HOME)
                        env=page.evaluate('({tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language})')
                        result['browser_environment']=env
                        result['browser_environment_ok']=env=={'tz':'Asia/Tokyo','lang':'ja-JP'}
                        url=f'http://127.0.0.1:{target.server_port}/'
                        page.goto(url,timeout=8000)
                        result['browser_proxy_relay']='ChannelGuard packaged relay' in page.content()
                        before=Target.calls;engines.stop(channel['id'])
                        failed=False
                        try:page.goto(url+'after-stop',timeout=5000)
                        except Exception:failed=True
                        result['browser_no_direct_fallback']=failed and Target.calls==before
                    finally:context.close()
            except Exception as exc:
                result['browser_test_error_type']=type(exc).__name__
            finally:engines.stop_all();job.close();target.shutdown();target.server_close()
        Path(args.self_test).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');return
    from PySide6 import QtCore,QtGui,QtWidgets
    from channelguard.storage import Store
    from channelguard.system import secure_folder,ChildJob
    from channelguard.ui import MainWindow,STYLE
    if args.smoke_ui:
        os.environ['QT_QPA_PLATFORM']='offscreen'
    app=QtWidgets.QApplication(sys.argv)
    if not QtGui.QFontDatabase.families():
        # Qt's offscreen plugin has no Windows font database; use installed system fonts in tests.
        for font in ('msyh.ttc','msyhbd.ttc','segoeui.ttf','seguisym.ttf'):
            font_path=Path(os.environ.get('WINDIR','C:/Windows'))/'Fonts'/font
            if font_path.exists():QtGui.QFontDatabase.addApplicationFont(str(font_path))
    app.setApplicationName('ChannelGuard');app.setOrganizationName('ChannelGuard')
    app.setStyle('Fusion');app.setStyleSheet(STYLE)
    app.setFont(QtGui.QFont('Microsoft YaHei UI',10))
    data_root=Path(args.data_dir) if args.data_dir else Path(os.environ['LOCALAPPDATA'])/'ChannelGuard'
    data_root.mkdir(parents=True,exist_ok=True)
    lock=QtCore.QLockFile(str(data_root/'app.lock'));lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QtWidgets.QMessageBox.information(None,'ChannelGuard 已运行','此数据目录已有一个运行实例。请使用现有窗口。');return
    job=None
    try:
        secure_folder(data_root)
        # Prior crash files contain transient node credentials. Clear only owned file names.
        runtime=data_root/'runtime'
        if runtime.exists():
            for folder in runtime.iterdir():
                if folder.is_dir() and not folder.is_symlink():
                    for name in ('config.yaml','browser.dpapi'):(folder/name).unlink(missing_ok=True)
        store=Store(data_root);job=ChildJob();window=MainWindow(store,job)
        window.show()
        if args.initialize:
            def initialize_when_ready():
                if window.busy:QtCore.QTimer.singleShot(500,initialize_when_ready);return
                window.initialization_wizard()
            QtCore.QTimer.singleShot(800,initialize_when_ready)
        if args.smoke_ui:
            def capture():
                if window.busy:QtCore.QTimer.singleShot(200,capture);return
                window.grab().save(args.smoke_ui);window.close()
            QtCore.QTimer.singleShot(2000,capture)
        app.exec()
    except Exception as exc:
        QtWidgets.QMessageBox.critical(None,'ChannelGuard 启动失败',str(exc))
        raise
    finally:
        if job:job.close()
        lock.unlock()

if __name__=='__main__':main()
