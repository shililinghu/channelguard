from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
from PySide6 import QtCore,QtGui,QtWidgets as W
import yaml
from . import __version__
from .browser import HOME,is_chromium_browser
from .config import parse_nodes,proxy_url_node,validate_channel
from .diagnostics import diagnose
from .engine import Engines,resource_root
from .storage import Store,new_channel,atomic_write
from .presets import inspect_local_proxies,reconcile,readiness_label,values
from .system import ChildJob,scan_network,running_apps,is_admin,elevate,install_guard,remove_guard,list_guards,split_windows_arguments
from .monitor import fingerprint,binding,observe,environment_patch
from .integrations import OpenClawIntegration,wsl_call
from .initialization import initialize
from .process_router import ProcessRouting,image_path,folder_pattern
from .app_catalog import discover_requested_apps,assign_many
from .startup import startup_enabled,set_startup

STYLE = '''
QWidget {font-family:"Microsoft YaHei UI","Segoe UI";font-size:13px;color:#dce6f3;}
QMainWindow,QDialog {background:#0c1422;}
QFrame#sidebar {background:#101c2c;border-right:1px solid #233249;}
QLabel#brand {font-size:23px;font-weight:700;color:#f0f5ff;}
QLabel#eyebrow {font-size:10px;font-weight:600;color:#66d9bd;letter-spacing:2px;}
QLabel#title {font-size:27px;font-weight:700;color:#f0f5ff;}
QLabel#muted {color:#8fa3be;}
QLabel#small {font-size:11px;color:#8fa3be;}
QLabel#stat {font-size:30px;font-weight:700;color:#68dcc0;}
QFrame#card {background:#131f30;border:1px solid #26384e;border-radius:12px;}
QFrame#toolboxPage {background:#0c1422;}
QLabel#cardtitle {font-size:17px;font-weight:600;}
QPushButton {background:#22344b;border:1px solid #304763;border-radius:7px;padding:9px 15px;color:#dce8f8;}
QPushButton:hover {background:#2b4260;}
QPushButton:pressed {background:#172b41;}
QPushButton:disabled {color:#60718a;background:#162236;border-color:#233249;}
QPushButton#primary {background:#58d5b6;border-color:#58d5b6;color:#082b23;font-weight:600;}
QPushButton#primary:hover {background:#80e2c9;}
QPushButton#danger {color:#ffb4ab;background:#382732;border-color:#69414b;}
QPushButton#nav {text-align:left;border:0;background:transparent;padding:13px 18px;color:#a9b9ce;}
QPushButton#nav:checked {background:#203a49;color:#77e0c6;border-left:3px solid #63d6bb;border-radius:0;}
QLineEdit,QPlainTextEdit,QTextEdit,QComboBox,QSpinBox,QDoubleSpinBox {background:#0d1727;border:1px solid #30445e;border-radius:6px;padding:8px;selection-background-color:#2e776c;}
QLineEdit:focus,QPlainTextEdit:focus,QComboBox:focus {border-color:#66d9bd;}
QComboBox QAbstractItemView {background:#152338;selection-background-color:#2b5365;}
QTableWidget,QListWidget {background:#111e2e;alternate-background-color:#152438;border:1px solid #253950;border-radius:8px;gridline-color:#223349;selection-background-color:#24485a;}
QHeaderView::section {background:#1a2b41;color:#9fb4d0;border:0;padding:10px;font-size:12px;}
QTableWidget::item,QListWidget::item {padding:9px;}
QTabWidget::pane {border:1px solid #26394f;border-radius:7px;padding:12px;}
QTabBar::tab {background:#142136;padding:10px 18px;color:#8fa7c2;}
QTabBar::tab:selected {color:#6ce0c1;background:#1d3545;}
QCheckBox {spacing:8px;}
QScrollArea {border:0;background:transparent;}
QScrollBar:vertical {background:#0e1929;width:10px;} QScrollBar::handle:vertical {background:#334963;min-height:30px;border-radius:5px;}
QToolTip {background:#21354b;color:#e6effb;border:1px solid #46728a;padding:6px;}
QStatusBar {background:#101c2d;color:#94aec9;}
QMessageBox {background:#132034;} QMenu {background:#18283d;}
'''

def label(text,kind=None,wrap=False):
    item = W.QLabel(text)
    if kind:
        item.setObjectName(kind)
    item.setWordWrap(wrap)
    return item

def button(text,callback,kind=None):
    item = W.QPushButton(text)
    if kind:
        item.setObjectName(kind)
    item.clicked.connect(callback)
    return item

def table(headers):
    item = W.QTableWidget(0,len(headers))
    item.setHorizontalHeaderLabels(headers)
    item.setEditTriggers(W.QAbstractItemView.EditTrigger.NoEditTriggers)
    item.setSelectionBehavior(W.QAbstractItemView.SelectionBehavior.SelectRows)
    item.setSelectionMode(W.QAbstractItemView.SelectionMode.SingleSelection)
    item.setAlternatingRowColors(True)
    item.verticalHeader().hide()
    item.horizontalHeader().setSectionResizeMode(W.QHeaderView.ResizeMode.Stretch)
    item.verticalHeader().setDefaultSectionSize(48)
    return item

def fill(item,rows):
    item.setRowCount(len(rows))
    for i,row in enumerate(rows):
        for j,value in enumerate(row):
            cell = W.QTableWidgetItem(str(value))
            cell.setToolTip(str(value))
            item.setItem(i,j,cell)

class Signals(QtCore.QObject):
    done = QtCore.Signal(object)
    error = QtCore.Signal(str)

class Task(QtCore.QRunnable):
    def __init__(self,fn):
        super().__init__()
        self.fn,self.signals = fn,Signals()
    def run(self):
        try:
            value = self.fn()
        except Exception as exc:
            # Do not stringify request errors that can embed authenticated proxy URLs.
            if type(exc).__module__.startswith(('requests','urllib3','playwright')):
                message = '连接或浏览器操作失败（'+type(exc).__name__+'）。凭据未写入诊断结果。'
            else:
                message = str(exc)
            self.signals.error.emit(message)
        else:
            self.signals.done.emit(value)

class ChannelDialog(W.QDialog):
    def __init__(self,parent,channel,network):
        super().__init__(parent)
        self.setWindowTitle('信道配置 · ChannelGuard')
        self.resize(760,720)
        self.channel = copy.deepcopy(channel)
        layout = W.QVBoxLayout(self)
        layout.addWidget(label('配置一条信道','title'))
        layout.addWidget(label('出口、环境和保护策略保存在一起。保存后启动才生效。','muted'))
        tabs = W.QTabWidget()
        layout.addWidget(tabs,1)
        base = W.QWidget();form = W.QFormLayout(base)
        self.name = W.QLineEdit(channel['name']);form.addRow('信道名称',self.name)
        self.interface = W.QComboBox();self.interface.addItem('跟随系统路由（可能经过现有 VPN）','')
        for adapter in network.get('adapters',[]):
            self.interface.addItem(f"{adapter['Name']}  ·  {adapter['Status']}",adapter['Name'])
        index = self.interface.findData(channel.get('interface',''))
        if index < 0:
            self.interface.addItem(channel['interface']+'（当前未发现）',channel['interface']);index=self.interface.count()-1
        self.interface.setCurrentIndex(index);form.addRow('出口网卡 / VPN',self.interface)
        self.mode = W.QComboBox();self.mode.addItems(['不额外使用代理','HTTP / SOCKS 代理地址','Clash / Mihomo 节点 YAML'])
        form.addRow('代理类型',self.mode)
        self.proxy_url = W.QLineEdit();self.proxy_url.setPlaceholderText('socks5://127.0.0.1:1080 或 http://用户名:密码@主机:端口')
        self.proxy_url.setEchoMode(W.QLineEdit.EchoMode.PasswordEchoOnEdit);form.addRow('代理地址',self.proxy_url)
        self.node_text = W.QPlainTextEdit();self.node_text.setPlaceholderText('粘贴一个节点，或使用下方按钮从 Clash 配置提取。仅导入节点，不执行原文件规则、订阅或脚本。')
        self.node_text.setMinimumHeight(220);form.addRow('节点 YAML',self.node_text)
        node = channel.get('node')
        if node:
            self.mode.setCurrentIndex(2)
            self.node_text.setPlainText(yaml.safe_dump(node,allow_unicode=True,sort_keys=False))
        actions = W.QHBoxLayout()
        actions.addWidget(button('从 YAML 文件提取节点',self.import_file))
        actions.addWidget(button('选择本机代理',lambda:self.pick_local(network)))
        form.addRow(actions)
        form.addRow(label('海外 VPS 需先部署可用的代理或 VPN。导入它的客户端节点配置即可。TLS 证书验证保持开启。','small',True))
        self.mode.currentIndexChanged.connect(self.mode_changed);self.mode_changed()
        tabs.addTab(base,'网络出口')
        env = W.QWidget();ef = W.QFormLayout(env)
        presets = W.QComboBox();presets.addItems(['选择地区模板…','美国 · 洛杉矶','美国 · 纽约','日本 · 东京','新加坡','英国 · 伦敦','德国 · 柏林','中国 · 上海'])
        ef.addRow('地区模板',presets)
        self.timezone = W.QLineEdit(channel['timezone']);ef.addRow('IANA 时区',self.timezone)
        self.locale = W.QLineEdit(channel['locale']);ef.addRow('浏览器语言',self.locale)
        self.country = W.QLineEdit(channel.get('expected_country',''));self.country.setPlaceholderText('US / JP / SG；留空则不校验')
        ef.addRow('预期出口国家',self.country)
        self.geo = W.QComboBox();self.geo.addItems(['拒绝网页定位','使用指定位置'])
        self.geo.setCurrentIndex(1 if channel['geo']=='fixed' else 0);ef.addRow('定位策略',self.geo)
        self.latitude = W.QDoubleSpinBox();self.latitude.setRange(-90,90);self.latitude.setDecimals(5);self.latitude.setValue(channel['latitude'])
        self.longitude = W.QDoubleSpinBox();self.longitude.setRange(-180,180);self.longitude.setDecimals(5);self.longitude.setValue(channel['longitude'])
        ef.addRow('纬度',self.latitude);ef.addRow('经度',self.longitude)
        self.doh = W.QLineEdit(channel['doh']);ef.addRow('信道 DNS（DoH）',self.doh)
        self.bootstrap_doh=W.QLineEdit(channel.get('bootstrap_doh','https://1.1.1.1/dns-query'));ef.addRow('节点域名引导 DoH',self.bootstrap_doh)
        self.notes = W.QPlainTextEdit(channel.get('notes',''));self.notes.setMaximumHeight(90);ef.addRow('备注',self.notes)
        ef.addRow(label('时区、语言、定位由专用浏览器落实。普通应用的支持情况不同。IP 地区由真实出口决定，数据库可能有误差。','small',True))
        presets.currentIndexChanged.connect(self.preset)
        tabs.addTab(env,'信道环境')
        protection = W.QWidget();pl = W.QVBoxLayout(protection)
        pl.addWidget(label('第一版默认保护策略','cardtitle'))
        for text in ['• 每条信道独立的代理进程、DNS 配置与浏览器资料目录。',
                     '• 本机代理只监听 127.0.0.1，使用随机认证；控制接口也需要认证。',
                     '• 信道内拒绝 UDP 与 IPv6 目标；浏览器关闭 QUIC，限制非代理 WebRTC UDP。',
                     '• 代理节点失效时不自动回落直连。专用浏览器固定使用本地代理。',
                     '• 代理服务器域名需要引导解析：使用直接加密 DoH；目标域名通过信道 DNS。',
                     '• 配置使用 Windows DPAPI 加密；运行配置受当前用户目录权限保护。',
                     '• TUN 是可选的进程分流；不能视为任意应用的完整断线保护。',
                     '• 需要更严格的普通应用保护时，可单独安装「只许本地代理」防火墙阻断。',
                     '• 浏览器不伪造 Canvas / WebGL / 字体，不保证网站无法识别代理或机房 IP。']:
            pl.addWidget(label(text,'muted',True))
        pl.addStretch();tabs.addTab(protection,'保护范围')
        bottom = W.QDialogButtonBox(W.QDialogButtonBox.StandardButton.Save|W.QDialogButtonBox.StandardButton.Cancel)
        bottom.button(W.QDialogButtonBox.StandardButton.Save).setText('保存信道')
        bottom.button(W.QDialogButtonBox.StandardButton.Cancel).setText('取消')
        bottom.accepted.connect(self.accept);bottom.rejected.connect(self.reject);layout.addWidget(bottom)

    def mode_changed(self,*_):
        self.proxy_url.setEnabled(self.mode.currentIndex()==1)
        self.node_text.setEnabled(self.mode.currentIndex()==2)

    def preset(self,index):
        values = [None,('America/Los_Angeles','en-US','US',34.0522,-118.2437),
                  ('America/New_York','en-US','US',40.7128,-74.006),('Asia/Tokyo','ja-JP','JP',35.6762,139.6503),
                  ('Asia/Singapore','en-SG','SG',1.3521,103.8198),('Europe/London','en-GB','GB',51.5074,-.1278),
                  ('Europe/Berlin','de-DE','DE',52.52,13.405),('Asia/Shanghai','zh-CN','CN',31.2304,121.4737)]
        if values[index]:
            tz,locale,country,lat,lon = values[index]
            self.timezone.setText(tz);self.locale.setText(locale);self.country.setText(country)
            self.latitude.setValue(lat);self.longitude.setValue(lon)

    def import_file(self):
        path,_ = W.QFileDialog.getOpenFileName(self,'选择 Clash / Mihomo 配置','','YAML (*.yaml *.yml);;所有文件 (*)')
        if path:
            try:
                nodes,errors = parse_nodes(Path(path).read_text(encoding='utf-8-sig'))
                names = [f"{i+1}. {n.get('name',n['type'])} · {n['type']}" for i,n in enumerate(nodes)]
                selected,ok = W.QInputDialog.getItem(self,'选择节点',f'可导入 {len(nodes)} 个；跳过 {len(errors)} 个无效或不支持的节点',names,0,False)
                if ok:
                    self.node_text.setPlainText(yaml.safe_dump(nodes[names.index(selected)],allow_unicode=True,sort_keys=False))
                    self.mode.setCurrentIndex(2)
            except Exception as exc:
                W.QMessageBox.warning(self,'导入失败',str(exc))

    def pick_local(self,network):
        listeners = network.get('listeners',[])
        if not listeners:
            W.QMessageBox.information(self,'没有发现','未发现常用本机代理监听。请启动 Clash / Xray 后重新扫描，或手动填写。');return
        names = [f"{v['process']} · {v['host']}:{v['port']}" for v in listeners]
        value,ok = W.QInputDialog.getItem(self,'选择代理入口','仅发现端口，不代表已验证协议和连通性',names,0,False)
        if ok:
            listener = listeners[names.index(value)]
            protocol,ok = W.QInputDialog.getItem(self,'确认协议','请选择该入口实际支持的协议',['http','socks5'],0,False)
            if ok:
                self.proxy_url.setText(f"{protocol}://127.0.0.1:{listener['port']}");self.mode.setCurrentIndex(1)

    def accept(self):
        try:
            c = self.channel
            c.update(name=self.name.text().strip(),interface=self.interface.currentData(),timezone=self.timezone.text().strip(),
                     locale=self.locale.text().strip(),expected_country=self.country.text().upper().strip(),
                     geo='fixed' if self.geo.currentIndex() else 'deny',latitude=self.latitude.value(),longitude=self.longitude.value(),
                     doh=self.doh.text().strip(),bootstrap_doh=self.bootstrap_doh.text().strip(),notes=self.notes.toPlainText())
            mode = self.mode.currentIndex()
            c['node'] = None if mode==0 else (proxy_url_node(self.proxy_url.text()) if mode==1 else parse_nodes(self.node_text.toPlainText())[0][0])
            validate_channel(c)
            super().accept()
        except Exception as exc:
            W.QMessageBox.warning(self,'请检查信道配置',str(exc))

class MainWindow(W.QMainWindow):
    PAGES = (
        ('信道工作台','以信道为单位管理出口、环境和保护策略。','build_dashboard'),
        ('应用接入','把应用送入信道，并明确每一种接入方式的保护范围。','build_apps'),
        ('网络发现','区分物理连接、VPN 隧道和本机代理入口。','build_network'),
        ('工具箱','集中查看 EXE 网络、实际流量、信道连接与检测工具。','build_toolbox'),
        ('插件','管理已有的应用接入扩展。','build_plugins'),
        ('检测与记录','查看配置与实测证据；未知项目保持未知。','build_diagnostics'),
        ('设置与恢复','管理本地数据、管理员能力和可恢复的网络规则。','build_settings'),
    )

    def __init__(self,store,job):
        super().__init__()
        self.store,self.job = store,job
        self.engines = Engines(store,job)
        self.openclaw=OpenClawIntegration(store,self.engines)
        self.process_routing=ProcessRouting(store,self.engines)
        self.last_network_fingerprint=None
        self.last_exit_check=0
        self.monitor_task=None
        self.network = {}
        self.reports = {}
        self.tasks = []
        self.busy = False
        self.setWindowTitle('ChannelGuard · 信道护航  v'+__version__)
        icon=resource_root()/'assets'/'channelguard.ico'
        if icon.exists():self.setWindowIcon(QtGui.QIcon(str(icon)))
        self.resize(1240,820);self.setMinimumSize(1080,720)
        root = W.QWidget();self.setCentralWidget(root);outer = W.QHBoxLayout(root);outer.setContentsMargins(0,0,0,0);outer.setSpacing(0)
        sidebar = W.QFrame();sidebar.setObjectName('sidebar');sidebar.setFixedWidth(210)
        sl = W.QVBoxLayout(sidebar);sl.setContentsMargins(17,30,17,20);sl.setSpacing(8)
        sl.addWidget(label('CHANNEL / GUARD','eyebrow'));sl.addWidget(label('信道护航','brand'))
        sl.addWidget(label('让应用进入指定的网络环境','small',True));sl.addSpacing(30)
        self.nav = []
        for i,(title,_,_) in enumerate(self.PAGES):
            text=f'{i+1:02d}   {title}'
            b = button(text,lambda checked=False,index=i:self.show_page(index),'nav');b.setCheckable(True);sl.addWidget(b);self.nav.append(b)
        sl.addStretch();sl.addWidget(label('LOCAL / WINDOWS','eyebrow'))
        sl.addWidget(label('配置仅保存在本机\n无账号 · 无遥测 · 无自动上传','small',True))
        sl.addWidget(label('v'+__version__+'  ·  '+('管理员模式' if is_admin() else '标准用户模式'),'small'))
        outer.addWidget(sidebar)
        content = W.QWidget();cl = W.QVBoxLayout(content);cl.setContentsMargins(28,25,28,18);cl.setSpacing(15)
        self.page_title = label('信道工作台','title');cl.addWidget(self.page_title)
        self.page_subtitle = label('创建信道，分配应用，再验证实际出口与环境。','muted',True);cl.addWidget(self.page_subtitle)
        top = W.QHBoxLayout();top.addWidget(label('当前信道','small'))
        self.channel_picker = W.QComboBox();self.channel_picker.setMinimumWidth(260);self.channel_picker.currentIndexChanged.connect(self.selection_changed)
        top.addWidget(self.channel_picker);top.addStretch()
        self.live = label('全部已停止','muted');top.addWidget(self.live);cl.addLayout(top)
        self.stack = W.QStackedWidget();cl.addWidget(self.stack,1);outer.addWidget(content,1)
        for _,_,builder in self.PAGES:getattr(self,builder)()
        self.statusBar().showMessage('就绪。启动信道不会自动切换系统代理；TUN 需单独启用。')
        self.refresh_channels();self.show_page(0)
        self.timer = QtCore.QTimer(self);self.timer.timeout.connect(self.tick);self.timer.start(2000)
        self.monitor_timer=QtCore.QTimer(self);self.monitor_timer.timeout.connect(self.monitor_tick);self.monitor_timer.start(30000)
        QtCore.QTimer.singleShot(200,self.scan)

    def build_dashboard(self):
        page = W.QWidget();layout = W.QVBoxLayout(page);layout.setContentsMargins(0,0,0,0);layout.setSpacing(15)
        stats = W.QHBoxLayout();self.stats = []
        for name in ('已保存信道','运行中信道','已分配应用'):
            card = W.QFrame();card.setObjectName('card');l = W.QVBoxLayout(card);l.setContentsMargins(20,15,20,15)
            l.addWidget(label(name,'small'));value=label('0','stat');self.stats.append(value);l.addWidget(value);stats.addWidget(card)
        layout.addLayout(stats)
        self.summary_card = W.QFrame();self.summary_card.setObjectName('card');s = W.QVBoxLayout(self.summary_card);s.setContentsMargins(23,20,23,20)
        self.channel_name = label('','cardtitle');s.addWidget(self.channel_name)
        self.channel_summary = label('','muted',True);self.channel_summary.setTextFormat(QtCore.Qt.TextFormat.PlainText);s.addWidget(self.channel_summary)
        self.protection_status = label('信道尚未启动','small',True);s.addWidget(self.protection_status)
        actions=W.QHBoxLayout()
        self.start_button=button('启动信道',self.start_selected,'primary');actions.addWidget(self.start_button)
        actions.addWidget(button('停止信道',self.stop_selected));actions.addWidget(button('打开专用浏览器',self.open_browser))
        actions.addWidget(button('检测这条信道',self.run_diagnostics));s.addLayout(actions);layout.addWidget(self.summary_card)
        bar=W.QHBoxLayout();bar.addWidget(button('＋ 新建信道',self.new_channel));bar.addWidget(button('编辑信道',self.edit_channel))
        bar.addWidget(button('复制信道',self.clone_channel));bar.addWidget(button('删除信道',self.delete_channel))
        bar.addWidget(button('VPN 分流对接',self.vpn_handoff));bar.addStretch();layout.addLayout(bar)
        row=W.QHBoxLayout();row.addWidget(button('初始化向导',self.initialization_wizard,'primary'))
        row.addWidget(button('立即自动检测',lambda:self.monitor_tick(force=True)))
        self.monitor_note=label('自动检测尚未启用；可通过初始化向导设置。','small',True)
        row.addWidget(self.monitor_note,1);layout.addLayout(row)
        self.setup_note=label('正在识别本机网络并生成信道预设…','muted',True)
        setup=W.QHBoxLayout();setup.addWidget(self.setup_note,1);setup.addWidget(button('重新识别并预设',self.scan));layout.addLayout(setup)
        self.channel_table=table(['信道','出口','网卡','环境','状态']);self.channel_table.itemSelectionChanged.connect(self.table_select)
        layout.addWidget(self.channel_table,1)
        layout.addWidget(label('专用浏览器继承环境配置。普通应用需要选择接入方式；“引擎运行”不代表已经完成防泄露验证。','small',True))
        self.stack.addWidget(page)

    def build_apps(self):
        page=W.QWidget();l=W.QVBoxLayout(page);l.setContentsMargins(0,0,0,0)
        l.addWidget(label('开启系统分流后，已添加 EXE 的新 TCP / UDP 连接按信道转发，无需应用支持代理；已有连接需重连。','muted',True))
        bar=W.QHBoxLayout();bar.addWidget(button('从运行中程序选择',self.pick_running));bar.addWidget(button('添加 EXE',self.pick_exe));bar.addWidget(button('识别已安装应用',self.import_installed_apps));bar.addWidget(button('添加目录范围',self.add_app_folder));bar.addWidget(button('移除分配',self.remove_app));bar.addStretch();l.addLayout(bar)
        native=W.QFrame();native.setObjectName('card');nl=W.QVBoxLayout(native)
        controls=W.QHBoxLayout();controls.addWidget(button('开启系统分流',self.start_process_routing,'primary'));controls.addWidget(button('停止系统分流',self.stop_process_routing));controls.addStretch();nl.addLayout(controls)
        self.process_note=label('系统分流未启用 · EXE 分配尚未接管系统连接','small',True);nl.addWidget(self.process_note)
        nl.addWidget(label('子进程随父程序；目录范围覆盖独立启动的后台服务和后续安装的游戏。系统 DNS 代查、其他驱动产生的流量不保证按进程归属。退出后恢复系统网络。','small',True));l.addWidget(native)
        self.app_table=table(['应用','程序路径','所属信道','接入状态']);l.addWidget(self.app_table,1)
        bar=W.QHBoxLayout();bar.addWidget(button('使用信道代理启动',self.launch_selected_app,'primary'));bar.addWidget(button('安装直连阻断',self.guard_app));bar.addWidget(button('移除直连阻断',self.unguard_app));l.addLayout(bar)
        l.addWidget(label('浏览器独立会话另提供时区 / 语言 / 定位控制；普通 EXE 的系统分流只负责网络。代理变量启动仅适用于遵守变量的程序。直连阻断与系统分流不能混用。','small',True))
        tun=W.QFrame();tun.setObjectName('card');tl=W.QVBoxLayout(tun);tl.addWidget(label('可选：管理员 TUN 进程分流','cardtitle'))
        tl.addWidget(label('接管系统路由，按 EXE 路径将已分配应用送入信道。未分配应用走默认出口。Windows DNS 可能由系统服务代查，TUN 模式不承诺逐应用 DNS 隔离；严格需求使用专用浏览器或本地代理接入。','muted',True))
        controls=W.QHBoxLayout();controls.addWidget(button('按应用 TUN 分流',self.start_tun));controls.addWidget(button('全局使用当前信道',lambda:self.start_tun(global_mode=True)));controls.addWidget(button('停用 TUN',self.stop_tun));self.tun_status=label('TUN 未启用','small');controls.addWidget(self.tun_status);controls.addStretch();tl.addLayout(controls)
        more=button('高级：系统 TUN 路由',lambda:tun.setVisible(not tun.isVisible()));l.addWidget(more);l.addWidget(tun);tun.hide()
        self.stack.addWidget(page)

    def build_network(self):
        page=W.QWidget();l=W.QVBoxLayout(page);l.setContentsMargins(0,0,0,0)
        bar=W.QHBoxLayout();bar.addWidget(button('重新扫描本机网络',self.scan,'primary'));bar.addStretch();self.scan_time=label('等待扫描','small');bar.addWidget(self.scan_time);l.addLayout(bar)
        self.network_table=table(['连接','类型 / 设备','状态','IPv4','网关']);l.addWidget(self.network_table,2)
        l.addWidget(label('代理入口 · 发现端口后仍需确认协议并检测','cardtitle'))
        self.listener_table=table(['进程','监听地址','端口']);l.addWidget(self.listener_table,1)
        self.route_info=label('','muted',True);self.route_info.setTextFormat(QtCore.Qt.TextFormat.PlainText);l.addWidget(self.route_info)
        self.stack.addWidget(page)

    def build_toolbox(self):
        scroll=W.QScrollArea();scroll.setWidgetResizable(True)
        page=W.QFrame();page.setObjectName('toolboxPage');l=W.QVBoxLayout(page);l.setContentsMargins(0,0,10,0);l.setSpacing(15)
        l.addWidget(label('选择一项工具开始；信道类工具使用上方的“当前信道”。','muted',True))
        grid=W.QGridLayout();grid.setSpacing(15)
        tools=(
            ('EXE 网络实测','查询程序的实际信道、收发速率与 TCP 统计；证据不足时显示未知。','查询 EXE 网络',self.inspect_app_network),
            ('系统分流流量','查看系统分流记录的应用、信道、连接和实际转发量。','查看实际流量',self.show_process_flows),
            ('信道连接','查看当前信道内核记录的目的地址、协议和出口链。','查看当前信道连接',self.show_connections),
            ('信道出口检测','检测当前信道的实际出口与环境，结果保存到“检测与记录”。','检测当前信道',self.run_diagnostics),
            ('浏览器实测','打开当前信道的专用浏览器，在首页检测出口、WebRTC 与定位。','浏览器实测首页',self.open_browser),
            ('诊断报告','导出当前信道已有的检测记录，不包含节点密码和浏览器 Cookie。','导出脱敏报告',self.export_report),
        )
        for i,(title,description,action,callback) in enumerate(tools):
            card=W.QFrame();card.setObjectName('card');c=W.QVBoxLayout(card);c.setContentsMargins(20,18,20,18);c.setSpacing(12)
            c.addWidget(label(title,'cardtitle'));c.addWidget(label(description,'muted',True),1)
            row=W.QHBoxLayout();row.addWidget(button(action,callback));row.addStretch();c.addLayout(row)
            grid.addWidget(card,i//2,i%2)
        grid.setColumnStretch(0,1);grid.setColumnStretch(1,1);l.addLayout(grid)
        l.addWidget(label('EXE 网络实测可以独立选择程序；也可先在“应用接入”选中已分配的应用，再来查询。','small',True))
        l.addStretch();scroll.setWidget(page);self.stack.addWidget(scroll)

    def build_plugins(self):
        page=W.QWidget();l=W.QVBoxLayout(page);l.setContentsMargins(0,0,0,0);l.setSpacing(15)
        l.addWidget(label('内置接入扩展 · 1 项','small'))
        card=W.QFrame();card.setObjectName('card');c=W.QVBoxLayout(card);c.setContentsMargins(22,20,22,20);c.setSpacing(14)
        c.addWidget(label('WSL OpenClaw','cardtitle'))
        c.addWidget(label('将 WSL 内的 OpenClaw 服务接入当前信道，无需把整个 node.exe 或 WSL 分配到信道。','muted',True))
        self.openclaw_note=label('尚未接入。选择上方信道后，可手动连接并验证实际出口。','small',True);c.addWidget(self.openclaw_note)
        row=W.QHBoxLayout();row.addWidget(button('将 WSL OpenClaw 接入当前信道',self.connect_openclaw,'primary'))
        row.addWidget(button('验证 OpenClaw 实际出口',self.verify_openclaw));row.addStretch();c.addLayout(row)
        c.addWidget(label('接入操作会修改 OpenClaw 服务的代理配置并重启该服务；验证按钮读取实际服务环境发起请求。','small',True));l.addWidget(card)
        l.addWidget(label('目前仅整理已有的内置接入扩展，暂不支持安装第三方插件。','muted',True))
        l.addStretch();self.stack.addWidget(page)

    def build_diagnostics(self):
        page=W.QWidget();l=W.QVBoxLayout(page);l.setContentsMargins(0,0,0,0)
        bar=W.QHBoxLayout();bar.addWidget(button('检测当前信道',self.run_diagnostics,'primary'));bar.addStretch();l.addLayout(bar)
        l.addWidget(label('检测使用本信道访问 api.ipify.org 与 ipwho.is。不会在失败后改用直连。导出不含节点密码和浏览器 Cookie；报告包含出口 IP。','small',True))
        self.report_time=label('尚无检测记录','small');l.addWidget(self.report_time)
        self.check_table=table(['检测项目','证据状态','结果 / 说明']);self.check_table.horizontalHeader().setSectionResizeMode(0,W.QHeaderView.ResizeMode.ResizeToContents)
        self.check_table.horizontalHeader().setSectionResizeMode(1,W.QHeaderView.ResizeMode.ResizeToContents);l.addWidget(self.check_table,2)
        self.browser_report=W.QPlainTextEdit();self.browser_report.setReadOnly(True);self.browser_report.setPlaceholderText('浏览器的实际时区、语言和 WebRTC 结果会显示在这里。先打开专用浏览器，在首页点击检测。')
        l.addWidget(self.browser_report,1)
        self.stack.addWidget(page)

    def build_settings(self):
        page=W.QWidget();l=W.QVBoxLayout(page);l.setContentsMargins(0,0,0,0)
        card=W.QFrame();card.setObjectName('card');c=W.QVBoxLayout(card);c.setContentsMargins(22,18,22,18)
        c.addWidget(label('本地数据与恢复','cardtitle'))
        self.startup_checkbox=W.QCheckBox('开机自启')
        self.startup_checkbox.setToolTip('登录当前 Windows 用户后自动启动信道护航。')
        try:self.startup_checkbox.setChecked(startup_enabled())
        except OSError as exc:
            self.startup_checkbox.setEnabled(False);self.startup_checkbox.setToolTip('无法读取开机自启设置：'+str(exc))
        self.startup_checkbox.toggled.connect(self.toggle_startup);c.addWidget(self.startup_checkbox)
        c.addWidget(label('数据目录：'+str(self.store.root),'muted',True))
        c.addWidget(label('配置由当前 Windows 用户加密。浏览器资料也保存在此目录。退出时停止本工具引擎与受管子进程；不修改系统时区，不自动启用系统代理。','muted',True))
        row=W.QHBoxLayout();row.addWidget(button('打开数据目录',lambda:os.startfile(str(self.store.root))));row.addWidget(button('备份加密配置',self.backup));row.addWidget(button('恢复加密配置',self.restore));c.addLayout(row)
        row=W.QHBoxLayout();row.addWidget(button('管理员重启',self.restart_admin));row.addWidget(button('停止全部信道',self.stop_all));row.addWidget(button('打开使用说明',self.open_readme));c.addLayout(row);l.addWidget(card)
        l.addWidget(label('本工具创建的直连阻断规则','cardtitle'))
        self.guard_table=table(['规则','说明','启用状态']);l.addWidget(self.guard_table,1)
        row=W.QHBoxLayout();row.addWidget(button('刷新规则',self.refresh_guards));row.addWidget(button('移除选中规则',self.remove_selected_guard));row.addStretch();l.addLayout(row)
        l.addWidget(label('移除阻断规则会恢复该应用的系统联网能力。即使工具异常退出，这些规则也会保留，可在这里恢复。\nTUN 未提供独立于引擎的系统级 Kill Switch。深层浏览器指纹与机房 IP 识别不在第一版保证范围。','small',True))
        self.stack.addWidget(page)

    def toggle_startup(self,enabled):
        try:
            set_startup(enabled,self.store.root)
            self.statusBar().showMessage('开机自启已开启。' if enabled else '开机自启已关闭。',5000)
        except OSError as exc:
            self.startup_checkbox.blockSignals(True)
            self.startup_checkbox.setChecked(not enabled)
            self.startup_checkbox.blockSignals(False)
            W.QMessageBox.warning(self,'开机自启设置失败',str(exc))

    def current(self):
        identity=self.channel_picker.currentData()
        return self.store.channel(identity) if identity else None

    def initialization_wizard(self):
        if self.busy:return
        def ready(info):
            self.network=info
            from .presets import candidates
            options=candidates(info)
            dialog=W.QDialog(self);dialog.setWindowTitle('初始化向导 · ChannelGuard');dialog.resize(760,490)
            layout=W.QVBoxLayout(dialog);layout.addWidget(label('初始化网络环境','title'))
            layout.addWidget(label('识别本机连接 → 选择直连与 VPN → 检测真实出口 → 校准环境。保留已有浏览器资料和应用分配。','muted',True))
            form=W.QFormLayout();direct=W.QComboBox();vpn=W.QComboBox();vpn.addItem('暂不配置 VPN','')
            for c in options:
                if c['discovery']['readiness']=='ready':
                    if c['discovery']['kind']=='wifi':direct.addItem(c['interface'],c['interface'])
                    if c['discovery']['kind']=='vpn':vpn.addItem(c['interface'],c['interface'])
            if vpn.count()==2:vpn.setCurrentIndex(1)
            form.addRow('本机 Wi-Fi 直连',direct);form.addRow('VPN 隧道',vpn)
            doh=W.QComboBox();doh.setEditable(True);doh.addItems(['https://1.1.1.1/dns-query','https://223.5.5.5/dns-query'])
            existing=next((c for c in self.store.data['channels'] if c.get('network_role')=='direct' or c.get('discovery',{}).get('kind')=='wifi'),None)
            if existing:doh.setCurrentText(existing['doh'])
            form.addRow('直连加密 DNS',doh);layout.addLayout(form)
            auto=W.QCheckBox('每 30 秒检测网络变化，每 5 分钟复查出口');auto.setChecked(True);layout.addWidget(auto)
            env=W.QCheckBox('按实测出口更新新浏览器会话的时区和语言');env.setChecked(True);layout.addWidget(env)
            oc=W.QCheckBox('将 Ubuntu 内现有 OpenClaw 服务接入直连（会重启该服务）')
            oc.setChecked(bool(self.store.data.get('integrations',{}).get('openclaw',{}).get('enabled')));layout.addWidget(oc)
            layout.addWidget(label('不会修改 VPN 客户端安全设置、系统时区或防火墙。新的 VPN 若需要应用排除，请用“VPN 分流对接”复制直连内核路径。选项不明确时保留原信道并提示。','small',True))
            layout.addStretch();buttons=W.QDialogButtonBox(W.QDialogButtonBox.StandardButton.Ok|W.QDialogButtonBox.StandardButton.Cancel)
            buttons.button(W.QDialogButtonBox.StandardButton.Ok).setText('初始化并检测');buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);layout.addWidget(buttons)
            if dialog.exec()!=W.QDialog.DialogCode.Accepted:return
            settings=dict(direct=direct.currentData(),vpn=vpn.currentData(),doh=doh.currentText(),monitor=auto.isChecked(),environment_auto=env.isChecked())
            if not settings['direct']:W.QMessageBox.warning(self,'未发现 Wi-Fi','请先连接本机 Wi-Fi，再重新初始化。');return
            connect=oc.isChecked()
            def run():
                result=initialize(self.store,self.engines,info,settings)
                if connect:
                    c=self.store.channel(result[0]['id'])
                    result.append({'openclaw':self.openclaw.configure(c,info)})
                    self.store.save()
                return result
            def applied(result):
                self.monitor_note.setText('初始化完成；失败项目保持未验证。自动检测 '+('已启用' if auto.isChecked() else '已关闭'))
                atomic_write(self.store.root/'reports'/'initialization.json',json.dumps(result,ensure_ascii=False,indent=2).encode())
                self.channel_picker.setCurrentIndex(self.channel_picker.findData(result[0]['id']))
            self.work('初始化并检测',run,applied)
        self.work('初始化：识别网络',scan_network,ready)

    def connect_openclaw(self):
        c=self.current()
        if not c:return
        def run():
            self.engines.start(copy.deepcopy(c))
            info=scan_network();result=self.openclaw.configure(c,info);self.store.save();return result
        self.work('接入 WSL OpenClaw（重启服务）',run,self.openclaw_result)

    def verify_openclaw(self):
        config=self.store.data.get('integrations',{}).get('openclaw',{})
        if not config.get('enabled'):
            W.QMessageBox.information(self,'尚未接入','先选择直连信道，然后点击“将 WSL OpenClaw 接入当前信道”。');return
        self.work('验证 OpenClaw 服务环境中的出口',lambda:wsl_call(config.get('distro','Ubuntu'),'verify'),self.openclaw_result)

    def openclaw_result(self,result):
        verification=result.get('verification',result)
        rows=verification.get('checks',[])
        observed=[row.get('body','').strip() for row in rows if row.get('status')==200]
        self.openclaw_note.setText('OpenClaw → '+self.store.channel(self.store.data['integrations']['openclaw']['channel_id'])['name']+'；'+(' / '.join(observed) if observed else '出口未验证，保持固定代理'))
        atomic_write(self.store.root/'reports'/'openclaw.json',json.dumps(result,ensure_ascii=False,indent=2).encode())

    def monitor_tick(self,force=False):
        policy=self.store.data.get('monitor',{})
        if self.busy or (not force and not policy.get('enabled')):return
        channels=[copy.deepcopy(c) for c in self.store.data['channels'] if c['id'] in self.engines.active]
        if not channels:
            self.monitor_note.setText('自动检测已启用；等待启动信道' if policy.get('enabled') else '自动检测未启用');return
        previous=self.last_network_fingerprint
        due=force or time.monotonic()-self.last_exit_check>=policy.get('exit_interval_seconds',300)
        def check():
            info=scan_network();signature=fingerprint(info);changed=previous is not None and signature!=previous
            results=[]
            for c in channels:
                target,message=binding(c,info)
                row={'id':c['id'],'message':message}
                if target is None:
                    self.engines.pause(c['id']);row.update(paused=True);results.append(row);continue
                runtime=self.engines.active[c['id']]
                if c.get('suggested_environment') and any(p.poll() is None for p in runtime['browsers']):
                    self.engines.pause(c['id']);row.update(paused=True,message='请关闭专用浏览器并重新初始化地区环境');results.append(row);continue
                if target!=c.get('interface') or runtime['process'].poll() is not None:
                    c['interface']=target
                    try:self.engines.rebind(c);row['interface']=target
                    except Exception:row.update(paused=True,message='网卡重绑定失败，信道已暂停；未切换到系统出口');results.append(row);continue
                if due or changed:
                    row['observation']=observe(self.engines.proxy(c['id']))
                results.append(row)
            integration_result=None
            integration=self.store.data.get('integrations',{}).get('openclaw',{})
            if integration.get('enabled') and (changed or due or self.openclaw.bridge is None):
                try:
                    state=wsl_call(integration.get('distro','Ubuntu'))
                    if self.openclaw.bridge is None or state['host']!=integration.get('host') or state['peer']!=integration.get('peer'):
                        integration_result=self.openclaw.configure(self.store.channel(integration['channel_id']),info,integration.get('distro','Ubuntu'))
                except Exception:integration_result={'error':'WSL 接入未恢复，请重新初始化；未切换系统出口'}
            return dict(network=info,signature=signature,changed=changed,checked=due or changed,results=results,openclaw=integration_result)
        def complete(result):
            self.network=result['network'];self.last_network_fingerprint=result['signature']
            if result['checked']:self.last_exit_check=time.monotonic()
            messages=[]
            for row in result['results']:
                c=self.store.channel(row['id'])
                if row.get('interface'):c['interface']=row['interface']
                c['monitor_paused']=bool(row.get('paused'))
                if row.get('message'):messages.append(c['name']+'：'+row['message'])
                observation=row.get('observation')
                if observation is None:continue
                old=c.get('last_observation',{})
                c['last_observation']=dict(observation,at=time.time())
                if not observation['reachable']:
                    messages.append(c['name']+'：出口未验证');continue
                c['external_vpn_pending']=False
                if c.get('environment_auto'):
                    patch=environment_patch(observation)
                    runtime=self.engines.active[c['id']]
                    live_browsers=any(p.poll() is None for p in runtime['browsers'])
                    change=any(c.get(k)!=v for k,v in patch.items())
                    if live_browsers and change:
                        c['suggested_environment']=patch
                        self.engines.pause(c['id']);c['monitor_paused']=True
                        messages.append(c['name']+'：地区变化，请关闭专用浏览器并重新初始化')
                    else:
                        c.update(patch);c.pop('suggested_environment',None)
                        runtime['channel']=copy.deepcopy(c);self.engines.write_browser_manifest(c,runtime)
                if old.get('ips') and set(old['ips'])!=set(observation['ips']):messages.append(c['name']+'：出口 IP 已变化')
            self.store.save()
            if result.get('openclaw'):
                if result['openclaw'].get('error'):messages.append(result['openclaw']['error'])
                else:self.openclaw_result(result['openclaw'])
            config=self.store.data.get('integrations',{}).get('openclaw',{})
            if config.get('enabled') and self.openclaw.bridge is None:messages.append('OpenClaw 接入桥未运行，请重新初始化')
            self.monitor_note.setText('；'.join(messages) or ('自动检测正常 · '+time.strftime('%H:%M:%S')+' · 最近出口复查 '+time.strftime('%H:%M:%S',time.localtime(time.time()-(time.monotonic()-self.last_exit_check)))))
            sanitized=copy.deepcopy(result)
            sanitized['network']['system_proxy']={'enabled':bool(result['network'].get('system_proxy',{}).get('enabled'))}
            atomic_write(self.store.root/'reports'/'monitor.json',json.dumps(sanitized,ensure_ascii=False,indent=2).encode())
        self.work('自动检测网络变化',check,complete,quiet=True)

    def selected_app(self):
        row=self.app_table.currentRow()
        if row<0:raise ValueError('先在表格中选择一个应用。')
        return self.app_rows[row]

    def show_page(self,index):
        self.stack.setCurrentIndex(index)
        title,subtitle,builder=self.PAGES[index]
        self.page_title.setText(title);self.page_subtitle.setText(subtitle)
        for i,b in enumerate(self.nav):b.setChecked(i==index)
        if builder=='build_settings':self.refresh_guards()

    def work(self,title,fn,callback=None,quiet=False):
        if self.busy:
            self.statusBar().showMessage('正在处理上一项操作，请稍候。');return
        self.busy=True;self.statusBar().showMessage(title+'…');self.start_button.setEnabled(False)
        task=Task(fn);self.tasks.append(task)
        def finish(value,error=False):
            self.busy=False;self.start_button.setEnabled(True)
            if error:
                self.statusBar().showMessage('操作未完成')
                if quiet:self.monitor_note.setText('自动检测暂未完成：'+str(value))
                else:W.QMessageBox.warning(self,'操作未完成',str(value))
            else:
                if callback:
                    try:callback(value)
                    except Exception as exc:W.QMessageBox.warning(self,'结果处理失败',str(exc))
                self.statusBar().showMessage(title+'完成')
            self.refresh_channels();self.tasks.remove(task)
        task.signals.done.connect(lambda value:finish(value));task.signals.error.connect(lambda error:finish(error,True))
        QtCore.QThreadPool.globalInstance().start(task)

    def refresh_channels(self):
        identity=self.channel_picker.currentData()
        self.channel_picker.blockSignals(True);self.channel_picker.clear()
        channels=self.store.data['channels']
        for c in channels:self.channel_picker.addItem(c['name']+'  ·  '+self.state(c['id']),c['id'])
        index=self.channel_picker.findData(identity);self.channel_picker.setCurrentIndex(max(0,index));self.channel_picker.blockSignals(False)
        self.channel_table.blockSignals(True)
        fill(self.channel_table,[[c['name'],c['node'].get('name',c['node']['type']) if c.get('node') else '待导入节点' if c.get('setup_required') else '不额外使用代理',
                                  c['interface'] or '系统路由',c['timezone'],self.state(c['id'])] for c in channels])
        self.channel_table.blockSignals(False)
        self.selection_changed()

    def state(self,identity):
        runtime=self.engines.active.get(identity)
        channel=self.store.channel(identity)
        if channel.get('monitor_paused'):return '已暂停 · 请重新检测 / 初始化'
        if not runtime and channel.get('interface') and self.network:
            from .presets import require_interface
            try:require_interface(channel,self.network)
            except ValueError:return '网卡未连接'
        if not runtime and channel.get('external_vpn_pending'):return '待 VPN 分流放行'
        return '运行中' if runtime and runtime['process'].poll() is None else ('引擎已退出' if runtime else '已检测 · 未启动' if channel.get('last_observation',{}).get('reachable') else readiness_label(self.store.channel(identity)))

    def selection_changed(self,*_):
        c=self.current()
        if not c:
            self.channel_name.setText('还没有信道')
            self.channel_summary.setText('点击「新建信道」，添加网络出口与环境配置。')
            self.protection_status.setText('当前未提供信道保护')
            self.app_rows=[];fill(self.app_table,[]);self.render_report();self.tick();return
        self.channel_name.setText(c['name'])
        node=c.get('node');endpoint=f"{node['type']} · {node.get('server')}:{node.get('port')}" if node else '等待填写海外服务器节点' if c.get('setup_required') else '跟随所选网络，不额外使用代理'
        discovery=c.get('discovery',{})
        detail='\n预设：'+discovery.get('detail','') if discovery.get('managed') else ''
        if c.get('external_vpn_pending'):detail+='\n待配置外部 VPN：仅将本信道独立内核加入绕过列表，随后重新检测实际出口。'
        if discovery.get('environment_source'):detail+='\n'+discovery['environment_source']
        self.channel_summary.setText(f"出口：{endpoint}\n网卡：{c['interface'] or '跟随系统路由（可能经过现有 VPN）'}\n环境：{c['timezone']}  /  {c['locale']}  /  {'拒绝定位' if c['geo']=='deny' else '指定定位'}"+detail)
        runtime=self.engines.active.get(c['id'])
        self.protection_status.setText(f"{self.state(c['id'])} · "+(f"本地代理端口 {runtime['port']} · 含认证 · 检测结果见「检测与记录」" if runtime else '启动后才可接入应用；当前尚未提供信道保护'))
        self.app_rows=[(channel,app) for channel in self.store.data['channels'] for app in channel.get('apps',[])]
        def app_status(channel,app):
            runtime=self.engines.active.get(channel['id'],{})
            entry=runtime.get('launches',{}).get(str(Path(app['path']).resolve()).casefold())
            return entry[1] if entry and entry[0].poll() is None else '仅分配 · 尚未接入'
        fill(self.app_table,[[app.get('label') or Path(app['path']).name,app['path'],channel['name'],app_status(channel,app)] for channel,app in self.app_rows])
        for i,(_,app) in enumerate(self.app_rows):
            self.app_table.item(i,1).setToolTip(app['path']+'\n目录范围：\n'+'\n'.join(app.get('routing_roots',[])))
        integration=self.store.data.get('integrations',{}).get('openclaw',{})
        if integration.get('enabled'):
            name=self.store.channel(integration['channel_id'])['name']
            self.openclaw_note.setText('OpenClaw（WSL / '+integration.get('distro','Ubuntu')+'）→ '+name+'；'+('接入桥运行中' if self.openclaw.bridge else '等待恢复接入桥'))
        self.render_report();self.tick()

    def table_select(self):
        row=self.channel_table.currentRow()
        if 0<=row<len(self.store.data['channels']):self.channel_picker.setCurrentIndex(row)

    def tick(self):
        channels=self.store.data['channels']
        live=sum(1 for r in list(self.engines.active.values()) if r['process'].poll() is None)
        self.stats[0].setText(str(len(channels)));self.stats[1].setText(str(live));self.stats[2].setText(str(sum(len(c['apps']) for c in channels)+bool(self.store.data.get('integrations',{}).get('openclaw',{}).get('enabled'))))
        self.live.setText(f'{live} 条信道运行中' if live else '全部已停止')
        router=self.engines.router
        self.tun_status.setText(('全局 TUN' if router.get('global_channel') else '应用 TUN')+' 运行中' if router and router['process'].poll() is None else 'TUN 未启用')
        if self.process_routing.enabled:
            try:self.process_routing.publish()
            except Exception as exc:self.process_note.setText('规则更新失败，保留之前规则：'+str(exc))
        process_state=self.process_routing.status()
        state=process_state['state']
        if state=='running':self.process_note.setText(f"系统分流运行中 · {process_state.get('rule_count',0)} 条规则 · {len(process_state.get('flows',[]))} 条实际转发流 · {process_state.get('blocked',0)} 条阻断规则")
        elif state=='error':self.process_note.setText(process_state.get('message','系统接管未生效'))
        elif state=='starting':self.process_note.setText('等待管理员确认或驱动就绪；当前尚不能确认系统接管')
        elif state=='stopping':self.process_note.setText('正在停止系统分流，请等待驱动退出')
        else:self.process_note.setText('系统分流未启用 · 新连接使用系统网络；独立浏览器 / OpenClaw 另行接入')
        for i,c in enumerate(channels):
            cell=self.channel_table.item(i,4)
            if cell:cell.setText(self.state(c['id']))
        for i,(channel,app) in enumerate(getattr(self,'app_rows',[])):
            runtime=self.engines.active.get(channel['id'],{})
            entry=runtime.get('launches',{}).get(str(Path(app['path']).resolve()).casefold())
            cell=self.app_table.item(i,3)
            if state=='running':
                ready=runtime.get('process') and runtime['process'].poll() is None and not channel.get('monitor_paused')
                text='系统规则已加载 · 新连接接管' if ready else '系统阻断 · 信道未就绪'
                patterns={str(Path(app['path']).resolve()).casefold()}|{folder_pattern(p).casefold() for p in app.get('routing_roots',[]) if Path(p).is_dir()}
                if any(f.get('channel_id')==channel['id'] and f.get('matched_pattern','').casefold() in patterns for f in process_state.get('flows',[])):text+=' · 已观察转发'
            else:text=entry[1] if entry and entry[0].poll() is None else '会话已退出' if entry else '仅分配 · 尚未接入'
            if cell:cell.setText(text)
        c=self.current()
        if c:
            path=self.store.root/'reports'/(c['id']+'-browser.json')
            if path.exists():
                try:
                    data=json.loads(path.read_text(encoding='utf-8'))
                    saved=data.get('saved_at',0)
                    heading='浏览器页面实测（历史记录，启动新会话后请重新检测）\n'
                    runtime=self.engines.active.get(c['id'])
                    if runtime and saved>=runtime['started']:heading='当前会话 · 浏览器页面实测\n'
                    self.browser_report.setPlainText(heading+json.dumps(data,ensure_ascii=False,indent=2))
                except (OSError,ValueError):pass

    def mutable(self,channel=None):
        if self.busy:raise ValueError('请等待当前操作完成。')
        if self.engines.router:raise ValueError('请先停用 TUN，再修改分配或信道。')
        if channel and channel['id'] in self.engines.active:raise ValueError('请先停止这条信道，再修改配置。')

    def vpn_handoff(self):
        channel=self.current()
        if not channel:return
        core=self.engines.prepare_core(channel['id'])
        dialog=W.QDialog(self);dialog.setWindowTitle('外部 VPN 分流对接');dialog.resize(760,300)
        layout=W.QVBoxLayout(dialog)
        layout.addWidget(label(channel['name'],'cardtitle'))
        layout.addWidget(label('每条信道使用独立内核文件。需要本机直连时，将下面这个文件加入外部 VPN 的「绕过 / 排除应用」列表。美国 VPN 信道的内核不要加入。\n受管浏览器仍通过本工具接入，不需要排除整个浏览器或 ChannelGuard.exe。\nZoogVPN 开启 Kill Switch 且关闭分流时，可能拒绝网卡直连；需要在 ZoogVPN 中手动配置。本工具不修改其安全开关。','muted',True))
        field=W.QLineEdit(str(core));field.setReadOnly(True);layout.addWidget(field)
        row=W.QHBoxLayout();row.addWidget(button('复制内核路径',lambda:W.QApplication.clipboard().setText(str(core))))
        row.addWidget(button('打开所在文件夹',lambda:os.startfile(str(core.parent))));row.addStretch();row.addWidget(button('关闭',dialog.accept));layout.addLayout(row)
        dialog.exec()

    def safe(self,fn):
        try:return fn()
        except Exception as exc:W.QMessageBox.warning(self,'无法继续',str(exc))

    def new_channel(self):
        def action():
            self.mutable();dialog=ChannelDialog(self,new_channel(),self.network)
            if dialog.exec():
                self.store.data['channels'].append(dialog.channel);self.store.save();self.refresh_channels();self.channel_picker.setCurrentIndex(self.channel_picker.count()-1)
        self.safe(action)

    def edit_channel(self):
        def action():
            c=self.current()
            if not c:return
            self.mutable(c);dialog=ChannelDialog(self,c,self.network)
            if dialog.exec():
                c.update(dialog.channel)
                if c.get('setup_required') and c.get('node'):c.pop('setup_required',None)
                if c.get('discovery'):c['discovery']=dict(key=c['discovery']['key'],managed=False)
                self.store.save();self.refresh_channels()
        self.safe(action)

    def clone_channel(self):
        def action():
            self.mutable();c=self.current()
            if not c:return
            clone=copy.deepcopy(c);clone['id']=new_channel()['id'];clone['name']=c['name']+' 副本';clone['apps']=[]
            clone.pop('discovery',None)
            self.store.data['channels'].append(clone);self.store.save();self.refresh_channels();self.channel_picker.setCurrentIndex(self.channel_picker.count()-1)
        self.safe(action)

    def delete_channel(self):
        def action():
            c=self.current()
            if not c:return
            self.mutable(c)
            if W.QMessageBox.question(self,'删除信道','删除此信道配置？浏览器资料目录将保留，避免丢失登录数据。')==W.QMessageBox.StandardButton.Yes:
                if c.get('discovery'):
                    suppressed=self.store.data.setdefault('discovery_suppressed',[])
                    if c['discovery']['key'] not in suppressed:suppressed.append(c['discovery']['key'])
                self.store.data['channels'].remove(c);self.store.save();self.refresh_channels()
        self.safe(action)

    def start_selected(self):
        c=self.current()
        if c:
            def start():
                runtime=self.engines.active.get(c['id'])
                if runtime and runtime['process'].poll() is not None:return self.engines.rebind(copy.deepcopy(c))
                return self.engines.start(copy.deepcopy(c))
            def complete(_):c['monitor_paused']=False;self.store.save()
            self.work('启动信道',start,complete)

    def stop_selected(self):
        c=self.current()
        if c:self.work('停止信道',lambda:self.engines.stop(c['id']))

    def stop_all(self):self.work('停止全部信道',self.engines.stop_all)

    def open_browser(self,url=''):
        if isinstance(url,bool):url=''
        c=self.current()
        if not c:return
        def run():
            runtime=self.engines.start(copy.deepcopy(c))
            if runtime['process'].poll() is not None:raise RuntimeError('信道引擎已退出，请停止后重新启动。')
            return self.engines.launch_browser(c['id'],url)
        self.work('打开专用浏览器',run)

    def scan(self):
        def discover():return inspect_local_proxies(scan_network(),[r['process'].pid for r in list(self.engines.active.values())])
        self.work('识别网络并预置信道',discover,self.scanned)

    def scanned(self,info):
        self.network=info;self.scan_time.setText('上次扫描 '+time.strftime('%H:%M:%S'))
        added=reconcile(self.store,info,set(self.engines.active))
        count=sum(1 for c in self.store.data['channels'] if c.get('discovery'))
        ready=sum(1 for c in self.store.data['channels'] if c.get('discovery',{}).get('readiness')=='ready')
        self.setup_note.setText(f'已预设 {count} 条信道：{ready} 条可接入，{count-ready} 条未连接或待配置。接入方式可能共享同一底层网络，出口待实测。')
        configs={c['InterfaceAlias']:c for c in info.get('configs',[])}
        def joined(value):return ', '.join(str(v) for v in values(value) if v)
        fill(self.network_table,[[a['Name'],a['InterfaceDescription'],a['Status'],joined(configs.get(a['Name'],{}).get('IPv4',[])),joined(configs.get(a['Name'],{}).get('Gateway',[]))] for a in info.get('adapters',[])])
        fill(self.listener_table,[[v['process'],v['host'],v['port']] for v in info.get('listeners',[])])
        routes=info.get('routes',[])
        self.route_info.setText('当前默认 / 拆分路由：\n'+'\n'.join(f"{r['DestinationPrefix']} → {r['InterfaceAlias']} → {r['NextHop']}" for r in routes)+'\n系统代理：'+('启用' if info.get('system_proxy',{}).get('enabled') else '关闭'))
        if not getattr(self,'startup_restored',False):
            self.startup_restored=True
            settings=self.store.data.get('initialization',{})
            if settings.get('completed') and settings.get('auto_start'):
                QtCore.QTimer.singleShot(300,self.restore_initialized)
            elif self.store.data.get('process_routing',{}).get('enabled'):
                QtCore.QTimer.singleShot(400,self.start_process_routing)

    def restore_initialized(self):
        if self.busy:QtCore.QTimer.singleShot(500,self.restore_initialized);return
        def run():
            info=scan_network();results=[]
            for identity in self.store.data.get('initialization',{}).get('channel_ids',[]):
                c=self.store.channel(identity)
                target,message=binding(c,info)
                if target is None:
                    c['monitor_paused']=True;results.append(c['name']+' 未连接');continue
                c['interface']=target
                try:self.engines.start(copy.deepcopy(c));c['monitor_paused']=False
                except Exception:c['monitor_paused']=True;results.append(c['name']+' 启动未完成')
            config=self.store.data.get('integrations',{}).get('openclaw',{})
            if config.get('enabled'):
                try:self.openclaw.prepare(self.store.channel(config['channel_id']),info,config.get('distro','Ubuntu'))
                except Exception:results.append('OpenClaw 接入桥恢复失败，请重新初始化')
            self.store.save()
            return results
        def complete(messages):
            self.monitor_note.setText('；'.join(messages) or '初始化配置已恢复；正在复查实际出口')
            QtCore.QTimer.singleShot(200,lambda:self.monitor_tick(force=True))
            if self.store.data.get('process_routing',{}).get('enabled'):
                QtCore.QTimer.singleShot(700,self.start_process_routing)
        self.work('恢复初始化信道',run,complete,quiet=True)

    def assign_path(self,path):
        c=self.current()
        if not c:return
        self.mutable()
        path=image_path(path)
        if Path(path).resolve()==self.engines.core.resolve() or Path(path).resolve().is_relative_to((self.store.root/'engines').resolve()):
            raise ValueError('不能将本工具的网络内核分配回信道，以免形成连接循环。')
        if any(app['path'].casefold()==path.casefold() for channel in self.store.data['channels'] for app in channel['apps']):
            raise ValueError('该程序已经分配过。先移除原分配再添加。')
        candidate=copy.deepcopy(c);candidate['apps'].append({'path':str(Path(path).resolve())});validate_channel(candidate)
        c.update(candidate);self.store.save();self.refresh_channels()
        self.sync_process_channels()

    def pick_exe(self):
        path,_=W.QFileDialog.getOpenFileName(self,'选择应用 EXE','','应用 (*.exe)')
        if path:self.safe(lambda:self.assign_path(path))

    def pick_running(self):
        def complete(apps):
            names=[a['name']+'  —  '+a['path'] for a in apps]
            if not names:return
            chosen,ok=W.QInputDialog.getItem(self,'选择运行中的应用','将加入当前信道；系统分流运行期间自动应用于新连接',names,0,False)
            if ok:self.safe(lambda:self.assign_path(apps[names.index(chosen)]['path']))
        self.work('获取运行程序',running_apps,complete)

    def remove_app(self):
        def action():
            c,app=self.selected_app();self.mutable();c['apps'].remove(app);self.store.save();self.refresh_channels()
        self.safe(action)

    def import_installed_apps(self):
        channel=self.current()
        if not channel:return
        def complete(result):
            dialog=W.QDialog(self);dialog.setWindowTitle('将已安装应用加入 '+channel['name']);dialog.resize(850,570)
            layout=W.QVBoxLayout(dialog);layout.addWidget(label('勾选应用及其安装目录。包含 Steam / STOVE 游戏目录、MuMu 虚拟机后台程序；规则运行期间自动应用。虚拟机转发流量仍需实测确认归属。','muted',True))
            items=W.QListWidget();items.setSelectionMode(W.QAbstractItemView.SelectionMode.NoSelection);layout.addWidget(items)
            for app in result['installed']:
                item=W.QListWidgetItem(app['label']+'  —  '+app['path']);item.setFlags(item.flags()|QtCore.Qt.ItemFlag.ItemIsUserCheckable);item.setCheckState(QtCore.Qt.CheckState.Checked);item.setToolTip('\n'.join(app['routing_roots']));items.addItem(item)
            if result['missing']:layout.addWidget(label('未识别：'+'、'.join(result['missing'])+'；可手动添加 EXE。','small',True))
            buttons=W.QDialogButtonBox(W.QDialogButtonBox.StandardButton.Ok|W.QDialogButtonBox.StandardButton.Cancel);buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);layout.addWidget(buttons)
            if dialog.exec()==W.QDialog.DialogCode.Accepted:
                selected=[app for i,app in enumerate(result['installed']) if items.item(i).checkState()==QtCore.Qt.CheckState.Checked]
                self.store.backup(self.store.root/('before-bulk-apps-'+str(time.time_ns())+'.dpapi'))
                self.safe(lambda:assign_many(self.store,channel['id'],selected));self.refresh_channels()
                self.sync_process_channels()
        self.work('识别应用与游戏库目录',discover_requested_apps,complete)

    def add_app_folder(self):
        def run():
            self.mutable();channel,app=self.selected_app()
            folder=W.QFileDialog.getExistingDirectory(self,'加入该应用所属信道的完整程序 / 游戏目录',str(Path(app['path']).parent))
            if not folder:return
            folder_pattern(folder)
            app['routing_roots']=list(dict.fromkeys(app.get('routing_roots',[])+[str(Path(folder).resolve())]))
            self.store.save();self.refresh_channels()
        self.safe(run)

    def prepare_process_channels(self):
        from .config import channel_config
        prepared=[]
        for c in self.store.data['channels']:
            if c.get('apps'):
                candidate=copy.deepcopy(c);candidate['native_udp']=True
                channel_config(candidate,1234,1235,'u','p','s');prepared.append((c,candidate))
        self.store.backup(self.store.root/('before-system-routing-'+str(time.time_ns())+'.dpapi'))
        for c,candidate in prepared:
            changed=not c.get('native_udp');c.update(candidate)
            if c.get('monitor_paused'):continue
            runtime=self.engines.active.get(c['id'])
            if runtime:
                if changed or not runtime.get('channel',{}).get('native_udp') or runtime['process'].poll() is not None:self.engines.rebind(c)
            else:
                try:self.engines.start(c)
                except Exception:c['monitor_paused']=True
        self.store.save()

    def sync_process_channels(self):
        if self.process_routing.enabled and any(c.get('apps') and not c.get('native_udp') for c in self.store.data['channels']):
            self.work('准备新增应用的 TCP / UDP 信道',self.prepare_process_channels)

    def start_process_routing(self):
        if self.process_routing.enabled and self.process_routing.status()['state'] in ('running','starting'):
            self.statusBar().showMessage('系统分流已开启，添加或修改 EXE 后自动应用新连接。');return
        def start():
            if self.engines.router:raise RuntimeError('请先停用 TUN，再启用系统进程分流。')
            if self.store.data.get('firewall_guards'):raise RuntimeError('请先在设置中移除旧版直连阻断规则；它与系统分流不兼容。')
            self.prepare_process_channels();self.process_routing.start()
        self.work('开启系统进程分流（Windows 管理员确认）',start)

    def stop_process_routing(self):
        self.safe(self.process_routing.stop)

    def show_process_flows(self):
        dialog=W.QDialog(self);dialog.setWindowTitle('系统分流实际流量');dialog.resize(1000,540)
        layout=W.QVBoxLayout(dialog);layout.addWidget(label('实际转发流（定时刷新）。规则加载不等于出口已验证；已有 TCP 连接不会迁移，系统 DNS 代查和驱动流量另行核查。','muted',True))
        grid=table(['进程 / PID','信道','协议','目的地址','已发送 / 接收']);layout.addWidget(grid)
        def refresh():
            data=self.process_routing.status();names={c['id']:c['name'] for c in self.store.data['channels']}
            fill(grid,[[f"{f['application']} / {f['pid']}",names.get(f['channel_id'],'未知'),f['protocol'],f"{f['destination']}:{f['port']}",f"{f['sent']} / {f['received']}"] for f in data.get('flows',[])])
        timer=QtCore.QTimer(dialog);timer.timeout.connect(refresh);timer.start(1000);refresh()
        layout.addWidget(button('关闭',dialog.accept));dialog.exec()

    def inspect_app_network(self):
        from .app_inspector_ui import AppInspectorDialog
        row=self.app_table.currentRow()
        path=self.app_rows[row][1]['path'] if 0<=row<len(self.app_rows) else ''
        AppInspectorDialog(self,path).exec()

    def launch_selected_app(self):
        def action():
            c,app=self.selected_app()
            if is_chromium_browser(app['path']):
                def launch():self.engines.start(copy.deepcopy(c));return self.engines.launch_app(c['id'],app['path'])
                self.work('打开浏览器独立信道会话（保留原浏览器资料）',launch)
                return
            if any(p.info.get('exe') and p.info['exe'].casefold()==app['path'].casefold() for p in __import__('psutil').process_iter(['exe'])):
                if W.QMessageBox.question(self,'程序可能已运行','检测到同路径程序正在运行。单实例应用可能复用旧进程，代理变量不会生效。仍要启动吗？')!=W.QMessageBox.StandardButton.Yes:return
            arguments,ok=W.QInputDialog.getText(self,'启动应用','启动参数（可留空；按 Windows 引号规则解析，不经过命令行 Shell）',text=app.get('arguments',''))
            if not ok:return
            parsed=split_windows_arguments(arguments)
            app['arguments']=arguments;self.store.save()
            def launch():self.engines.start(copy.deepcopy(c));return self.engines.launch_app(c['id'],app['path'],parsed)
            self.work('通过信道代理启动应用',launch)
        self.safe(action)

    def guard_app(self):
        def action():
            c,app=self.selected_app()
            if Path(app['path']).resolve()==self.engines.core.resolve():
                raise ValueError('不能给网络内核安装直连阻断，否则所有信道都会失去出口。')
            text='此规则会持续阻断该 EXE 到非回环地址的直接连接。只有通过本机代理联网的应用适用；不适用于 TUN 接入，子进程需分别设置。\n\n'+app['path']+'\n\n安装后可在「设置与恢复」移除。继续安装？'
            if W.QMessageBox.question(self,'安装应用直连阻断',text)!=W.QMessageBox.StandardButton.Yes:return
            def installed(name):self.store.data['firewall_guards'][name]=app['path'];self.store.save()
            self.work('安装直连阻断',lambda:install_guard(app['path']),installed)
        self.safe(action)

    def unguard_app(self):
        def action():
            from .system import firewall_rule_name
            c,app=self.selected_app();name=firewall_rule_name(app['path'])
            if W.QMessageBox.question(self,'恢复应用联网','移除此应用的直连阻断？应用将恢复使用系统网络的能力。')==W.QMessageBox.StandardButton.Yes:
                self.work('移除直连阻断',lambda:remove_guard(name),lambda _:self.guard_removed(name))
        self.safe(action)

    def guard_removed(self,name):
        self.store.data['firewall_guards'].pop(name,None);self.store.save();self.guard_table.setRowCount(0)

    def start_tun(self,checked=False,global_mode=False):
        if self.process_routing.enabled:
            W.QMessageBox.information(self,'请先停止系统分流','系统进程分流不能与本工具 TUN 同时运行。');return
        if not is_admin():W.QMessageBox.information(self,'需要管理员权限','先到「设置与恢复」点击「管理员重启」，再启用 TUN。');return
        if not self.network:W.QMessageBox.information(self,'先扫描网络','请先在网络发现中完成扫描。');return
        if any(r['DestinationPrefix'] in ('0.0.0.0/1','128.0.0.0/1') for r in self.network.get('routes',[])):
            W.QMessageBox.warning(self,'检测到现有 VPN 拆分路由','当前 VPN 正在接管默认流量。第一版为避免相互抢路由，不会叠加启动 TUN。请手动断开现有 VPN，再重新扫描。专用浏览器和本地代理接入仍可使用。');return
        c=self.current()
        if global_mode and (not c or c['id'] not in self.engines.active):
            W.QMessageBox.information(self,'先启动信道','全局模式需要先启动当前信道。');return
        description='全部应用走当前信道，UDP / IPv6 全局阻断。' if global_mode else '未分配应用使用 TUN 默认出口；UDP / IPv6 在已分配应用中被阻断。'
        if W.QMessageBox.question(self,'启用系统 TUN 路由','这会临时接管系统路由。'+description+'\nTUN 不是独立 Kill Switch，已有连接需重启应用。停止 TUN 后恢复系统路由。继续？')==W.QMessageBox.StandardButton.Yes:
            self.work('启动 TUN 分流',lambda:self.engines.start_router(copy.deepcopy(self.store.data['channels']),c['id'] if global_mode else None))

    def stop_tun(self):self.work('停止 TUN 分流',self.engines.stop_router)

    def run_diagnostics(self):
        c=self.current()
        if not c:return
        self.show_page(next(i for i,page in enumerate(self.PAGES) if page[2]=='build_diagnostics'))
        def complete(report):self.reports[c['id']]=report;self.render_report()
        self.work('检测信道出口',lambda:diagnose(self.engines,copy.deepcopy(c)),complete)

    def render_report(self):
        c=self.current()
        if not c:self.check_table.setRowCount(0);self.browser_report.clear();self.report_time.setText('尚无检测记录');return
        report=self.reports.get(c['id'])
        if not report:
            path=self.store.root/'reports'/(c['id']+'-network.json')
            if path.exists():
                try:report=json.loads(path.read_text(encoding='utf-8'))
                except (OSError,ValueError):pass
        statuses={'observed':'已观察','failed':'失败','warning':'需确认','configured':'仅配置','unknown':'未验证'}
        self.report_time.setText('最近记录：'+report.get('time','未知时间')+' · 配置或网络改变后请重新检测' if report else '尚无检测记录')
        fill(self.check_table,[[x['name'],statuses.get(x['status'],x['status']),x['detail']] for x in (report or {}).get('checks',[])])
        self.check_table.resizeRowsToContents()
        self.browser_report.clear()

    def export_report(self):
        c=self.current()
        if not c:return
        report={'app_version':__version__,'channel_name':c['name'],'exported_at':time.strftime('%Y-%m-%d %H:%M:%S')}
        for kind in ('network','browser'):
            path=self.store.root/'reports'/(c['id']+'-'+kind+'.json')
            if path.exists():
                try:report[kind]=json.loads(path.read_text(encoding='utf-8'))
                except (OSError,ValueError):pass
        path,_=W.QFileDialog.getSaveFileName(self,'导出诊断报告（含出口 IP，不含节点密码）','ChannelGuard-report.json','JSON (*.json)')
        if path:self.safe(lambda:atomic_write(Path(path),json.dumps(report,ensure_ascii=False,indent=2).encode('utf-8')))

    def show_connections(self):
        c=self.current()
        if not c:return
        def complete(data):
            rows=[]
            for conn in data.get('connections',[])[:200]:
                meta=conn.get('metadata',{});rows.append([meta.get('host') or meta.get('destinationIP'),meta.get('destinationPort'),meta.get('network'),', '.join(conn.get('chains',[]))])
            dialog=W.QDialog(self);dialog.setWindowTitle('当前信道连接');dialog.resize(850,440);layout=W.QVBoxLayout(dialog)
            t=table(['目的地址','端口','协议','出口链']);fill(t,rows);layout.addWidget(t);dialog.exec()
        self.work('读取当前连接',lambda:self.engines.connections(c['id']),complete)

    def refresh_guards(self):
        if self.busy:return
        self.work('读取防火墙规则',list_guards,lambda rows:fill(self.guard_table,[[r['Name'],r['DisplayName'],r['Enabled']] for r in rows]))

    def remove_selected_guard(self):
        row=self.guard_table.currentRow()
        if row<0:return
        name=self.guard_table.item(row,0).text()
        if W.QMessageBox.question(self,'移除直连阻断','移除所选规则，恢复对应应用的系统联网能力？')==W.QMessageBox.StandardButton.Yes:
            self.work('移除规则',lambda:remove_guard(name),lambda _:self.guard_removed(name))

    def backup(self):
        path,_=W.QFileDialog.getSaveFileName(self,'备份配置（仅同一 Windows 用户可恢复）','ChannelGuard-backup.dpapi','加密配置 (*.dpapi)')
        if path:self.safe(lambda:self.store.backup(path))

    def restore(self):
        def action():
            self.mutable()
            if self.engines.active:raise ValueError('先停止全部信道，再恢复配置。')
            path,_=W.QFileDialog.getOpenFileName(self,'恢复配置（不包含浏览器资料）','','加密配置 (*.dpapi)')
            if not path:return
            from .storage import dpapi
            restored=json.loads(dpapi(Path(path).read_bytes(),True))
            if restored.get('schema')!=1 or not isinstance(restored.get('channels'),list):raise ValueError('配置格式不正确。')
            for c in restored['channels']:validate_channel(c)
            if W.QMessageBox.question(self,'恢复配置','用备份替换当前信道配置？当前配置会先备份到数据目录。')!=W.QMessageBox.StandardButton.Yes:return
            self.store.backup(self.store.root/('before-restore-'+str(int(time.time()))+'.dpapi'))
            # Firewall state reflects the machine, not the backup.
            restored['firewall_guards']=self.store.data.get('firewall_guards',{})
            self.store.data=restored;self.store.save();self.refresh_channels()
        self.safe(action)

    def restart_admin(self):
        if is_admin():W.QMessageBox.information(self,'管理员模式','当前已经是管理员模式。');return
        if self.busy:return
        if self.engines.active:
            if W.QMessageBox.question(self,'管理员重启','将停止当前受管信道和子进程，再请求 Windows 管理员权限。继续？')!=W.QMessageBox.StandardButton.Yes:return
        def action():
            self.engines.stop_all();self.store.save()
            args=[] if getattr(sys,'frozen',False) else [str(resource_root()/'main.py')]
            args+=['--data-dir',str(self.store.root),'--wait-parent',str(os.getpid())]
            elevate(args);self.close()
        self.safe(action)

    def open_readme(self):
        path=resource_root()/'docs'/'使用说明.txt'
        if path.exists():os.startfile(str(path))

    def closeEvent(self,event):
        if self.busy:
            W.QMessageBox.information(self,'操作进行中','请等待当前操作完成，再退出。');event.ignore();return
        count=sum(1 for runtime in self.engines.active.values() for process in runtime.get('apps',[])+runtime.get('browsers',[]) if process.poll() is None)
        if count and W.QMessageBox.question(self,'关闭受管应用',f'退出会关闭由本工具启动的 {count} 个应用及受管浏览器。请先保存其中的工作。继续退出？')!=W.QMessageBox.StandardButton.Yes:
            event.ignore();return
        self.timer.stop();self.monitor_timer.stop();self.process_routing.close();self.openclaw.close();self.engines.stop_all();self.job.close();self.store.save();event.accept()
