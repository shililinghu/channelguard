"""Live EXE network evidence dialog. Does not assign apps or change routing."""
from __future__ import annotations
import json
from pathlib import Path
import threading
from PySide6 import QtCore,QtWidgets as W
from .app_inspector import AppInspector,reference_probe,route_evidence
from .system import running_apps,is_admin
from .ui import label,button,table,fill,Task


def rate(value):
    if value is None:return '无法测量 / 等待可比较样本'
    return f'{value/1024:.1f} KiB/s · {value*8/1_000_000:.3f} Mbps'


def number(value,unit=' ms'):
    return f'{value:.1f}{unit}' if value is not None else '无法测量'


class AppInspectorDialog(W.QDialog):
    def __init__(self,parent,path=''):
        super().__init__(parent)
        self.owner=parent;self.inspector=None;self.snapshot=None;self.reference=None;self.routes=None
        self.tasks=[];self.sampling=False;self.probing=False;self.closing=False;self.cancel=threading.Event()
        self.setWindowTitle('EXE 网络实测 · 信道与性能');self.resize(1160,820)
        layout=W.QVBoxLayout(self)
        layout.addWidget(label('按完整 EXE 路径查询；不修改应用分配、代理或网络路由。请让目标程序实际联网，持续观察至少 30–60 秒。','muted',True))
        row=W.QHBoxLayout();self.path=W.QLineEdit(path);self.path.setPlaceholderText('选择目标 EXE（运行中的程序才能提供实时证据）');row.addWidget(self.path,1)
        self.browse_button=button('选择 EXE',self.browse);self.running_button=button('运行中程序',self.pick_running)
        row.addWidget(self.browse_button);row.addWidget(self.running_button);layout.addLayout(row)
        row=W.QHBoxLayout();self.children=W.QCheckBox('包含可验证的子进程');self.children.setChecked(True);row.addWidget(self.children)
        self.enable_tcp=W.QCheckBox('补充 Windows TCP 统计（需管理员）');self.enable_tcp.setEnabled(is_admin())
        self.enable_tcp.setToolTip('为目标连接启用字节、RTT、重传统计；不修改路由。标准用户可查看已有统计及分流计数；需要时使用设置中的管理员重启。')
        row.addWidget(self.enable_tcp);row.addStretch();self.start=button('开始观察',self.begin,'primary');row.addWidget(self.start)
        self.pause=button('暂停',self.stop);self.pause.setEnabled(False);row.addWidget(self.pause);layout.addLayout(row)
        self.note=label('尚未采样。没有证据时显示未知，不将规则分配视为实际联网信道。','muted',True);layout.addWidget(self.note)
        self.tabs=W.QTabWidget();layout.addWidget(self.tabs,1)
        overview=W.QWidget();v=W.QVBoxLayout(overview)
        self.conclusion=label('等待采样','cardtitle',True);v.addWidget(self.conclusion)
        self.coverage=label('','small',True);v.addWidget(self.coverage)
        self.speed=table(['计数来源（分别展示，不相加）','实时上传','实时下载','近 60 秒下载 P50 / P95','近 60 秒上 / 下峰值','覆盖 / 样本'])
        v.addWidget(self.speed,2)
        v.addWidget(label('速率只统计两次快照均可见的同一流。首个样本、已结束连接、权限不足均可能缺数；0 表示观察到零增量，不表示断网。P50/P95 是吞吐分布，不是延迟。','small',True))
        self.processes=table(['PID','进程创建时间','完整程序路径']);v.addWidget(self.processes,1)
        self.tabs.addTab(overview,'实际吞吐与范围')
        flow_page=W.QWidget();v=W.QVBoxLayout(flow_page)
        self.flows=table(['证据来源','PID','观察到的信道 / 路径','协议','目的地','证据强度','依据与限制']);v.addWidget(self.flows,3)
        self.flow_detail=W.QPlainTextEdit();self.flow_detail.setReadOnly(True);self.flow_detail.setPlaceholderText('选择一条连接，查看完整依据与限制。');v.addWidget(self.flow_detail,1)
        self.flows.itemSelectionChanged.connect(self.show_flow_detail);self.tabs.addTab(flow_page,'信道交叉验证')
        tcp_page=W.QWidget();v=W.QVBoxLayout(tcp_page)
        v.addWidget(label('RTT、波动和重传来自 Windows 对该 TCP 端点的统计。经过本地代理 / 中继时，不能代表业务服务器延迟。重传 / 超时为该连接的累计计数，不是本次窗口丢包率。','small',True))
        self.tcp=table(['PID / 远端','测量范围','平滑 RTT / 波动','RTT 最小 / 最大','累计重传段 / 超时','本次间隔重传 / 超时 / RTT','统计状态']);v.addWidget(self.tcp)
        self.tabs.addTab(tcp_page,'TCP 延迟与重传')
        route_page=W.QWidget();v=W.QVBoxLayout(route_page)
        v.addWidget(label('核对本地源网卡与系统候选路由。其他 VPN 驱动可以逐应用重定向；候选路由仅作辅助，不能证明真实信道或公网出口。','muted',True))
        self.route_button=button('核查当前远端的候选路由',self.check_routes);v.addWidget(self.route_button)
        self.route_text=W.QPlainTextEdit();self.route_text.setReadOnly(True);v.addWidget(self.route_text);self.tabs.addTab(route_page,'系统路由辅助')
        probe=W.QWidget();v=W.QVBoxLayout(probe)
        v.addWidget(label('独立参考探测：由诊断进程经指定信道请求 Cloudflare 和 ipify，每站最多 3 次。它验证的是这些请求，不是目标 EXE 的业务速度或出口。失败率不是丢包率；小样本不证明长期稳定。','muted',True))
        row=W.QHBoxLayout();self.channel=W.QComboBox();row.addWidget(self.channel,1)
        self.transfer=W.QCheckBox('额外下载 4 MiB / 上传 256 KiB 测试数据');row.addWidget(self.transfer);v.addLayout(row)
        row=W.QHBoxLayout();self.probe_button=button('运行信道参考探测',self.probe,'primary');row.addWidget(self.probe_button)
        self.cancel_button=button('停止探测',lambda:self.cancel.set());self.cancel_button.setEnabled(False);row.addWidget(self.cancel_button);row.addStretch();v.addLayout(row)
        self.probe_text=W.QPlainTextEdit();self.probe_text.setReadOnly(True);v.addWidget(self.probe_text);self.tabs.addTab(probe,'信道参考探测')
        self.evidence=W.QPlainTextEdit();self.evidence.setReadOnly(True);self.tabs.addTab(self.evidence,'依据与完整报告')
        row=W.QHBoxLayout();row.addWidget(label('报告含所选路径、PID、连接地址及探测 IP；不包含节点密码、认证令牌或应用内容。','small',True));row.addStretch()
        self.export_button=button('导出实测报告',self.export);row.addWidget(self.export_button);row.addWidget(button('关闭',self.request_close));layout.addLayout(row)
        self.timer=QtCore.QTimer(self);self.timer.setInterval(2000);self.timer.timeout.connect(self.sample)
        self.refresh_channels()
        if path:QtCore.QTimer.singleShot(0,self.begin)

    def background(self,fn,complete,on_error=None):
        task=Task(fn);self.tasks.append(task)
        def finish(value,error=False):
            try:
                if error:
                    if on_error:on_error(value)
                    else:self.note.setText('未能取得证据：'+str(value))
                elif not self.closing:complete(value)
            except Exception as exc:
                self.note.setText('结果未能显示：'+type(exc).__name__)
            finally:
                self.tasks.remove(task)
                if self.closing and not self.tasks:super(AppInspectorDialog,self).reject()
        task.signals.done.connect(lambda value:finish(value));task.signals.error.connect(lambda value:finish(value,True))
        QtCore.QThreadPool.globalInstance().start(task)

    def browse(self):
        if self.probing:return
        path,_=W.QFileDialog.getOpenFileName(self,'选择要观察的 EXE',self.path.text(),'应用 (*.exe)')
        if path:self.set_target(path)

    def set_target(self,path):
        self.stop();self.path.setText(path);self.inspector=None;self.snapshot=None;self.reference=None;self.routes=None
        self.conclusion.setText('目标已选择，等待开始观察。');self.note.setText('尚未取得此 EXE 的实时证据。')
        for grid in (self.speed,self.processes,self.flows,self.tcp):grid.setRowCount(0)
        for text in (self.probe_text,self.route_text,self.evidence):text.clear()
        self.coverage.clear();self.flow_detail.clear()

    def pick_running(self):
        if self.sampling or self.probing:return
        self.stop()
        def complete(rows):
            items=[row['name']+'  —  '+row['path'] for row in rows]
            if not items:W.QMessageBox.information(self,'没有可读进程','没有可读取完整路径的运行程序。');return
            chosen,ok=W.QInputDialog.getItem(self,'查询运行中的程序','只观察，不分配信道',items,0,False)
            if ok:self.set_target(rows[items.index(chosen)]['path']);self.begin()
        self.background(running_apps,complete)

    def begin(self):
        if self.closing or self.probing:return
        if self.sampling:QtCore.QTimer.singleShot(200,self.begin);return
        path=Path(self.path.text().strip().strip('"'))
        if not path.is_file() or path.suffix.casefold()!='.exe':
            W.QMessageBox.information(self,'选择 EXE','请先选择一个实际存在的 EXE 程序。');return
        self.inspector=AppInspector(path,self.owner.engines,self.owner.process_routing,lambda:self.owner.store.data['channels'],self.children.isChecked(),self.enable_tcp.isChecked())
        self.snapshot=None;self.reference=None;self.routes=None;self.probe_text.clear();self.route_text.clear()
        self.path.setReadOnly(True);self.children.setEnabled(False);self.enable_tcp.setEnabled(False)
        self.start.setEnabled(False);self.pause.setEnabled(True);self.timer.start();self.sample()

    def stop(self):
        self.timer.stop();self.start.setEnabled(True);self.pause.setEnabled(False)
        self.path.setReadOnly(False);self.children.setEnabled(True);self.enable_tcp.setEnabled(is_admin())
        if self.snapshot:self.note.setText('观察已暂停；显示 '+self.snapshot['time']+' 的历史快照，不能代表当前网络。')

    def sample(self):
        if self.sampling or not self.inspector:return
        self.sampling=True;inspector=self.inspector
        def done(report):
            self.sampling=False
            if inspector is self.inspector:
                self.snapshot=report;self.render()
                if not self.timer.isActive():self.stop()
        def error(message):
            self.sampling=False;self.note.setText('本次采样失败，旧结果不能代表当前网络：'+str(message))
        self.background(inspector.capture,done,error)

    def render(self):
        report=self.snapshot
        observed='、'.join(c['name'] for c in report['observed_channels']) or '暂无可验证的信道转发记录'
        configured='、'.join(report['configured_channels']) or '未分配'
        counts={source:sum(f['source']==source for f in report['flows']) for source in ('系统分流','Windows 连接表','信道内核')}
        self.conclusion.setText('已观察信道：'+observed+'\n配置分配（仅配置）：'+configured+
            f"\n证据：系统分流 {counts['系统分流']} / Windows 连接 {counts['Windows 连接表']} / 可归属内核连接 {counts['信道内核']}；仅目的地址关联 {report['core_destination_correlations']}（不能唯一归属）")
        self.coverage.setText(('没有可验证的运行实例；目标可能未运行或权限不足。\n' if not report['processes'] else '')+
            '\n'.join(report['warnings'][:3])+f"\n本次无法读取完整路径的系统进程 {report['unreadable_processes']} 个；未识别进程不计入 EXE 流量。")
        self.note.setText(f"{report['time']} · 已观察 {report['elapsed']:.1f} 秒 · 可验证进程 {len(report['processes'])} 个 · 可见证据 {len(report['flows'])} 条；结论仅覆盖这些连接，不能断言整个 EXE 只走此信道。")
        rows=[]
        for source,values in report['rates'].items():
            rows.append([source,rate(values['up']),rate(values['down']),rate(values['down_p50'])+' / '+rate(values['down_p95']),
                rate(values['up_peak'])+' / '+rate(values['down_peak']),
                f"可比较 {values['comparable_flows']} / 可见 {values['visible_flows']} 流；{values['samples']} 个样本\n新增 {values['new_flows']} / 消失 {values['disappeared_flows']} / 重置 {values['resets']}\n零增量样本 {values['quiet_samples']}（不等于断网）"])
        fill(self.speed,rows);self.speed.resizeRowsToContents()
        fill(self.processes,[[p['pid'],__import__('datetime').datetime.fromtimestamp(p['created']).astimezone().isoformat(timespec='seconds'),p['exe']] for p in report['processes']])
        fill(self.flows,[[f['source'],f['pid'] if f['pid'] is not None else '按路径',f['channel'],f['protocol'],f['destination'],f['evidence'],f['detail']] for f in report['flows']])
        self.show_flow_detail()
        tcp_rows=[]
        for row in report['tcp']:
            path=row.get('path');has_rtt=bool(path and path['CountRtt'])
            window=row.get('window') or {}
            tcp_rows.append([str(row['pid'])+' / '+row['destination'],row['scope'],
                (number(path['SmoothedRtt'])+' / '+number(path['RttVar'])) if has_rtt else '无法测量 / 尚无 RTT 样本',
                (number(path['MinRtt'])+' / '+number(path['MaxRtt'])) if has_rtt else '无法测量',
                (str(path['PktsRetrans'])+' / '+str(path['Timeouts'])) if path else '无法测量',
                (f"{window['seconds']:.1f} 秒：{window['retransmitted_segments']} / {window['retransmission_timeouts']}；RTT "+number(window['mean_rtt_ms'])) if window else '等待可比较样本',
                '；'.join([('字节可读' if row.get('data') else row.get('data_reason',row.get('reason','不可用'))),('路径可读' if path else row.get('path_reason','路径不可用'))])])
        fill(self.tcp,tcp_rows);self.tcp.resizeRowsToContents()
        self.refresh_channels()
        self.evidence.setPlainText(json.dumps(self.document(),ensure_ascii=False,indent=2))

    def show_flow_detail(self):
        row=self.flows.currentRow();flows=(self.snapshot or {}).get('flows',[])
        if 0<=row<len(flows):self.flow_detail.setPlainText(json.dumps(flows[row],ensure_ascii=False,indent=2))
        else:self.flow_detail.clear()

    def document(self):
        return dict(exe_observation=self.snapshot,independent_channel_probe=self.reference,os_candidate_routes=self.routes)

    def refresh_channels(self):
        current=self.channel.currentData();self.channel.clear()
        observed={c['id'] for c in (self.snapshot or {}).get('observed_channels',[])}
        for channel in self.owner.store.data['channels']:
            runtime=self.owner.engines.active.get(channel['id'])
            if runtime and runtime['process'].poll() is None:
                self.channel.addItem(channel['name']+(' · 已观察转发' if channel['id'] in observed else ' · 运行中，EXE 归属未证实'),channel['id'])
        index=self.channel.findData(current)
        if index>=0:self.channel.setCurrentIndex(index)

    def check_routes(self):
        if not self.snapshot:return
        self.route_button.setEnabled(False);snapshot=self.snapshot
        def done(result):
            self.routes=result;self.route_button.setEnabled(True);self.route_text.setPlainText(json.dumps(result,ensure_ascii=False,indent=2))
        def error(message):self.route_button.setEnabled(True);self.route_text.setPlainText('查询失败：'+str(message))
        self.background(lambda:route_evidence(snapshot),done,error)

    def probe(self):
        if self.probing:return
        identity=self.channel.currentData()
        if not identity:W.QMessageBox.information(self,'无运行信道','先启动一条信道，才可进行独立参考探测。');return
        self.probing=True;self.cancel.clear();self.probe_button.setEnabled(False);self.cancel_button.setEnabled(True)
        self.browse_button.setEnabled(False);self.running_button.setEnabled(False);self.path.setReadOnly(True)
        self.probe_text.setPlainText('正在执行独立信道请求。该结果不代表所选 EXE 的业务性能…')
        transfer=self.transfer.isChecked()
        def done(result):
            self.reference=result;self.probing=False;self.probe_button.setEnabled(True);self.cancel_button.setEnabled(False)
            self.browse_button.setEnabled(True);self.running_button.setEnabled(True);self.path.setReadOnly(self.timer.isActive())
            summary=result['summary'];lines=[result['scope'],
                f"HTTPS 请求：{summary['successes']} / {summary['attempts']} 次成功；请求失败率 "+(number(summary['failure_ratio']*100,' %') if summary['failure_ratio'] is not None else '未知'),
                '完整请求耗时 P50 / P95：'+number(summary['p50_ms'])+' / '+number(summary['p95_ms']),
                '诊断请求的公网出口：'+('、'.join(summary['exits']) or '无法确认')]
            for site,row in result['per_site'].items():lines.append(site+' 同站相邻请求耗时差均值：'+number(row['mean_adjacent_difference_ms']))
            for direction,row in result['transfer'].items():lines.append(('参考下载' if direction=='download' else '参考上传')+'：'+(rate(row['bytes_per_second']) if row['success'] else '未测得（'+row['error']+'）'))
            if result['cancelled']:lines.append('检测已停止，以上为部分样本。')
            lines+=['']+result['limitations'];self.probe_text.setPlainText('\n'.join(lines))
        def error(message):
            self.probing=False;self.probe_button.setEnabled(True);self.cancel_button.setEnabled(False);self.probe_text.setPlainText('未测得：'+str(message))
            self.browse_button.setEnabled(True);self.running_button.setEnabled(True);self.path.setReadOnly(self.timer.isActive())
        self.background(lambda:reference_probe(self.owner.engines,identity,transfer,self.cancel),done,error)

    def export(self):
        if not self.snapshot:return
        path,_=W.QFileDialog.getSaveFileName(self,'保存网络实测报告','EXE-network-observation.json','JSON (*.json)')
        if path:
            try:Path(path).write_text(json.dumps(self.document(),ensure_ascii=False,indent=2),encoding='utf-8')
            except OSError as exc:W.QMessageBox.warning(self,'保存失败',str(exc))

    def request_close(self):
        self.timer.stop();self.cancel.set()
        if self.tasks:self.closing=True;self.note.setText('正在结束当前采样 / 探测，请稍候…')
        else:super().reject()

    def reject(self):self.request_close()

    def closeEvent(self,event):
        if self.tasks:self.request_close();event.ignore()
        else:self.timer.stop();self.cancel.set();event.accept()
