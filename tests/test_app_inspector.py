import ctypes as C
import json
import socket
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from channelguard.app_inspector import (select_processes,core_owner,RateHistory,AppInspector,
    reference_probe,route_evidence,bounded_body)
from channelguard.tcp_stats import TcpRow,Tcp6Row,Data,PathStats,TcpStats,make_row
from channelguard.process_router import NativeRouter


class AttributionTests(unittest.TestCase):
    def test_full_path_and_verified_ancestry(self):
        rows={1:dict(exe=r'C:\A\app.exe',created=10,ppid=0),
              2:dict(exe=r'C:\B\app.exe',created=11,ppid=0),
              3:dict(exe=r'C:\A\child.exe',created=12,ppid=1),
              4:dict(exe=r'C:\A\old.exe',created=9,ppid=1)}
        self.assertEqual(set(select_processes(rows,r'c:\a\APP.exe',False)),{1})
        self.assertEqual(set(select_processes(rows,r'C:\A\app.exe',True)),{1,3})

    def test_core_source_join_requires_known_proxy_endpoint(self):
        sockets=[dict(protocol='TCP',local=['127.0.0.1',50001],remote=['127.0.0.1',18001],pid=7)]
        metadata=dict(network='tcp',sourceIP='127.0.0.1',sourcePort='50001')
        self.assertIsNotNone(core_owner(metadata,{},sockets,'a',{'a':18001})[0])
        self.assertIsNone(core_owner(metadata,{},sockets,'b',{'b':18002})[0])
        self.assertIsNone(core_owner(metadata,{},sockets,'a',{'a':18001},True)[0])
        self.assertIsNone(core_owner(dict(metadata,sourcePort='50002'),{},sockets,'a',{'a':18001})[0])

    def test_same_destination_or_process_basename_is_never_attribution(self):
        processes={1:dict(exe=r'C:\real\app.exe')}
        self.assertIsNone(core_owner(dict(process='app.exe',destinationIP='192.0.2.55'),processes,[],'a',{})[0])
        self.assertIsNone(core_owner(dict(processPath=r'C:\other\app.exe'),processes,[],'a',{})[0])
        self.assertEqual(core_owner(dict(processPath=r'C:\real\app.exe'),processes,[],'a',{})[0],'完整程序路径')

    def test_absent_process_and_stale_native_snapshot_are_unknown(self):
        routing=Mock();routing.status.return_value=dict(state='running',at=time.time()-30,flows=[dict(pid=1,channel_id='a',sent=100,received=200)])
        engine=SimpleNamespace(active={},router=None)
        inspector=AppInspector(Path(__file__).with_suffix('.exe'),engine,routing,lambda:[dict(id='a',name='A',apps=[])])
        with patch('channelguard.app_inspector.psutil.process_iter',return_value=[]),patch('channelguard.app_inspector.psutil.net_connections',return_value=[]):
            report=inspector.capture()
        self.assertFalse(report['processes']);self.assertFalse(report['observed_channels'])
        self.assertIsNone(report['rates']['系统分流']['down'])
        self.assertTrue(report['warnings'])

    def test_snapshot_does_not_export_auth_tokens_or_raw_api_metadata(self):
        now=time.time();pid=123
        process=Mock();process.pid=pid;process.info=dict(pid=pid,ppid=0,exe=r'C:\A\app.exe',name='app.exe',create_time=now-10)
        live=Mock();live.exe.return_value=r'C:\A\app.exe';live.create_time.return_value=now-10
        engine=SimpleNamespace(active={},router=None);routing=Mock()
        routing.status.return_value=dict(state='running',at=now,token='secret-sentinel',flows=[dict(pid=pid,id=1,channel_id='a',protocol='TCP',destination='example.com',destination_ip='192.0.2.55',port=443,sent=123,received=456,age_ms=1000)])
        inspector=AppInspector(r'C:\A\app.exe',engine,routing,lambda:[dict(id='a',name='A',apps=[])])
        with patch('channelguard.app_inspector.psutil.process_iter',return_value=[process]),patch('channelguard.app_inspector.psutil.net_connections',return_value=[]),patch('channelguard.app_inspector.psutil.Process',return_value=live):report=inspector.capture()
        self.assertEqual(report['observed_channels'],[dict(id='a',name='A')])
        self.assertNotIn('secret-sentinel',json.dumps(report))

    def test_native_raw_ip_and_age_are_preserved_without_dns_guess(self):
        router=NativeRouter.__new__(NativeRouter);router.configs={'a':1};router.rules={'app.exe':2}
        router.dll=Mock()
        def copy(values,_):
            flow=values[0];flow.id=5;flow.pid=7;flow.proxy_id=1;flow.rule_id=2;flow.age_ms=1234
            flow.port=443;flow.host=b'cached-name.example';flow.name=b'app.exe';flow.sent=100;flow.received=200
            for index,value in enumerate(socket.inet_pton(socket.AF_INET,'192.0.2.12')):flow.destination[index]=value
            return 1
        router.dll.ProxyBridge_GetFlows.side_effect=copy
        flow=router.flows()[0]
        self.assertEqual(flow['destination_ip'],'192.0.2.12');self.assertEqual(flow['destination'],'cached-name.example')
        self.assertEqual(flow['age_ms'],1234);self.assertEqual(flow['channel_id'],'a')


class CounterTests(unittest.TestCase):
    def test_real_elapsed_deltas_and_sources_never_summed(self):
        history=RateHistory()
        first={'系统分流':{'flow':dict(at=10,up=100,down=200)},'信道内核':{'same':dict(at=10,up=100,down=200)}}
        self.assertIsNone(history.update(first,10)['系统分流']['up'])
        second={'系统分流':{'flow':dict(at=12,up=1100,down=4200)},'信道内核':{'same':dict(at=12,up=1100,down=4200)}}
        result=history.update(second,12)
        self.assertEqual(result['系统分流']['up'],500);self.assertEqual(result['信道内核']['down'],2000)
        self.assertNotIn('total',result)

    def test_first_new_closed_reset_stale_and_gaps_are_not_zero_measurements(self):
        history=RateHistory()
        self.assertIsNone(history.update({'系统分流':{'f':dict(at=1,up=100,down=200)}},1)['系统分流']['down'])
        self.assertIsNone(history.update({'系统分流':{'f':dict(at=1,up=100,down=200)}},2)['系统分流']['down'])
        reset=history.update({'系统分流':{'f':dict(at=3,up=10,down=20)}},3)['系统分流']
        self.assertEqual(reset['resets'],1);self.assertIsNone(reset['down'])
        gone=history.update({},4)['系统分流'];self.assertIsNone(gone['up']);self.assertEqual(gone['disappeared_flows'],1)
        self.assertIsNone(history.update({'系统分流':{'f':dict(at=5,up=20,down=40)}},5)['系统分流']['down'])

    def test_comparable_idle_flow_can_be_zero_but_not_outage(self):
        history=RateHistory();history.update({'Windows TCP':{'f':dict(at=1,up=5,down=5)}},1)
        values=history.update({'Windows TCP':{'f':dict(at=2,up=5,down=5)}},2)['Windows TCP']
        self.assertEqual(values['down'],0);self.assertEqual(values['quiet_samples'],1)
        self.assertNotIn('stable',values);self.assertNotIn('packet_loss',values)

    def test_observed_byte_totals_survive_history_retention_limit(self):
        history=RateHistory()
        for index in range(1805):values=history.update({'系统分流':{'f':dict(at=index,up=index*10,down=index*20)}},index)['系统分流']
        self.assertEqual(values['observed_download'],1804*20)


class TcpTests(unittest.TestCase):
    def test_windows_abi_and_network_byte_order(self):
        self.assertEqual([C.sizeof(x) for x in (TcpRow,Tcp6Row,Data,PathStats)],[20,52,96,160])
        conn=dict(local=['127.0.0.1',50001],remote=['192.0.2.10',443],state='ESTABLISHED')
        row=make_row(conn)
        self.assertEqual(C.string_at(C.byref(row,4),4),b'\x7f\0\0\1');self.assertEqual(row.remote_port,socket.htons(443))
        conn.update(local=['::1',50001],remote=['2001:db8::1',443]);row=make_row(conn)
        self.assertEqual(bytes(row.remote),socket.inet_pton(socket.AF_INET6,'2001:db8::1'))

    def test_disabled_estats_is_unavailable_even_if_return_buffer_has_numbers(self):
        tcp=TcpStats();fake=Mock()
        fake.GetPerTcpConnectionEStats.return_value=0;tcp.api=fake
        result=tcp.read(dict(protocol='TCP',local=['127.0.0.1',1],remote=['127.0.0.1',2],state='ESTABLISHED'))
        self.assertNotIn('data',result);self.assertNotIn('path',result)
        fake.SetPerTcpConnectionEStats.assert_not_called()


class FakeResponse:
    def __init__(self,data,status=200):self.data=data;self.status_code=status
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def raise_for_status(self):
        if self.status_code>=400:raise RuntimeError('do not export credentials')
    def iter_content(self,size):
        for offset in range(0,len(self.data),size):yield self.data[offset:offset+size]


class ProbeTests(unittest.TestCase):
    def test_probe_is_independent_with_explicit_proxy_and_two_services(self):
        engine=Mock();engine.active={'a':dict(process=Mock(poll=Mock(return_value=None)))};engine.proxy.return_value='http://u:secret@127.0.0.1:1'
        http=Mock();http.__enter__=Mock(return_value=http);http.__exit__=Mock()
        http.get.side_effect=lambda url,**_:FakeResponse(b'{"ip":"192.0.2.1"}' if 'ipify' in url else b'ip=192.0.2.2\n')
        http.proxies={}
        with patch('channelguard.app_inspector.session',return_value=http):report=reference_probe(engine,'a',False,threading.Event())
        self.assertEqual(report['summary']['successes'],6);self.assertEqual(len(report['summary']['exits']),2)
        self.assertIn('不是所选 EXE',report['scope']);self.assertNotIn('secret',json.dumps(report))
        self.assertEqual(http.proxies['https'],engine.proxy.return_value)
        self.assertFalse(http.post.called)

    def test_failures_do_not_retry_direct_or_produce_fake_speed(self):
        engine=Mock();engine.active={'a':dict(process=Mock(poll=Mock(return_value=None)))};engine.proxy.return_value='http://secret@localhost'
        http=Mock();http.__enter__=Mock(return_value=http);http.__exit__=Mock();http.get.side_effect=RuntimeError('secret-auth-string');http.proxies={}
        with patch('channelguard.app_inspector.session',return_value=http):report=reference_probe(engine,'a',False,threading.Event())
        self.assertEqual(report['summary']['failure_ratio'],1);self.assertIsNone(report['summary']['p50_ms'])
        self.assertNotIn('secret',json.dumps(report));self.assertEqual(http.get.call_count,6)

    def test_response_limit_and_cancellation(self):
        with self.assertRaises(ValueError):bounded_body(FakeResponse(b'x'*100),10,threading.Event(),time.monotonic()+1)
        cancel=threading.Event();cancel.set()
        with self.assertRaises(InterruptedError):bounded_body(FakeResponse(b'x'),10,cancel,time.monotonic()+1)

    def test_route_is_only_supporting_evidence_and_ip_validated(self):
        report=dict(flows=[dict(source='Windows 连接表',destination='192.0.2.1:443'),dict(source='Windows 连接表',destination="evil';exit:1")])
        with patch('channelguard.app_inspector.powershell',return_value='{"routes":[]}') as command:result=route_evidence(report)
        self.assertNotIn('evil',command.call_args.args[0]);self.assertIn('不能证明',result['note'])


if __name__=='__main__':unittest.main()
