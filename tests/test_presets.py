import copy
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from channelguard.storage import Store
from channelguard.presets import candidates,reconcile,probe_proxy,require_ready,require_interface,readiness_label,inspect_local_proxies
from channelguard.config import validate_channel

def inventory():
    return {
        'environment':{'timezone':'China Standard Time','culture':'zh-CN'},
        'adapters':[
            dict(Name='WLAN 2',InterfaceDescription='Intel Wi-Fi',Status='Up',Guid='wifi-guid',Hardware=True),
            dict(Name='有线',InterfaceDescription='Realtek PCIe',Status='Disconnected',Guid='ethernet-guid',Hardware=True),
            dict(Name='VPN',InterfaceDescription='TAP-Windows Adapter',Status='Up',Guid='vpn-guid',Hardware=False),
            dict(Name='WSL',InterfaceDescription='Hyper-V Virtual Ethernet Adapter',Status='Up',Guid='wsl',Hardware=False)],
        'configs':[
            dict(InterfaceAlias='WLAN 2',IPv4=['203.0.113.10'],Gateway=['203.0.113.1']),
            dict(InterfaceAlias='VPN',IPv4=['203.0.113.12'],Gateway=[])],
        'routes':[dict(InterfaceAlias='WLAN 2',DestinationPrefix='0.0.0.0/0'),dict(InterfaceAlias='VPN',DestinationPrefix='0.0.0.0/1')],
        'proxy_candidates':[dict(host='127.0.0.1',port=1080,process='xray.exe',probe=dict(state='ready',protocol='socks5',detail='Test handshake'))],
    }

class PresetContracts(unittest.TestCase):
    def test_manual_and_previously_ready_adapters_must_still_be_connected(self):
        require_interface({'interface':'WLAN 2'},inventory())
        require_interface({'interface':''},inventory())
        for name in ('有线','removed VPN'):
            with self.assertRaises(ValueError):require_interface({'interface':name},inventory())

    def test_real_exits_preset_with_distinct_honest_states(self):
        channels=candidates(inventory())
        self.assertEqual(len(channels),6) # system, WiFi, cable, VPN, SOCKS, future VPS
        self.assertFalse(any(c['interface']=='WSL' for c in channels))
        self.assertTrue(all(c['timezone']=='Asia/Shanghai' and c['locale']=='zh-CN' and c['geo']=='deny' for c in channels))
        for c in channels:validate_channel(c)
        cable=next(c for c in channels if c['interface']=='有线')
        with self.assertRaises(ValueError):require_ready(cable)
        future=next(c for c in channels if c.get('setup_required'))
        with self.assertRaises(ValueError):require_ready(future)
        proxy=next(c for c in channels if c.get('node'))
        self.assertEqual(proxy['node']['type'],'socks5');require_ready(proxy)

    def test_migration_preserves_identity_apps_and_custom_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Store(Path(folder));old=store.data['channels'][0];identity=old['id']
            old['apps']=[{'path':'C:\\Tools\\myapp.exe'}];old['timezone']='Asia/Tokyo'
            reconcile(store,inventory());ids=[c['id'] for c in store.data['channels']]
            reconcile(store,inventory());self.assertEqual(ids,[c['id'] for c in store.data['channels']])
            current=store.channel(identity)
            self.assertEqual(current['name'],'系统默认信道');self.assertEqual(current['timezone'],'Asia/Tokyo')
            self.assertEqual(current['apps'],[{'path':'C:\\Tools\\myapp.exe'}])
            self.assertEqual(len(Store(Path(folder)).data['channels']),6)

    def test_disappeared_exits_retained_and_marked_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Store(Path(folder));reconcile(store,inventory())
            wifi=next(c for c in store.data['channels'] if c['interface']=='WLAN 2');identity=wifi['id']
            changed=inventory();changed['adapters']=[]
            reconcile(store,changed)
            self.assertEqual(store.channel(identity)['discovery']['readiness'],'offline')

    def test_auto_environment_tracks_system_without_overwriting_a_changed_value(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Store(Path(folder));reconcile(store,inventory())
            wifi=next(c for c in store.data['channels'] if c['interface']=='WLAN 2')
            wifi['timezone']='Europe/London'
            changed=inventory();changed['environment']={'timezone':'Tokyo Standard Time','culture':'ja-JP'}
            reconcile(store,changed)
            self.assertEqual(wifi['timezone'],'Europe/London');self.assertEqual(wifi['locale'],'ja-JP')
            vpn=next(c for c in store.data['channels'] if c['interface']=='VPN')
            self.assertEqual(vpn['timezone'],'Asia/Tokyo')

    def test_manual_edits_active_channels_and_deleted_presets_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Store(Path(folder));reconcile(store,inventory())
            wifi=next(c for c in store.data['channels'] if c['interface']=='WLAN 2')
            wifi['discovery']['managed']=False;wifi['name']='我自己的名称'
            proxy=next(c for c in store.data['channels'] if c.get('node'))
            proxy['node']['username']='user';proxy['node']['password']='test-secret'
            before=copy.deepcopy(proxy)
            cable=next(c for c in store.data['channels'] if c['interface']=='有线')
            store.data['discovery_suppressed']=[cable['discovery']['key']];store.data['channels'].remove(cable)
            changed=inventory();changed['proxy_candidates'][0]['probe']={'state':'offline','detail':'Not listening'}
            reconcile(store,changed,{proxy['id']})
            self.assertEqual(wifi['name'],'我自己的名称');self.assertEqual(proxy,before)
            self.assertFalse(any(c['interface']=='有线' for c in store.data['channels']))

    def test_transient_probe_failure_does_not_change_known_socks_to_http(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Store(Path(folder));reconcile(store,inventory())
            proxy=next(c for c in store.data['channels'] if c.get('node'))
            changed=inventory();changed['proxy_candidates'][0]['probe']={'state':'offline','detail':'Timeout'}
            reconcile(store,changed)
            self.assertEqual(proxy['node']['type'],'socks5')
            self.assertNotEqual(readiness_label(proxy),'可接入 · 待实测')

    def test_offline_vps_never_turns_into_direct_channel(self):
        future=next(c for c in candidates(inventory()) if c.get('setup_required'))
        self.assertIsNone(future['node'])
        with self.assertRaises(ValueError):require_ready(future)

    def test_socks_probe_only_performs_local_handshake(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen();received=[]
            def respond():
                connection,_=server.accept()
                with connection:
                    received.append(connection.recv(100));connection.sendall(b'\x05\x00')
            thread=threading.Thread(target=respond);thread.start()
            result=probe_proxy('127.0.0.1',server.getsockname()[1]);thread.join(timeout=2)
            self.assertEqual(result['state'],'ready');self.assertEqual(result['protocol'],'socks5')
            self.assertEqual(received,[b'\x05\x02\x00\x02']) # no SOCKS CONNECT request
        self.assertEqual(probe_proxy('192.0.2.10',443)['state'],'unsupported')

    def test_owned_engines_and_openvpn_management_ports_not_added_as_proxies(self):
        result=inspect_local_proxies({'listeners':[dict(host='127.0.0.1',port=10001,process='mihomo.exe',owned=True),dict(host='127.0.0.1',port=10002,process='openvpn.exe')]})
        self.assertEqual(result['proxy_candidates'],[])

if __name__=='__main__':unittest.main()
