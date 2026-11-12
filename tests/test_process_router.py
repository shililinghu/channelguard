import ctypes
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from channelguard.process_router import make_plan,folder_pattern,Flow,NativeRouter
from channelguard.app_catalog import assign_many
from channelguard.storage import new_channel
from channelguard.config import channel_config

class Process:
    def __init__(self,alive=True):self.alive=alive
    def poll(self):return None if self.alive else 1

class ProcessRoutingTests(unittest.TestCase):
    def test_stopped_channel_becomes_block_and_never_uses_another_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);exe=root/'app.exe';exe.write_bytes(b'test')
            c=new_channel();c['apps']=[{'path':str(exe)}]
            other=new_channel()
            runtime={'process':Process(),'port':1234,'username':'u','password':'secret'}
            plan=make_plan([c,other],{other['id']:runtime},root)
            self.assertTrue(plan['rules'][0]['blocked'])
            self.assertEqual(plan['rules'][0]['channel_id'],c['id'])
            self.assertEqual(plan['proxies'][0]['channel_id'],other['id'])

    def test_exact_exe_precedes_directory_and_duplicate_channels_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);apps=root/'apps';apps.mkdir();exe=apps/'app.exe';exe.write_bytes(b'test')
            c=new_channel();c['apps']=[{'path':str(exe),'routing_roots':[str(apps)]}]
            plan=make_plan([c],{},root)
            self.assertEqual(plan['rules'][0]['pattern'],str(exe.resolve()))
            self.assertEqual(plan['rules'][1]['pattern'],str(apps.resolve())+'\\*')
            other=new_channel();other['apps']=[{'path':str(exe)}]
            with self.assertRaises(ValueError):make_plan([c,other],{},root)

    def test_disk_root_and_owned_engine_cannot_be_captured(self):
        with self.assertRaises(ValueError):folder_pattern(Path.cwd().anchor)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);exe=root/'engines/identity/mihomo.exe';exe.parent.mkdir(parents=True);exe.write_bytes(b'test')
            c=new_channel();c['apps']=[{'path':str(exe)}]
            with self.assertRaises(ValueError):make_plan([c],{},root)
            c['apps']=[{'path':str(root/'missing.exe'),'routing_roots':[str(root)]}]
            with self.assertRaises(ValueError):make_plan([c],{},root)

    def test_replaced_launcher_keeps_game_directory_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);games=root/'games';games.mkdir()
            c=new_channel();c['apps']=[{'path':str(games/'missing.exe'),'routing_roots':[str(games)]}]
            plan=make_plan([c],{},root)
            self.assertEqual(len(plan['rules']),1)
            self.assertTrue(plan['rules'][0]['blocked'])

    def test_native_udp_is_explicit_and_http_channel_cannot_silently_downgrade(self):
        c=new_channel();default=channel_config(c,1,2,'u','p','s')
        self.assertIn('NETWORK,UDP,REJECT',default['rules'])
        c['native_udp']=True;enabled=channel_config(c,1,2,'u','p','s')
        self.assertTrue(enabled['proxies'][0]['udp'])
        self.assertNotIn('NETWORK,UDP,REJECT',enabled['rules'])
        c['interface']='WLAN 2'
        bound=channel_config(c,1,2,'u','p','s')
        self.assertEqual(bound['bind-address'],'[::1]')
        self.assertEqual(bound['interface-name'],'WLAN 2')
        self.assertEqual(bound['proxies'][0]['interface-name'],'WLAN 2')
        c['interface']=''
        c['node']={'type':'http','server':'127.0.0.1','port':1234}
        with self.assertRaises(ValueError):channel_config(c,1,2,'u','p','s')

    def test_flow_layout_matches_x64_native_header(self):
        self.assertEqual(ctypes.sizeof(Flow),168)
        self.assertEqual(Flow.sent.offset,24)
        self.assertEqual(Flow.host.offset,100)

    def test_adding_rule_does_not_reset_existing_udp_proxy(self):
        router=NativeRouter.__new__(NativeRouter)
        router.configs={};router.proxy_settings={};router.rules={}
        router.dll=Mock();router.dll.ProxyBridge_AddProxyConfig.return_value=1
        router.dll.ProxyBridge_AddRule.return_value=1
        proxy=dict(channel_id='A',port=1234,username='u',password='p')
        router.apply(dict(proxies=[proxy],rules=[]))
        rule=dict(pattern='C:\\Games\\a.exe',channel_id='A',blocked=False)
        router.apply(dict(proxies=[proxy],rules=[rule]))
        router.dll.ProxyBridge_EditProxyConfig.assert_not_called()
        router.apply(dict(proxies=[dict(proxy,port=1235)],rules=[rule]))
        router.dll.ProxyBridge_EditProxyConfig.assert_called_once()

    def test_bulk_assignment_validates_all_before_reassigning(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);exe=root/'app.exe';exe.write_bytes(b'test')
            original=new_channel();original['apps']=[dict(path=str(exe))];target=new_channel()
            store=Mock(data=dict(channels=[original,target]));store.channel.return_value=target
            with self.assertRaises(ValueError):assign_many(store,target['id'],[dict(path=str(exe)),dict(path=str(root/'missing.exe'))])
            self.assertEqual(len(original['apps']),1);self.assertFalse(target['apps']);store.save.assert_not_called()
