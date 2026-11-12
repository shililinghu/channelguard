from pathlib import Path
import copy
import tempfile
import unittest
from unittest.mock import patch
from channelguard.storage import Store,new_channel
from channelguard.initialization import initialize
from test_monitor import network


class Process:
    def poll(self):return None


class Engine:
    def __init__(self):self.active={}
    def start(self,c):self.active[c['id']]={'browsers':[],'process':Process(),'channel':copy.deepcopy(c)}
    def rebind(self,c):self.active[c['id']]['channel']=copy.deepcopy(c)
    def proxy(self,identity):return 'http://127.0.0.1:1'
    def write_browser_manifest(self,*args):pass


class InitializationTests(unittest.TestCase):
    def test_reinitialization_preserves_identity_apps_and_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory));c=new_channel('My Wi-Fi');c.update(interface='WiFi',discovery={'kind':'wifi','key':'adapter:one'})
            c['apps']=[{'path':'C:/custom/app.exe'}];store.data['channels']=[c];store.save()
            engine=Engine();options=dict(direct='WiFi',vpn='newVPN',doh='https://223.5.5.5/dns-query',monitor=True)
            def observed(proxy):return {'reachable':True,'ips':['198.18.0.1'],'country':'JP','timezone':'Asia/Tokyo'}
            with patch('channelguard.initialization.observe',observed):
                initialize(store,engine,network(),options)
                identities=[c['id'] for c in store.data['channels']]
                initialize(store,engine,network(),options)
            self.assertEqual(identities,[c['id'] for c in store.data['channels']])
            self.assertEqual(store.channel(c['id'])['apps'],[{'path':'C:/custom/app.exe'}])
            self.assertEqual(store.channel(c['id'])['timezone'],'Asia/Tokyo')
            self.assertTrue(store.data['monitor']['enabled'])
            self.assertTrue(list(store.root.glob('before-initialization-*.dpapi')))

    def test_invalid_vpn_selection_changes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory));before=copy.deepcopy(store.data);engine=Engine()
            with self.assertRaises(ValueError):initialize(store,engine,network(False),dict(direct='WiFi',vpn='missing',doh='https://1.1.1.1/dns-query'))
            self.assertEqual(store.data,before);self.assertFalse(engine.active)
