import copy
import json
from pathlib import Path
import tempfile
import unittest
from channelguard.config import channel_config,parse_nodes,proxy_url_node,router_config,validate_channel
from channelguard.storage import Store,dpapi,new_channel
from channelguard.system import ChildJob,firewall_rule_name,ps_quote,split_windows_arguments

class ConfigContracts(unittest.TestCase):
    def test_proxy_has_no_direct_fallback_and_authenticates(self):
        c=new_channel();c['node']=proxy_url_node('socks5://name:secret@192.0.2.10:1080');c['interface']='WLAN 2'
        config=channel_config(c,20001,20002,'user','pass','secret')
        self.assertEqual(config['authentication'],['user:pass'])
        self.assertEqual(config['bind-address'],'127.0.0.1')
        self.assertFalse(config['allow-lan'])
        self.assertEqual(config['rules'][-1],'MATCH,CG-EXIT')
        self.assertNotIn('DIRECT',str(config['rules']))
        self.assertEqual(config['proxies'][0]['interface-name'],'WLAN 2')
        self.assertEqual(config['dns']['nameserver'],['https://1.1.1.1/dns-query#CG-EXIT'])

    def test_import_ignores_original_control_plane_and_rules(self):
        text='''external-controller: 0.0.0.0:9090
secret: malicious
rules: [MATCH,DIRECT]
proxy-providers: {remote: {url: 'http://127.0.0.1/private'}}
proxies:
  - {name: sample, type: socks5, server: 127.0.0.1, port: 1080}
'''
        nodes,errors=parse_nodes(text)
        self.assertEqual(len(nodes),1);self.assertFalse(errors)
        c=new_channel();c['node']=nodes[0]
        config=channel_config(c,20001,20002,'u','p','s')
        self.assertNotIn('proxy-providers',config)
        self.assertEqual(config['external-controller'],'127.0.0.1:20002')

    def test_insecure_tls_rejected(self):
        with self.assertRaises(ValueError):
            parse_nodes('proxies: [{name: bad, type: trojan, server: x.example, port: 443, password: p, skip-cert-verify: true}]')

    def test_url_credentials_not_truncated(self):
        node=proxy_url_node('http://a%40b:p%3Ass%23word@127.0.0.1:7897')
        self.assertEqual(node['username'],'a@b');self.assertEqual(node['password'],'p:ss#word')

    def test_rule_injection_rejected(self):
        c=new_channel();c['apps']=[{'path':'C:\\bad,MATCH,DIRECT.exe'}]
        with self.assertRaises(ValueError):validate_channel(c)

    def test_invalid_timezone_rejected(self):
        c=new_channel();c['timezone']='America/Not_A_Real_City'
        with self.assertRaises(Exception):validate_channel(c)

    def test_tun_matches_process_and_rejects_duplicates(self):
        c=new_channel();c['apps']=[{'path':'C:\\Tools\\app.exe'}]
        runtimes={c['id']:dict(port=20001,username='u',password='p')}
        config=router_config([c],runtimes,20002,'s')
        self.assertIn('PROCESS-PATH,C:\\Tools\\app.exe,CG-'+c['id'],config['rules'])
        self.assertTrue(config['tun']['strict-route'])
        clone=copy.deepcopy(c);clone['id']=new_channel()['id'];runtimes[clone['id']]=runtimes[c['id']]
        with self.assertRaises(ValueError):router_config([c,clone],runtimes,20002,'s')

    def test_firewall_names_are_path_scoped_and_quotes_literal(self):
        self.assertEqual(firewall_rule_name('C:\\Tools\\APP.exe'),firewall_rule_name('c:\\tools\\app.exe'))
        self.assertEqual(len(firewall_rule_name('C:\\Tools\\app.exe')),33)
        self.assertEqual(ps_quote("C:\\Sam's\\app.exe"),"'C:\\Sam''s\\app.exe'")

    def test_windows_arguments_preserve_paths_and_never_invoke_shell(self):
        self.assertEqual(split_windows_arguments('"C:\\A B\\script.js" --name "hello world"'),['C:\\A B\\script.js','--name','hello world'])
        self.assertEqual(split_windows_arguments('--value a&b'),['--value','a&b'])

    def test_global_tun_has_no_direct_fallback(self):
        c=new_channel();r={c['id']:dict(port=20001,username='u',password='p')}
        config=router_config([c],r,20002,'s',c['id'])
        self.assertEqual(config['rules'][-1],'MATCH,CG-'+c['id'])
        self.assertNotIn('MATCH,DIRECT',config['rules'])

    def test_tun_exempts_owned_cores_to_prevent_routing_loops(self):
        a,b=new_channel(),new_channel()
        r={a['id']:dict(port=20001,username='a',password='p'),b['id']:dict(port=20003,username='b',password='p')}
        config=router_config([a,b],r,20002,'s',b['id'],['C:\\ChannelGuard\\mihomo.exe'])
        self.assertEqual(config['rules'][0],'PROCESS-PATH,C:\\ChannelGuard\\mihomo.exe,DIRECT')
        self.assertEqual(config['dns']['nameserver'],['https://1.1.1.1/dns-query#CG-'+b['id']])

class StorageContracts(unittest.TestCase):
    def test_windows_user_encryption_roundtrip_and_tamper_rejection(self):
        secret=b'not-a-real-password-test-only'
        encrypted=dpapi(secret)
        self.assertNotIn(secret,encrypted);self.assertEqual(dpapi(encrypted,True),secret)
        broken=bytearray(encrypted);broken[len(broken)//2]^=0x55
        with self.assertRaises(OSError):dpapi(bytes(broken),True)

    def test_settings_and_backup_do_not_store_plaintext_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d));c=store.data['channels'][0]
            c['node']=proxy_url_node('socks5://test-user:unique-test-secret@127.0.0.1:1080');store.save()
            self.assertNotIn(b'unique-test-secret',store.path.read_bytes())
            store.backup(Path(d)/'backup.dpapi')
            self.assertEqual(Store(Path(d)).data['channels'][0]['node']['password'],'unique-test-secret')

    def test_corrupt_config_is_preserved_not_reset(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'settings.dpapi';p.write_bytes(b'broken configuration')
            with self.assertRaises(RuntimeError):Store(Path(d))
            self.assertEqual(p.read_bytes(),b'broken configuration')

if __name__=='__main__':unittest.main()
