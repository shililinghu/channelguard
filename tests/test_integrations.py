import unittest
from types import SimpleNamespace
from unittest.mock import patch
from channelguard.integrations import OpenClawIntegration
from channelguard import wsl_helper


class IntegrationTests(unittest.TestCase):
    def test_service_restart_waits_for_node_and_inherited_environment(self):
        with patch.object(wsl_helper,'inspect',side_effect=[RuntimeError('Unexpected gateway runtime'),{'proxy_configured':False},{'proxy_configured':True}]),patch.object(wsl_helper.time,'sleep') as sleep:
            self.assertTrue(wsl_helper.wait_ready()['proxy_configured'])
            self.assertEqual(sleep.call_count,2)

    def test_wsl_address_accepts_powershell_scalar_array_and_wrapped_array(self):
        state=dict(host='192.0.2.1',peer='192.0.2.102')
        for addresses in ('192.0.2.1',['192.0.2.1'],{'value':['192.0.2.1'],'Count':1}):
            with self.subTest(addresses=addresses):
                integration=OpenClawIntegration(SimpleNamespace(data={}),SimpleNamespace(active={}))
                with patch('channelguard.integrations.wsl_call',return_value=state),patch('channelguard.integrations.ProxyBridge') as bridge:
                    bridge.return_value.port=12345
                    integration.prepare({'id':'direct'},{'configs':[{'InterfaceAlias':'vEthernet (WSL)','IPv4':addresses}]})
                    self.assertEqual(bridge.call_args.args[:3],('192.0.2.1',0,'192.0.2.102'))

    def test_matching_lan_address_cannot_open_wsl_listener(self):
        integration=OpenClawIntegration(SimpleNamespace(data={}),SimpleNamespace(active={}))
        with patch('channelguard.integrations.wsl_call',return_value=dict(host='198.51.100.3',peer='198.51.100.4')),patch('channelguard.integrations.ProxyBridge') as bridge:
            with self.assertRaises(RuntimeError):
                integration.prepare({'id':'direct'},{'configs':[{'InterfaceAlias':'Wi-Fi','IPv4':'198.51.100.3'}]})
            bridge.assert_not_called()
