import copy
import unittest
from channelguard.monitor import fingerprint,binding,environment_patch
from channelguard.storage import new_channel


def network(vpn=True):
    adapters=[{'Name':'WiFi','InterfaceDescription':'Intel Wi-Fi','Status':'Up','Guid':'one','Hardware':True}]
    configs=[{'InterfaceAlias':'WiFi','IPv4':['198.51.100.13'],'Gateway':['198.51.100.11']}]
    routes=[{'InterfaceAlias':'WiFi','DestinationPrefix':'0.0.0.0/0','NextHop':'198.51.100.11','RouteMetric':0}]
    if vpn:
        adapters.append({'Name':'newVPN','InterfaceDescription':'WireGuard VPN','Status':'Up','Guid':'two','Hardware':False})
        configs.append({'InterfaceAlias':'newVPN','IPv4':['203.0.113.12'],'Gateway':[]})
        routes.append({'InterfaceAlias':'newVPN','DestinationPrefix':'0.0.0.0/1','NextHop':'203.0.113.11','RouteMetric':0})
    return dict(adapters=adapters,configs=configs,routes=routes)


class MonitorTests(unittest.TestCase):
    def test_fingerprint_ignores_order_and_own_listener_but_detects_new_gateway(self):
        a=network();b=copy.deepcopy(a)
        b['adapters'].reverse();b['listeners']=[{'port':33333}]
        b['adapters'][0]['LinkSpeed']='10 Gbps'
        self.assertEqual(fingerprint(a),fingerprint(b))
        b['configs'][0]['Gateway']=['198.51.100.12']
        self.assertNotEqual(fingerprint(a),fingerprint(b))

    def test_missing_vpn_never_rebinds_to_wifi_or_system(self):
        c=new_channel();c.update(interface='oldVPN',network_role='vpn')
        self.assertIsNone(binding(c,network(False))[0])
        self.assertEqual(binding(c,network())[0],'newVPN')

    def test_multiple_vpns_require_choice(self):
        info=network();info['adapters'].append(dict(info['adapters'][1],Name='otherVPN',Guid='third'))
        info['configs'].append(dict(info['configs'][1],InterfaceAlias='otherVPN'))
        info['routes'].append(dict(info['routes'][1],InterfaceAlias='otherVPN'))
        c=new_channel();c.update(network_role='vpn',interface='old')
        self.assertIsNone(binding(c,info)[0])
        c['interface']='newVPN'
        self.assertEqual(binding(c,info)[0],'newVPN')

    def test_observed_environment_keeps_unknown_language_and_rejects_bad_timezone(self):
        self.assertEqual(environment_patch({'country':'US','timezone':'America/New_York'}),
            {'expected_country':'US','locale':'en-US','timezone':'America/New_York'})
        self.assertEqual(environment_patch({'country':'ZZ'}),{'expected_country':'ZZ'})
        with self.assertRaises(Exception):environment_patch({'timezone':'MadeUp/Nowhere'})
