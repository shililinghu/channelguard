import base64
import socket
import socketserver
import threading
import unittest
from channelguard.bridge import ProxyBridge


class Process:
    def poll(self):return None


class BridgeTests(unittest.TestCase):
    def test_authentication_credential_translation_and_dead_channel(self):
        received=[]
        class Upstream(socketserver.BaseRequestHandler):
            def handle(self):
                received.append(self.request.recv(10000))
                self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True
        server=Server(('127.0.0.1',0),Upstream)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        runtime={'port':server.server_address[1],'username':'actual','password':'private','process':Process()}
        target=[runtime]
        bridge=ProxyBridge('127.0.0.1',0,'127.0.0.1','wsl-secret',lambda:target[0])
        def request(auth):
            with socket.create_connection(('127.0.0.1',bridge.port),timeout=3) as client:
                header='CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n'
                if auth:header+='Proxy-Authorization: Basic '+base64.b64encode(auth.encode()).decode()+'\r\n'
                client.sendall((header+'\r\n').encode());return client.recv(10000)
        try:
            self.assertIn(b'407',request(None));self.assertFalse(received)
            self.assertIn(b'407',request('cg-wsl:wrong'));self.assertFalse(received)
            self.assertIn(b'200',request('cg-wsl:wsl-secret'))
            self.assertIn(base64.b64encode(b'actual:private'),received[0])
            self.assertNotIn(base64.b64encode(b'cg-wsl:wsl-secret'),received[0])
            count=len(received);target[0]=None
            self.assertIn(b'503',request('cg-wsl:wsl-secret'))
            self.assertEqual(count,len(received),'Dead channel must never dial a target directly')
        finally:bridge.close();server.shutdown();server.server_close()
