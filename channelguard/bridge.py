"""Authenticated WSL-only ingress to an existing channel, with no system fallback."""
from __future__ import annotations
import base64
import hmac
import select
import socket
import socketserver
import threading


class ProxyBridge:
    def __init__(self, host, port, peer, password, runtime):
        self.runtime=runtime
        self.accepted=0
        self.denied=0
        self.closed=False
        self.sockets=set()
        self.lock=threading.Lock()
        owner=self
        expected='Basic '+base64.b64encode(('cg-wsl:'+password).encode()).decode()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=True
            daemon_threads=True

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                client=self.request
                if self.client_address[0]!=peer:
                    owner.denied+=1
                    return
                client.settimeout(8)
                try:
                    header=b''
                    while b'\r\n\r\n' not in header:
                        part=client.recv(4096)
                        if not part:return
                        header+=part
                        if len(header)>65536:return
                    head,body=header.split(b'\r\n\r\n',1)
                    lines=head.decode('iso-8859-1').split('\r\n')
                    auth=[line.split(':',1)[1].strip() for line in lines[1:]
                          if line.lower().startswith('proxy-authorization:')]
                    if len(auth)!=1 or not hmac.compare_digest(auth[0].encode('iso-8859-1'),expected.encode()):
                        owner.denied+=1
                        client.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ChannelGuard"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                        return
                    current=owner.runtime()
                    if not current or current['process'].poll() is not None:
                        client.sendall(b'HTTP/1.1 503 Channel Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                        return
                    credential=base64.b64encode((current['username']+':'+current['password']).encode()).decode()
                    # Upstream remains the authenticated loopback channel; never dial the target here.
                    forwarded=[lines[0]]+[line for line in lines[1:]
                        if not line.lower().startswith(('proxy-authorization:','proxy-connection:'))]
                    forwarded+=['Proxy-Authorization: Basic '+credential]
                    upstream=socket.create_connection(('127.0.0.1',current['port']),timeout=5)
                    with upstream:
                        with owner.lock:owner.sockets.update((client,upstream))
                        try:
                            upstream.sendall(('\r\n'.join(forwarded)+'\r\n\r\n').encode('iso-8859-1')+body)
                            owner.accepted+=1
                            client.settimeout(30);upstream.settimeout(30)
                            while not owner.closed:
                                ready,_,_=select.select([client,upstream],[],[],1)
                                for source in ready:
                                    data=source.recv(65536)
                                    if not data:return
                                    (upstream if source is client else client).sendall(data)
                        finally:
                            with owner.lock:owner.sockets.difference_update((client,upstream))
                except (OSError,ValueError,UnicodeError):
                    return

        self.server=Server((host,port),Handler)
        self.host,self.port=self.server.server_address
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def close(self):
        self.closed=True
        with self.lock:
            for sock in list(self.sockets):
                try:sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
        self.server.shutdown();self.server.server_close();self.thread.join(3)
