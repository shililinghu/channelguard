"""Authenticated-core compatibility shim: IPv4 loopback clients to IPv6 loopback.

Some external VPN split drivers rewrite excluded IPv4 UDP binds to a physical NIC.
The core listens exclusively on ::1; this non-excluded GUI hosts the 127.0.0.1 shim.
Authentication is performed by the core. No code here dials an Internet destination.
"""
import select
import socket
import socketserver
import threading
import time

def receive(sock,count):
    result=b''
    while len(result)<count:
        value=sock.recv(count-len(result))
        if not value:raise OSError('Closed core connection')
        result+=value
    return result

def address_tail(sock,kind):
    if kind==1:return receive(sock,6)
    if kind==4:return receive(sock,18)
    if kind==3:
        size=receive(sock,1);return size+receive(sock,size[0]+2)
    raise OSError('Unsupported SOCKS address')

class LoopbackCompat:
    def __init__(self,port):
        self.port=port;self.closed=False;self.clients=set();self.lock=threading.Lock()
        with socket.create_connection(('::1',port),timeout=3):pass
        owner=self
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=False
            daemon_threads=True
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                client=self.request;upstream=None
                try:
                    client.settimeout(8)
                    upstream=socket.create_connection(('::1',port),timeout=3)
                    with owner.lock:owner.clients.update((client,upstream))
                    first=receive(client,1)
                    if first==b'\5':
                        count=receive(client,1);upstream.sendall(first+count+receive(client,count[0]))
                        choice=receive(upstream,2);client.sendall(choice)
                        if choice==b'\5\2':
                            head=receive(client,2);user=receive(client,head[1]);size=receive(client,1)
                            upstream.sendall(head+user+size+receive(client,size[0]))
                            response=receive(upstream,2);client.sendall(response)
                            if response!=b'\1\0':return
                        elif choice!=b'\5\0':return
                        head=receive(client,4);upstream.sendall(head+address_tail(client,head[3]))
                        reply=receive(upstream,4);tail=address_tail(upstream,reply[3])
                        if head[1]==3 and reply[1]==0:
                            # Expose only our IPv4 loopback UDP relay, never the core's NIC.
                            client.sendall(b'\5\0\0\1\x7f\0\0\1'+port.to_bytes(2,'big'))
                        else:client.sendall(reply+tail)
                    else:upstream.sendall(first)
                    client.settimeout(30);upstream.settimeout(30)
                    while not owner.closed:
                        readable,_,_=select.select([client,upstream],[],[],.5)
                        for sock in readable:
                            value=sock.recv(65536)
                            if not value:return
                            (upstream if sock is client else client).sendall(value)
                except OSError:pass
                finally:
                    with owner.lock:owner.clients.discard(client);owner.clients.discard(upstream)
                    if upstream:upstream.close()
        self.tcp=Server(('127.0.0.1',port),Handler)
        try:
            self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self.udp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024)
            self.udp.bind(('127.0.0.1',port))
        except Exception:
            self.tcp.server_close();raise
        self.tcp_thread=threading.Thread(target=self.tcp.serve_forever,kwargs={'poll_interval':.1},daemon=True)
        self.udp_thread=threading.Thread(target=self.relay_udp,daemon=True)
        self.tcp_thread.start();self.udp_thread.start()

    def relay_udp(self):
        by_peer={};by_socket={};last={}
        try:
            while not self.closed:
                ready,_,_=select.select([self.udp,*by_socket],[],[],.2)
                for sock in ready:
                    try:
                        if sock is self.udp:
                            value,peer=self.udp.recvfrom(65535)
                            if peer[0]!='127.0.0.1':continue
                            if peer not in by_peer:
                                if len(by_peer)>=128:continue
                                target=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
                                target.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024)
                                target.connect(('::1',self.port))
                                by_peer[peer]=target;by_socket[target]=peer
                            last[peer]=time.monotonic();by_peer[peer].send(value)
                        else:
                            value=sock.recv(65535);peer=by_socket[sock]
                            last[peer]=time.monotonic();self.udp.sendto(value,peer)
                    except OSError:continue
                for peer,stamp in list(last.items()):
                    if time.monotonic()-stamp>120:
                        sock=by_peer.pop(peer);by_socket.pop(sock,None);last.pop(peer,None);sock.close()
        except (OSError,ValueError):pass
        finally:
            for sock in by_socket:sock.close()

    def close(self):
        self.closed=True
        with self.lock:
            for sock in list(self.clients):
                try:sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
        self.tcp.shutdown();self.tcp.server_close();self.udp.close()
        self.tcp_thread.join(2);self.udp_thread.join(2)
