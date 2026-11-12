#include "pb_internal.h"

/* ChannelGuard: each UDP client has its own SOCKS association. A shared
 * association cannot identify which app owns a reply from a common server.
 * No destination is contacted outside the selected SOCKS proxy. */
#define CG_UDP_SESSIONS 256
typedef struct {
    BOOL used;
    CONNECTION_INFO key;
    PROXY_CONFIG proxy;
    ULONGLONG active;
} CG_UDP;

static void cg_udp_close(CG_UDP *s)
{
    if (!s->used) return;
    if (s->proxy.udp_tcp_ctrl != INVALID_SOCKET) closesocket(s->proxy.udp_tcp_ctrl);
    if (s->proxy.udp_send_sock != INVALID_SOCKET) closesocket(s->proxy.udp_send_sock);
    memset(s, 0, sizeof(*s));
}

static BOOL cg_udp_key(UINT16 port, BOOL v6, CONNECTION_INFO *out, UINT32 up)
{
    BOOL found = FALSE;
    AcquireSRWLockShared(&lock);
    for (CONNECTION_INFO *c = connection_hash_table[port % CONNECTION_HASH_SIZE]; c; c = c->next) {
        if (c->src_port == port && c->is_udp && c->is_ipv6 == v6) {
            memcpy(out, c, sizeof(*out));
            if (up) InterlockedExchangeAdd64(&c->up_bytes, up);
            found = TRUE; break;
        }
    }
    ReleaseSRWLockShared(&lock);
    return found;
}

static BOOL cg_udp_same(const CONNECTION_INFO *a, const CONNECTION_INFO *b)
{
    return a->src_port == b->src_port && a->pid == b->pid && a->is_ipv6 == b->is_ipv6 &&
        a->proxy_config_id == b->proxy_config_id && a->orig_dest_port == b->orig_dest_port &&
        (a->is_ipv6 ? memcmp(a->src_ip6,b->src_ip6,16)==0 && memcmp(a->orig_dest_ip6,b->orig_dest_ip6,16)==0 :
                     a->src_ip == b->src_ip && a->orig_dest_ip == b->orig_dest_ip);
}

static BOOL cg_udp_current(CG_UDP *s, UINT32 down)
{
    BOOL found = FALSE;
    AcquireSRWLockShared(&lock);
    for (CONNECTION_INFO *c = connection_hash_table[s->key.src_port % CONNECTION_HASH_SIZE]; c; c = c->next) {
        if (c->is_udp && cg_udp_same(c,&s->key)) {
            if (down) InterlockedExchangeAdd64(&c->down_bytes,down);
            found = TRUE; break;
        }
    }
    ReleaseSRWLockShared(&lock);
    return found;
}

static CG_UDP *cg_udp_session(CG_UDP *sessions, CONNECTION_INFO *key)
{
    CG_UDP *free_slot = NULL;
    for (int i=0;i<CG_UDP_SESSIONS;i++) {
        CG_UDP *s=&sessions[i];
        if (s->used && cg_udp_same(&s->key,key)) return s;
        if (s->used && s->key.src_port==key->src_port && s->key.is_ipv6==key->is_ipv6) cg_udp_close(s);
        if (!s->used && !free_slot) free_slot=s;
    }
    if (!free_slot) return NULL; /* Capacity exhaustion fails closed. */
    PROXY_CONFIG *proxy=find_proxy_config(key->proxy_config_id);
    if (!proxy || proxy->type!=PROXY_TYPE_SOCKS5) return NULL;
    CG_UDP *s=free_slot;
    s->used=TRUE;memcpy(&s->key,key,sizeof(*key));memcpy(&s->proxy,proxy,sizeof(*proxy));
    s->proxy.udp_tcp_ctrl=INVALID_SOCKET;s->proxy.udp_send_sock=INVALID_SOCKET;
    s->proxy.udp_connected=FALSE;s->proxy.last_udp_attempt=0;
    if (!establish_udp_associate_for_config(&s->proxy)) {cg_udp_close(s);return NULL;}
    /* Connected UDP accepts packets only from this association's relay. */
    if (connect(s->proxy.udp_send_sock,(struct sockaddr*)&s->proxy.udp_relay_addr,sizeof(s->proxy.udp_relay_addr))==SOCKET_ERROR) {
        cg_udp_close(s);return NULL;
    }
    u_long nonblock=1;
    ioctlsocket(s->proxy.udp_send_sock,FIONBIO,&nonblock);
    s->active=GetTickCount64();return s;
}

static SOCKET cg_udp_listener(BOOL v6)
{
    SOCKET sock=socket(v6?AF_INET6:AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (sock==INVALID_SOCKET) return sock;
    int on=1;setsockopt(sock,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(char*)&on,sizeof(on));
    configure_udp_socket(sock,1024*1024,1000);
    if (v6) {
        setsockopt(sock,IPPROTO_IPV6,IPV6_V6ONLY,(char*)&on,sizeof(on));
        struct sockaddr_in6 a={0};a.sin6_family=AF_INET6;a.sin6_port=htons(LOCAL_UDP_RELAY_PORT);
        if (bind(sock,(struct sockaddr*)&a,sizeof(a))==SOCKET_ERROR) {closesocket(sock);return INVALID_SOCKET;}
    } else {
        struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(LOCAL_UDP_RELAY_PORT);
        if (bind(sock,(struct sockaddr*)&a,sizeof(a))==SOCKET_ERROR) {closesocket(sock);return INVALID_SOCKET;}
    }
    u_long nonblock=1;ioctlsocket(sock,FIONBIO,&nonblock);return sock;
}

DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa;if (WSAStartup(MAKEWORD(2,2),&wsa)) return 1;
    CG_UDP *sessions=calloc(CG_UDP_SESSIONS,sizeof(CG_UDP));
    unsigned char *packet=malloc(MAXBUF),*frame=malloc(MAXBUF);
    udp_relay_socket=cg_udp_listener(FALSE);udp_relay_socket6=cg_udp_listener(TRUE);
    if (!sessions || !packet || !frame || udp_relay_socket==INVALID_SOCKET) goto done;
    while (running) {
        fd_set reads;FD_ZERO(&reads);FD_SET(udp_relay_socket,&reads);
        if (udp_relay_socket6!=INVALID_SOCKET) FD_SET(udp_relay_socket6,&reads);
        for (int i=0;i<CG_UDP_SESSIONS;i++) if (sessions[i].used) {
            CG_UDP *s=&sessions[i];
            if (GetTickCount64()-s->active>60000 || !cg_udp_current(s,0)) {cg_udp_close(s);continue;}
            FD_SET(s->proxy.udp_send_sock,&reads);FD_SET(s->proxy.udp_tcp_ctrl,&reads);
        }
        struct timeval timeout={0,100000};
        if (select(0,&reads,NULL,NULL,&timeout)<=0) continue;
        /* Consume replies before creating sockets: Windows reuses SOCKET handles. */
        for (int i=0;i<CG_UDP_SESSIONS;i++) if (sessions[i].used) {
            CG_UDP *s=&sessions[i];
            if (FD_ISSET(s->proxy.udp_tcp_ctrl,&reads)) {
                char b;int n=recv(s->proxy.udp_tcp_ctrl,&b,1,MSG_PEEK);
                if (n<=0) {cg_udp_close(s);continue;}
            }
            if (!FD_ISSET(s->proxy.udp_send_sock,&reads)) continue;
            int n=recv(s->proxy.udp_send_sock,(char*)frame,MAXBUF,0),header=0;
            if (n<10 || frame[0] || frame[1] || frame[2]) continue;
            CONNECTION_INFO *k=&s->key;
            if (!k->is_ipv6 && frame[3]==1 && memcmp(frame+4,&k->orig_dest_ip,4)==0 &&
                (((UINT16)frame[8]<<8)|frame[9])==k->orig_dest_port) header=10;
            if (k->is_ipv6 && n>=22 && frame[3]==4 && memcmp(frame+4,k->orig_dest_ip6,16)==0 &&
                (((UINT16)frame[20]<<8)|frame[21])==k->orig_dest_port) header=22;
            if (!header || !cg_udp_current(s,n-header)) continue;
            if (k->is_ipv6 && udp_relay_socket6!=INVALID_SOCKET) {
                struct sockaddr_in6 a={0};a.sin6_family=AF_INET6;a.sin6_port=htons(k->src_port);memcpy(&a.sin6_addr,k->src_ip6,16);
                sendto(udp_relay_socket6,(char*)frame+header,n-header,0,(struct sockaddr*)&a,sizeof(a));
            } else if (!k->is_ipv6) {
                struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(k->src_port);a.sin_addr.s_addr=k->src_ip;
                sendto(udp_relay_socket,(char*)frame+header,n-header,0,(struct sockaddr*)&a,sizeof(a));
            }
            s->active=GetTickCount64();
        }
        for (int family=0;family<2 && running;family++) {
            SOCKET local=family?udp_relay_socket6:udp_relay_socket;
            if (local==INVALID_SOCKET || !FD_ISSET(local,&reads)) continue;
            struct sockaddr_storage peer={0};int size=sizeof(peer);
            int n=recvfrom(local,(char*)packet,MAXBUF-22,0,(struct sockaddr*)&peer,&size);
            if (n<=0) continue;
            UINT16 port=ntohs(family?((struct sockaddr_in6*)&peer)->sin6_port:((struct sockaddr_in*)&peer)->sin_port);
            CONNECTION_INFO key;
            if (!cg_udp_key(port,family,&key,n)) continue;
            if (!family) {
                UINT32 ip=((struct sockaddr_in*)&peer)->sin_addr.s_addr;
                if ((ip&255)!=127 && ip!=key.orig_dest_ip) continue;
            } else {
                static const UINT8 lb[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                void *ip=&((struct sockaddr_in6*)&peer)->sin6_addr;
                if (memcmp(ip,lb,16) && memcmp(ip,key.orig_dest_ip6,16)) continue;
            }
            CG_UDP *s=cg_udp_session(sessions,&key);if (!s) continue;
            memset(frame,0,4);frame[3]=family?4:1;int header=family?22:10;
            if (family) memcpy(frame+4,key.orig_dest_ip6,16);else memcpy(frame+4,&key.orig_dest_ip,4);
            frame[header-2]=(unsigned char)(key.orig_dest_port>>8);frame[header-1]=(unsigned char)key.orig_dest_port;
            memcpy(frame+header,packet,n);
            if (send(s->proxy.udp_send_sock,(char*)frame,n+header,0)==SOCKET_ERROR && WSAGetLastError()!=WSAEWOULDBLOCK) cg_udp_close(s);
            else s->active=GetTickCount64();
        }
    }
done:
    if (sessions) {for (int i=0;i<CG_UDP_SESSIONS;i++) cg_udp_close(&sessions[i]);free(sessions);}
    free(packet);free(frame);
    if (udp_relay_socket!=INVALID_SOCKET) {closesocket(udp_relay_socket);udp_relay_socket=INVALID_SOCKET;}
    if (udp_relay_socket6!=INVALID_SOCKET) {closesocket(udp_relay_socket6);udp_relay_socket6=INVALID_SOCKET;}
    WSACleanup();return 0;
}
