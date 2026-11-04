/* Optional loopback-only transport diagnostic. MIT. No AP deliveries accepted. */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef long long s64;
extern u32 sock_init(void*,u64,u64,int) __asm__("_ZN2nn6socket10InitializeEPvmmi");
extern int sock_socket(int,int,int) __asm__("nnsocketSocket");
extern int sock_connect(int,const void*,u32) __asm__("nnsocketConnect");
extern int sock_close(int) __asm__("nnsocketClose");
extern int sock_fcntl(int,int,...) __asm__("nnsocketFcntl");
extern int sock_poll(void*,u64,int) __asm__("nnsocketPoll");
extern s64 sock_send(int,const void*,u64,int) __asm__("nnsocketSend");
extern s64 sock_recv(int,void*,u64,int) __asm__("nnsocketRecv");
extern int sock_error(void) __asm__("nnsocketGetLastErrno");
extern void network_probe_debug(const char*);

static unsigned char pool[0x200000] __attribute__((aligned(4096)));
static int initialized, disabled, fd=-1, connected, tx_at, tx_size, rx_size;
static u64 ticks, retry_at;
static char tx[64],rx[64];

static int again(int error) {return error==11 || error==35 || error==115 || error==36;}
static void reset(void) {
    if(fd>=0)sock_close(fd);
    fd=-1;connected=0;tx_at=tx_size=rx_size=0;retry_at=ticks+300;
}
static void queue(const char *p) {
    tx_at=tx_size=0;
    while(*p && tx_size<63)tx[tx_size++]=*p++;
}
void network_probe_tick(void) {
    ticks++;
    if(disabled || ticks<60)return;
    if(!initialized) {
        u32 result=sock_init(pool,sizeof pool,0x20000,2);
        if(result) {network_probe_debug("LAS_AP_NET initialize failed; diagnostic disabled\n");disabled=1;return;}
        initialized=1;network_probe_debug("LAS_AP_NET socket service initialized\n");
    }
    if(fd<0) {
        if(ticks<retry_at)return;
        fd=sock_socket(2,1,6);
        if(fd<0) {reset();return;}
        if(sock_fcntl(fd,4,0x800)<0) {reset();return;}
        // Horizon BSD sockaddr_in: len, family, port (network order), loopback.
        unsigned char address[16]={16,2,0x45,0x73,127,0,0,1,0,0,0,0,0,0,0,0}; // port 17779
        if(sock_connect(fd,address,sizeof address)<0 && !again(sock_error())) {reset();return;}
        retry_at=ticks+600;
    }
    if(!connected) {
        struct {int fd;short events,revents;} p={fd,4,0};
        int ready=sock_poll(&p,1,0);
        if(ready<0 || (p.revents&0x38) || ticks>retry_at) {reset();return;}
        if(!ready || !(p.revents&4))return;
        connected=1;queue("LAS_NATIVE_PROBE_V1\n");
    }
    if(tx_at<tx_size) {
        s64 n=sock_send(fd,tx+tx_at,(u64)(tx_size-tx_at),0);
        if(n>0)tx_at+=(int)n;
        else if(n==0 || !again(sock_error())) {reset();return;}
    }
    if(tx_at<tx_size)return;
    s64 n=sock_recv(fd,rx+rx_size,(u64)(sizeof rx-rx_size),0);
    if(n==0) {reset();return;}
    if(n<0) {if(!again(sock_error()))reset();return;}
    rx_size+=(int)n;
    if(rx_size==5 && rx[0]=='P' && rx[1]=='I' && rx[2]=='N' && rx[3]=='G' && rx[4]=='\n') {
        rx_size=0;queue("PONG\n");network_probe_debug("LAS_AP_NET loopback PING received; PONG queued\n");
    } else if(rx_size>=5) {
        network_probe_debug("LAS_AP_NET unsupported diagnostic command rejected\n");reset();
    }
}
