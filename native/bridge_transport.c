/* Bounded nonblocking localhost JSON transport. Original code, MIT.
 * Development native bridge: capability claims are deliberately empty. */
#include "generated_profile.h"
#include "wire_json.h"
typedef unsigned long long u64;
typedef long long s64;
extern unsigned sock_init(void*,u64,u64,int) __asm__("_ZN2nn6socket10InitializeEPvmmi");
extern int sock_socket(int,int,int) __asm__("nnsocketSocket");
extern int sock_connect(int,const void*,unsigned) __asm__("nnsocketConnect");
extern int sock_close(int) __asm__("nnsocketClose");
extern int sock_fcntl(int,int,...) __asm__("nnsocketFcntl");
extern int sock_poll(void*,u64,int) __asm__("nnsocketPoll");
extern s64 sock_send(int,const void*,u64,int) __asm__("nnsocketSend");
extern s64 sock_recv(int,void*,u64,int) __asm__("nnsocketRecv");
extern int sock_error(void) __asm__("nnsocketGetLastErrno");
extern void network_probe_debug(const char*);
extern void native_bridge_log(const char*,u64);
extern int native_bridge_state(char*,unsigned);
extern int native_bridge_deliver(const WireJson*);
extern int native_bridge_sync_checks(const WireJson*);
extern int native_bridge_deathlink(const WireJson*);
extern int native_bridge_hint(const WireJson*);
static unsigned char pool[0x200000] __attribute__((aligned(4096)));
static char tx[65536],rx[65536];
static WireJson json;
static int initialized,disabled,fd=-1,connected,ack,tx_at,tx_size,rx_size;
static u64 ticks,retry_at,deadline,state_at,last_rx;
static int again(int e){return e==11||e==35||e==115||e==36;}
static void reset(void){
    if(fd>=0)sock_close(fd);
    fd=-1;connected=ack=tx_at=tx_size=rx_size=0;retry_at=ticks+300;
}
static void hello(void){
    tx_at=tx_size=0;
    for(unsigned i=0;i<sizeof BRIDGE_HELLO-1;i++)tx[tx_size++]=BRIDGE_HELLO[i];
}
static int command(int size){
    if(wire_parse(&json,rx,size))return -1;
    int t=wire_member(&json,0,"t");
    if(!ack){
        unsigned version=0;int ok=wire_member(&json,0,"ok");
        if(!wire_equal(&json,t,"hello_ack")||wire_u32(&json,wire_member(&json,0,"protocol"),&version)||
           version!=1||ok<0||json.tokens[ok].type!='t')return -1;
        ack=1;state_at=0;
        network_probe_debug("LAS_AP_BRIDGE validated PC acknowledgement\n");return 0;
    }
    if(wire_equal(&json,t,"deliver")){
        int result=native_bridge_deliver(&json);state_at=0;return result<0?-1:0;
    }
    if(wire_equal(&json,t,"sync_checks")){
        int result=native_bridge_sync_checks(&json);state_at=0;return result<0?-1:0;
    }
    if(wire_equal(&json,t,"deathlink")){
        int result=native_bridge_deathlink(&json);state_at=0;return result<0?-1:0;
    }
    if(wire_equal(&json,t,"hint")){
        int result=native_bridge_hint(&json);state_at=0;return result<0?-1:0;
    }
    return -1;
}
void bridge_transport_tick(void){
    ticks++;if(disabled||ticks<60)return;
    if(!initialized){
        if(sock_init(pool,sizeof pool,0x20000,2)){
            disabled=1;network_probe_debug("LAS_AP_BRIDGE socket initialization failed\n");return;
        }initialized=1;
    }
    if(fd<0){
        if(ticks<retry_at)return;
        fd=sock_socket(2,1,6);if(fd<0){reset();return;}
        if(sock_fcntl(fd,4,0x800)<0){reset();return;}
        unsigned char address[16]={16,2,0x45,0x72,127,0,0,1}; // 17778
        if(sock_connect(fd,address,sizeof address)<0&&!again(sock_error())){reset();return;}
        deadline=ticks+600;
    }
    if(!connected){
        struct{int fd;short events,revents;} poll={fd,4,0};
        int result=sock_poll(&poll,1,0);
        if(result<0||(poll.revents&0x38)||ticks>deadline){reset();return;}
        if(!result||!(poll.revents&4))return;
        connected=1;last_rx=ticks;hello();
        native_bridge_log("LAS_AP_BRIDGE hello queued bytes=",tx_size);
    }
    if((!ack||tx_at<tx_size)&&ticks>deadline){reset();return;}
    if(tx_at==tx_size&&ack&&ticks>=state_at){
        tx_at=0;tx_size=native_bridge_state(tx,sizeof tx);
        if(tx_size<0){reset();return;}state_at=ticks+120;deadline=ticks+1800;
    }
    if(tx_at<tx_size){
        s64 n=sock_send(fd,tx+tx_at,(u64)(tx_size-tx_at),0);
        if(n>0)tx_at+=(int)n;else if(!n||!again(sock_error())){
            native_bridge_log("LAS_AP_BRIDGE send failure errno=",sock_error());reset();return;
        }
    }
    // Keep any complete frame until the queued outgoing frame drains. This
    // bounds both receive work and command execution to one command per tick.
    if(tx_at<tx_size)return;
    for(int i=0;i<rx_size;i++)if(rx[i]=='\n'){
        if(command(i)){network_probe_debug("LAS_AP_BRIDGE invalid or unsupported command rejected\n");reset();return;}
        int consumed=i+1;for(int k=consumed;k<rx_size;k++)rx[k-consumed]=rx[k];
        rx_size-=consumed;last_rx=ticks;return;
    }
    if(rx_size==sizeof rx){reset();return;}
    struct{int fd;short events,revents;} read_poll={fd,1,0};
    int readable=sock_poll(&read_poll,1,0);
    if(readable<0||(read_poll.revents&0x38)){reset();return;}
    if(!readable||!(read_poll.revents&1))return;
    unsigned remaining=sizeof rx-rx_size;
    if(remaining>4096)remaining=4096;
    s64 n=sock_recv(fd,rx+rx_size,remaining,0);
    if(n>0)rx_size+=(int)n;
    else if(!n||!again(sock_error())){
        native_bridge_log("LAS_AP_BRIDGE receive failure errno=",sock_error());reset();
    }
}
