/* LAS 1.0.0 native hook probe. Original code, MIT licensed.
 * Hooks execute on the game's calling thread and always forward original calls.
 * This build deliberately makes no Archipelago capability claims.
 */
#include "generated_profile.h"
#if PROBE_BRIDGE
#include "wire_json.h"
#include "generated_rewards.h"
#endif
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef u64 (*Call8)(u64,u64,u64,u64,u64,u64,u64,u64);
typedef struct { u64 addr,size; u32 type,attr,perm,ipc,device,pad; } MemInfo;
u64 original_add_tail, original_frame_tail,original_has_tail,original_factory_tail;
u64 original_world_npc_tail;
static int reward_active;
static u64 main_base, frames, additions;
static u64 player_stable_frames;
static int gave_test_reward;
#if PROBE_RECEIPT || PROBE_MANAGED
extern int las_state_bind(u8 *,const u8 *);
extern int las_state_prepare(const u8 *,const u8 *,u32,const u8 *,const u8 *);
extern int las_state_commit(u8 *,const u8 *,u32,const u8 *,const u8 *);
extern int las_state_check(u8 *,const u8 *,unsigned);
extern u32 las_state_cursor(const u8 *);
extern int las_state_validate(const u8 *,const u8 *);
static u64 save_owner;
static unsigned save_depth;
static int receipt_announced;
static u8 before_grant[0x5EE0] __attribute__((aligned(16)));
static int save_transaction_active;
#if PROBE_BRIDGE
static void abort_event_for_load(void);
#endif
extern void las_image_crc(u8 *,const u32 *);
static u64 thread_token(void) {u64 token;__asm__ volatile("mrs %0,tpidrro_el0":"=r"(token));return token?token:1;}
static void save_enter(void) {
    u64 token=thread_token();
    if(__atomic_load_n(&save_owner,__ATOMIC_ACQUIRE)==token){save_depth++;return;}
    for(;;){u64 empty=0;if(__atomic_compare_exchange_n(&save_owner,&empty,token,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))break;}
    save_depth=1;
}
static void save_leave(void) {if(!--save_depth)__atomic_store_n(&save_owner,0,__ATOMIC_RELEASE);}
#endif
extern u64 forward_add(u64,u64,u64,u64,u64,u64,u64,u64);
extern u64 forward_frame(u64,u64,u64,u64,u64,u64,u64,u64);
extern u64 forward_has(u64,u64,u64,u64,u64,u64,u64,u64);
extern u64 forward_factory(u64,u64,u64,u64,u64,u64,u64,u64);

static u32 query(MemInfo *info, u64 address) {
    register u64 x0 __asm__("x0")=(u64)info;
    register u64 x1 __asm__("x1");
    register u64 x2 __asm__("x2")=address;
    __asm__ volatile("svc #6" : "+r"(x0), "=r"(x1), "+r"(x2) : :
        "x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    return (u32)x0;
}
static void debug(const char *s) {
    u64 len=0; while(s[len]) len++;
    register u64 x0 __asm__("x0")=(u64)s;
    register u64 x1 __asm__("x1")=len;
    __asm__ volatile("svc #0x27" : "+r"(x0), "+r"(x1) : :
        "x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
}
void network_probe_debug(const char *s) {debug(s);}
static void hex(char *p,u64 n) {
    const char *digits="0123456789ABCDEF";
    for(int i=0;i<16;i++) p[i]=digits[(n>>(60-4*i))&15];
}
static void log_value(const char *label,u64 v) {
    char out[120]; unsigned n=0;
    while(label[n] && n<90) {out[n]=label[n];n++;}
    hex(out+n,v);out[n+16]='\n';out[n+17]=0;debug(out);
}
void native_bridge_log(const char *label,u64 value){log_value(label,value);}
#if PROBE_SAVE
typedef void *(*CopyFn)(void *,const void *,u64);
typedef u32 (*WriteFn)(u64,long long,const void *,u64,u64);
static CopyFn original_memcpy,original_memmove;
static WriteFn original_write_file;
static unsigned save_copy_logs;
static void refresh_copy_import(CopyFn *original,u64 offset,CopyFn hook) {
    CopyFn *slot=(CopyFn *)(main_base+offset);
    CopyFn current=__atomic_load_n(slot,__ATOMIC_ACQUIRE);
    if(current && current!=hook) {
        __atomic_store_n(original,current,__ATOMIC_RELEASE);
        __atomic_store_n(slot,hook,__ATOMIC_RELEASE);
    }
}
static int touches_save(u64 address,u64 size) {
    u64 start=main_base+LIVE_SAVE;
    return size && size<0x100000 && address<start+0x5EC8 && address+size>start;
}
static int full_save_snapshot(void *d,const void *s,u64 n){
    u64 live=main_base+LIVE_SAVE,dest=(u64)d;
    return (u64)s==live&&n==0x5EE0&&(dest>=live+n||dest+n<=live);
}
static void observe_copy(void *destination,const void *source,u64 size) {
    if(save_copy_logs<100 && (touches_save((u64)source,size)||touches_save((u64)destination,size))) {
        save_copy_logs++;
        log_value("LAS_AP_SAVE copy source=",(u64)source);
        log_value("LAS_AP_SAVE copy destination=",(u64)destination);
        log_value("LAS_AP_SAVE copy size=",size);
    }
}
static void *las_memcpy(void *d,const void *s,u64 n) {
#if PROBE_RECEIPT || PROBE_MANAGED
    int protected=touches_save((u64)s,n)||touches_save((u64)d,n);
    if(protected)save_enter();
    int snapshot=full_save_snapshot(d,s,n);
#if PROBE_BRIDGE
    if((u64)d<=main_base+LIVE_SAVE+NATIVE_STATE_OFFSET &&
       (u64)d+n>=main_base+LIVE_SAVE+NATIVE_STATE_OFFSET+NATIVE_STATE_SIZE &&
       !touches_save((u64)s,n))abort_event_for_load();
#endif
    const void *actual=(snapshot&&save_transaction_active)?before_grant:s;
#else
    const void *actual=s;
#endif
    void *r=__atomic_load_n(&original_memcpy,__ATOMIC_ACQUIRE)(d,actual,n);
#if PROBE_RECEIPT || PROBE_MANAGED
    if(snapshot)las_image_crc((u8 *)d,(const u32 *)(main_base+0x17029F8));
#endif
    refresh_copy_import(&original_memcpy,MEMCPY_GOT,las_memcpy);
    observe_copy(d,s,n);
#if PROBE_RECEIPT || PROBE_MANAGED
    if(protected)save_leave();
#endif
    return r;
}
static void *las_memmove(void *d,const void *s,u64 n) {
#if PROBE_RECEIPT || PROBE_MANAGED
    int protected=touches_save((u64)s,n)||touches_save((u64)d,n);
    if(protected)save_enter();
    int snapshot=full_save_snapshot(d,s,n);
#if PROBE_BRIDGE
    if((u64)d<=main_base+LIVE_SAVE+NATIVE_STATE_OFFSET &&
       (u64)d+n>=main_base+LIVE_SAVE+NATIVE_STATE_OFFSET+NATIVE_STATE_SIZE &&
       !touches_save((u64)s,n))abort_event_for_load();
#endif
    const void *actual=(snapshot&&save_transaction_active)?before_grant:s;
#else
    const void *actual=s;
#endif
    void *r=__atomic_load_n(&original_memmove,__ATOMIC_ACQUIRE)(d,actual,n);
#if PROBE_RECEIPT || PROBE_MANAGED
    if(snapshot)las_image_crc((u8 *)d,(const u32 *)(main_base+0x17029F8));
#endif
    refresh_copy_import(&original_memmove,MEMMOVE_GOT,las_memmove);
    observe_copy(d,s,n);
#if PROBE_RECEIPT || PROBE_MANAGED
    if(protected)save_leave();
#endif
    return r;
}
static u32 las_write_file(u64 handle,long long offset,const void *data,u64 size,u64 option) {
    u64 caller=(u64)__builtin_return_address(0);
    u32 result=__atomic_load_n(&original_write_file,__ATOMIC_ACQUIRE)(handle,offset,data,size,option);
    WriteFn *slot=(WriteFn *)(main_base+WRITE_FILE_GOT);
    WriteFn current=__atomic_load_n(slot,__ATOMIC_ACQUIRE);
    if(current && current!=las_write_file) {
        __atomic_store_n(&original_write_file,current,__ATOMIC_RELEASE);
        __atomic_store_n(slot,las_write_file,__ATOMIC_RELEASE);
    }
    if(size>=0x5000 && size<=0x10000) {
        log_value("LAS_AP_SAVE write buffer=",(u64)data);
        log_value("LAS_AP_SAVE write offset=",(u64)offset);
        log_value("LAS_AP_SAVE write size=",size);
        log_value("LAS_AP_SAVE write caller offset=",caller-main_base);
        log_value("LAS_AP_SAVE write result=",result);
    }
    return result;
}
#endif
#if PROBE_RECEIPT
static void receipt_tick(void) {
    u8 *save=(u8 *)(main_base+LIVE_SAVE);
    u64 manager=*(volatile u64 *)(main_base+GAME_MANAGER);
    if(!manager || !*(volatile u64 *)(manager+0x4b8))return;
    if(*(volatile u32 *)(main_base+0x1CC1390)!=256 ||
       *(volatile u64 *)(main_base+0x1CC1388)!=(u64)(save+0x5DC0))return;
    // This test is explicitly restricted to the already-completed fresh Tarin slot.
    if(!(save[0x5DC0+258/8]&(1u<<(258%8))))return;
    if(++player_stable_frames<360)return;
    save_enter();
    u8 *state=save+NATIVE_STATE_OFFSET;
    int bound=las_state_bind(state,DIAGNOSTIC_FP);
    if(bound<0){if(!receipt_announced)debug("LAS_AP_RECEIPT incompatible saved state; delivery blocked\n");receipt_announced=1;save_leave();return;}
    las_state_check(state,DIAGNOSTIC_FP,0);
    u32 cursor=las_state_cursor(state);
    if(cursor) {
        if(!receipt_announced){log_value("LAS_AP_RECEIPT saved cursor restored=",cursor);debug("LAS_AP_RECEIPT no duplicate grant\n");}
        receipt_announced=1;save_leave();return;
    }
    if(las_state_prepare(state,DIAGNOSTIC_FP,0,state+24,DIAGNOSTIC_NEXT)) {save_leave();return;}
    for(unsigned i=0;i<sizeof before_grant;i++)before_grant[i]=save[i];
    u32 before=*(u32 *)(save+0x5540);
    if(before>9949){save_leave();return;}
    save_transaction_active=1;
    ((Call8)(main_base+0x7E18B0))(105,1,(u64)-1,0,0,0,0,0);
    u32 after=*(u32 *)(save+0x5540);
    int committed=after==before+50 ? las_state_commit(state,DIAGNOSTIC_FP,0,before_grant+NATIVE_STATE_OFFSET+24,DIAGNOSTIC_NEXT) : -1;
    if(committed) {
        for(unsigned i=0;i<sizeof before_grant;i++)save[i]=before_grant[i];
        debug("LAS_AP_RECEIPT grant failed; live snapshot restored\n");
    } else {
        log_value("LAS_AP_RECEIPT rupees before=",before);
        log_value("LAS_AP_RECEIPT rupees after=",after);
        debug("LAS_AP_RECEIPT diagnostic cursor committed=1; save to persist\n");
        receipt_announced=1;
    }
    save_transaction_active=0;save_leave();
}
#endif
static int bytes_equal(const u8 *a,const u8 *b,unsigned n) {
    for(unsigned i=0;i<n;i++) if(a[i]!=b[i]) return 0;
    return 1;
}
#if PROBE_BRIDGE
static int event_pending;
static int deathlink_pending;
static u32 deathlink_ack;
static int hint_pending;
static u32 hint_ack,hint_ack_index;
static u32 event_cursor;
static u8 event_previous[32],event_next[32];
static void abort_event_for_load(void){
    event_pending=0;deathlink_pending=0;hint_pending=0;save_transaction_active=0;player_stable_frames=0;
}
extern int native_request_common(u64,const char *);
extern int native_spawn_zol(u64,u32);
static void finish_event_reward(void) {
    if(!event_pending)return;
    save_enter();
    u8 *s=(u8 *)(main_base+LIVE_SAVE+NATIVE_STATE_OFFSET);
    int status=las_state_commit(s,MANAGED_FP,event_cursor,event_previous,event_next);
    event_pending=0;save_transaction_active=0;
    log_value("LAS_AP_BRIDGE event reward completion status=",(u64)(long long)status);
    save_leave();
}
static int bridge_ready(void) {
    u8 *save=(u8 *)(main_base+LIVE_SAVE);
    u64 gm=*(volatile u64 *)(main_base+GAME_MANAGER);
    return !event_pending && !deathlink_pending && !hint_pending && (save[0x5544]||save[0x5545]) && player_stable_frames>=60 && gm && *(volatile u64 *)(gm+0x4b8) &&
        *(volatile u32 *)(main_base+0x1CC1390)==256 &&
        *(volatile u64 *)(main_base+0x1CC1388)==(u64)(save+0x5DC0) &&
        *(volatile u64 *)(main_base+0x1CC1368)==(u64)(save+0x54C0) &&
        !las_state_validate(save+NATIVE_STATE_OFFSET,MANAGED_FP);
}
static int append(char *out,unsigned cap,int at,const char *text) {
    while(*text){if((unsigned)at>=cap)return -1;out[at++]=*text++;}return at;
}
static int number(char *out,unsigned cap,int at,u32 value) {
    char digits[11];unsigned n=0;do{digits[n++]=(char)('0'+value%10);value/=10;}while(value);
    while(n){if(at<0||(unsigned)at>=cap)return -1;out[at++]=digits[--n];}return at;
}
int native_bridge_state(char *out,unsigned cap) {
    // Up to 352 ten-digit check IDs plus framing fit comfortably in this bound.
    if(cap<384+11*MANAGED_COUNT)return -1;
    u8 *s=(u8 *)(main_base+LIVE_SAVE+NATIVE_STATE_OFFSET);
    save_enter();int valid=!las_state_validate(s,MANAGED_FP);
    int at=append(out,cap,0,"{\"t\":\"state\",\"cursor\":");
    at=number(out,cap,at,valid?las_state_cursor(s):0);
    at=append(out,cap,at,",\"history_hash\":\"");
    if(valid){
        const char *hexes="0123456789abcdef";
        for(unsigned i=0;i<32;i++){out[at++]=hexes[s[24+i]>>4];out[at++]=hexes[s[24+i]&15];}
    }else at=append(out,cap,at,"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945");
    at=append(out,cap,at,"\",\"checks\":[");unsigned count=0;
    if(valid)for(unsigned i=0;i<MANAGED_COUNT;i++)if(s[56+i/8]&(1u<<(i%8))){
        if(count++)out[at++]=',';at=number(out,cap,at,MANAGED_IDS[i]);
    }
    at=append(out,cap,at,bridge_ready()?"],\"ready\":true,\"victory\":" : "],\"ready\":false,\"victory\":");
    int won=valid&&(*(u8 *)(main_base+LIVE_SAVE+0x5DC0+NATIVE_VICTORY_FLAG/8)&(1u<<(NATIVE_VICTORY_FLAG%8)));
    at=append(out,cap,at,won?"true":"false");
    u64 gm=*(volatile u64 *)(main_base+GAME_MANAGER);
    int active=valid&&player_stable_frames>=60&&gm&&*(volatile u64 *)(gm+0x4b8)&&
        *(volatile u64 *)(main_base+0x1CC1388)==main_base+LIVE_SAVE+0x5DC0;
    at=append(out,cap,at,",\"alive\":");
    at=append(out,cap,at,!active?"null":((*(u8 *)(main_base+LIVE_SAVE+0x5544)||*(u8 *)(main_base+LIVE_SAVE+0x5545))?"true":"false"));
    at=append(out,cap,at,",\"deathlink_ack\":");at=number(out,cap,at,deathlink_ack);
    at=append(out,cap,at,deathlink_pending?",\"deathlink_busy\":true":",\"deathlink_busy\":false");
    at=append(out,cap,at,",\"hint_ack\":");at=number(out,cap,at,hint_ack);
    at=append(out,cap,at,hint_pending?",\"hint_busy\":true":",\"hint_busy\":false");
    at=append(out,cap,at,"}\n");
    save_leave();return at;
}
int native_bridge_deathlink(const WireJson *j){
    u32 nonce;
    if(!NATIVE_DEATHLINK||wire_u32(j,wire_member(j,0,"nonce"),&nonce)||!nonce)return -1;
    if(nonce==deathlink_ack)return 0;
    if(!bridge_ready())return 1;
    if(!native_request_common(main_base,"AP_DeathLink"))return 1;
    deathlink_pending=1;deathlink_ack=nonce;return 0;
}
int native_bridge_hint(const WireJson *j){
    u32 index,nonce;
    if(wire_u32(j,wire_member(j,0,"index"),&index)||index>=NATIVE_HINT_COUNT||
       wire_u32(j,wire_member(j,0,"nonce"),&nonce)||!nonce)return -1;
    if(nonce==hint_ack)return index==hint_ack_index?0:-1;
    if(!bridge_ready())return 1;
    if(!native_request_common(main_base,NATIVE_HINT_ENTRIES[index]))return 1;
    hint_pending=1;hint_ack=nonce;hint_ack_index=index;return 0;
}
static int reward_flag(const u8 *save,int flag){return !!(save[0x5DC0+flag/8]&(1u<<(flag%8)));}
static void reward_set_flag(u8 *save,int flag,int value){
    u8 *p=save+0x5DC0+flag/8,mask=(u8)(1u<<(flag%8));
    if(value)*p|=mask;else *p&=(u8)~mask;
}
static u8 *indexed_storage(u8 *save,const NativeReward *r){
    if(r->storage_offset>=0)return save+r->storage_offset;
    u64 pointer=*(volatile u64 *)(main_base+0x1CC1208);
    unsigned size=*(volatile u32 *)(main_base+0x1CC1210);
    if(size<7||size>32||pointer<(u64)save||pointer+size>(u64)(save+0x5EC4))return 0;
    return (u8 *)pointer;
}
static int apply_reward(u8 *save,const NativeReward *r){
    unsigned native=r->native0;
    if(r->kind==4){
        unsigned number=r->dungeon?((unsigned)r->dungeon-1):9;
        unsigned record=r->dungeon?2*((unsigned)r->dungeon-1):18;
        u8 *target=save+0xE0+record*0x10;
        u64 table=*(volatile u64 *)(main_base+0x1CC11B0);
        // Verify that the engine's own dungeon table aliases this save record.
        if(!table||*(volatile u64 *)(table+number*8)!=(u64)target)return -1;
        if(native==48){if(target[0]==255)return -1;target[0]++;}
        else{
            unsigned bit=native==44?1:native==45?2:native==47?4:native==49?8:0;
            if(!bit)return -1;target[1]|=(u8)bit;
        }
        return 0;
    }
    int chosen=-1;
    u8 *storage=0;
    if(r->kind==5){
        storage=indexed_storage(save,r);if(!storage)return -1;
        for(unsigned i=0;i<r->index_count;i++){
            unsigned bit=r->indexes[i]+r->storage_shift;
            if(!(storage[bit/8]&(1u<<(bit%8)))){chosen=(int)r->indexes[i];break;}
        }
        // Every valid engine slot is already owned: preserve all vanilla bits.
        if(chosen<0)return 0;
    }
    if(r->kind==1&&reward_flag(save,r->progressive_flag))native=r->native1;
    for(unsigned i=0;i<r->flag_count;i++)reward_set_flag(save,r->flags[i][0],r->flags[i][1]);
    u32 before=*(u32 *)(save+0x5540);
    if(r->kind!=3)((Call8)(main_base+0x7E18B0))(native,r->count,(u64)(long long)chosen,0,0,0,0,0);
    if(r->extra_native>=0&&(r->extra_flag<0||reward_flag(save,r->extra_flag)))
        ((Call8)(main_base+0x7E18B0))((u64)r->extra_native,r->extra_count,(u64)-1,0,0,0,0,0);
    if(r->heal){
        unsigned bit=100%8;u8 *p=save+0x55E4+100/8,was=*p;
        ((Call8)(main_base+0x7E18B0))(100,99,(u64)-1,0,0,0,0,0);
        *p=(u8)((*p&~(1u<<bit))|(was&(1u<<bit)));
        u32 max=(u32)((Call8)(main_base+0xDF8260))(main_base+0x1CC1368,0,0,0,0,0,0,0);
        unsigned current=save[0x5544]|(unsigned)save[0x5545]<<8;
        if(current!=max)return -1;
    }
    if(r->capacity_mask && (save[0x555C]&r->capacity_mask)!=r->capacity_mask)return -1;
    if(r->kind==5){
        unsigned bit=(unsigned)chosen+r->storage_shift;
        if(!(storage[bit/8]&(1u<<(bit%8))))return -1;
        if(r->bottle_flag>=0&&chosen==1)reward_set_flag(save,r->bottle_flag,1);
    }
    if(r->getting_flag>=0)reward_set_flag(save,r->getting_flag,1);
    for(unsigned i=0;i<r->flag_count;i++)if(reward_flag(save,r->flags[i][0])!=r->flags[i][1])return -1;
    if(r->kind==2){
        u32 after=*(u32 *)(save+0x5540),wanted=before+r->rupees;
        if(wanted>9999)wanted=9999;
        return after==wanted?0:-1;
    }
    // The inspected common AddItem tail records its accepted item ID here.
    if(r->kind!=3&&!(save[0x55E4+native/8]&(1u<<(native%8))))return -1;
    return 0;
}
int native_bridge_sync_checks(const WireJson *j){
    int array=wire_member(j,0,"checks");
    if(array<0||j->tokens[array].type!='['||j->tokens[array].count>128)return -1;
    unsigned ordinals[128],count=0;
    for(int token=array+1;token<j->tokens[array].next;token=j->tokens[token].next){
        u32 id;if(count>=128||wire_u32(j,token,&id))return -1;
        unsigned ordinal=MANAGED_COUNT;
        for(unsigned i=0;i<MANAGED_COUNT;i++)if(MANAGED_IDS[i]==id){ordinal=i;break;}
        if(ordinal==MANAGED_COUNT)return -1;
        ordinals[count++]=ordinal;
    }
    if(!bridge_ready())return 1;
    save_enter();u8 *s=(u8 *)(main_base+LIVE_SAVE+NATIVE_STATE_OFFSET);
    int status=las_state_validate(s,MANAGED_FP);
    if(!status)for(unsigned i=0;i<count;i++)las_state_check(s,MANAGED_FP,ordinals[i]);
    save_leave();return status?-1:0;
}
int native_bridge_deliver(const WireJson *j) {
    unsigned expected,receipt,item,count;
    u8 previous[32],next[32];
    int grant=wire_member(j,0,"grant");
    if(wire_u32(j,wire_member(j,0,"expected_cursor"),&expected)||
       wire_hash(j,wire_member(j,0,"expected_hash"),previous)||
       wire_hash(j,wire_member(j,0,"next_hash"),next)||
       wire_u32(j,wire_member(j,grant,"receipt_index"),&receipt)||receipt!=expected||
       wire_u32(j,wire_member(j,grant,"item_id"),&item)||
       wire_u32(j,wire_member(j,grant,"count"),&count)||count!=1)return -1;
    const NativeReward *reward=0;
    for(unsigned i=0;i<NATIVE_REWARD_COUNT;i++)if(NATIVE_REWARDS[i].id==item){reward=&NATIVE_REWARDS[i];break;}
    if(!reward||!wire_equal(j,wire_member(j,grant,"item_name"),reward->name)||
       !wire_equal(j,wire_member(j,grant,"item_key"),reward->key)||
       !wire_equal(j,wire_member(j,grant,"semantic"),reward->semantic))return -1;
    int index=wire_member(j,grant,"collectible_index"),dungeon=wire_member(j,grant,"dungeon");
    if(index<0||dungeon<0)return -1;
    if(reward->kind==5){
        unsigned ordinal;
        if(j->tokens[index].type!='n'||wire_u32(j,wire_member(j,grant,"ap_item_ordinal"),&ordinal)||ordinal>=reward->index_count)return -1;
    }else if(j->tokens[index].end-j->tokens[index].start!=2||
             j->text[j->tokens[index].start]!='-'||j->text[j->tokens[index].start+1]!='1')return -1;
    if(reward->kind==4){unsigned dn;if(wire_u32(j,dungeon,&dn)||dn!=(unsigned)reward->dungeon)return -1;}
    else if(j->tokens[dungeon].type!='n')return -1;
    if(!bridge_ready())return 1;
    save_enter();u8 *save=(u8 *)(main_base+LIVE_SAVE),*s=save+NATIVE_STATE_OFFSET;
    int status=las_state_prepare(s,MANAGED_FP,expected,previous,next);
    if(status==2){save_leave();return 0;}
    if(status){save_leave();return -1;}
    for(unsigned i=0;i<sizeof before_grant;i++)before_grant[i]=save[i];
    u32 before=*(u32 *)(save+0x5540);
    if(before>9999){save_leave();return -1;}
    save_transaction_active=1;
    if(reward->kind==8){
        event_cursor=expected;
        for(unsigned i=0;i<32;i++){event_previous[i]=previous[i];event_next[i]=next[i];}
        event_pending=1;
        if(!native_request_common(main_base,reward->event_entry)){
            event_pending=0;save_transaction_active=0;save_leave();return 1;
        }
        save_leave();return 0;
    }
    if(reward->kind==7){
        int spawned=native_spawn_zol(main_base,expected);
        status=spawned?las_state_commit(s,MANAGED_FP,expected,previous,next):-1;
        save_transaction_active=0;save_leave();return spawned?(status?-1:0):1;
    }
    reward_active=1;
    int applied=apply_reward(save,reward);
    reward_active=0;
    u32 after=*(u32 *)(save+0x5540);
    status=!applied?las_state_commit(s,MANAGED_FP,expected,previous,next):-1;
    if(status){
        for(unsigned i=0;i<sizeof before_grant;i++)save[i]=before_grant[i];
        debug("LAS_AP_BRIDGE reward failed; live snapshot restored\n");
    }else{
        log_value("LAS_AP_BRIDGE network receipt committed=",las_state_cursor(s));
        log_value("LAS_AP_BRIDGE rupees after=",after);
    }
    save_transaction_active=0;save_leave();return status?-1:0;
}
#endif
#if PROBE_MANAGED
static void managed_check(unsigned ordinal) {
    if(ordinal>=MANAGED_COUNT)return;
    u8 *save=(u8 *)(main_base+LIVE_SAVE);
    if(*(volatile u32 *)(main_base+0x1CC1390)!=256 ||
       *(volatile u64 *)(main_base+0x1CC1388)!=(u64)(save+0x5DC0))return;
    save_enter();u8 *state=save+NATIVE_STATE_OFFSET;
    int status=las_state_bind(state,MANAGED_FP);
    if(status>=0)status=las_state_check(state,MANAGED_FP,ordinal);
    save_leave();
    if(status)debug("LAS_AP_MANAGED incompatible saved state; check blocked\n");
    else log_value("LAS_AP_MANAGED persistent check=",MANAGED_IDS[ordinal]);
}
#endif
__attribute__((visibility("default")))
u64 las_has(u64 item,u64 count,u64 index,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7){
#if PROBE_MANAGED
    if(!reward_active&&count==1){
        for(unsigned i=0;i<MANAGED_SHELL_COUNT;i++)if(item==MANAGED_SHELLS[i].native && index==MANAGED_SHELLS[i].index){
            u8 *s=(u8 *)(main_base+LIVE_SAVE+NATIVE_STATE_OFFSET);
            save_enter();int valid=las_state_validate(s,MANAGED_FP);
            unsigned bit=MANAGED_SHELLS[i].ordinal;
            u64 owned=valid?0:!!(s[56+bit/8]&(1u<<(bit%8)));
            save_leave();return owned;
        }
    }
#endif
#if PROBE_UNDERWATER
    if(item==58 && (u64)__builtin_return_address(0)==main_base+0x8C45BC)return 0;
#endif
    return forward_has(item,count,index,a3,a4,a5,a6,a7);
}
__attribute__((visibility("default")))
u64 las_factory(u64 output,u64 room,u64 info,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7){
    /* Spawn descriptors always pass unchanged. The retired factory/pool
     * renderer is intentionally removed; visuals are selected by the NPC ctor. */
    return forward_factory(output,room,info,a3,a4,a5,a6,a7);
}
__attribute__((visibility("default")))
u64 las_world_npc(u64 component,u64 context,u64 name,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7){
#if NATIVE_WORLD_VISUALS
    if(context && name){
        /* Verified component-init context: actor shared_ptr at +0x18.
         * Real factory/actor/header identities are distinct from item indexes.
         * No descriptor, resource handle, refcount or string pool is changed.
         */
        u64 owner=*(const u64 *)(context+0x18);
        const u64 *span=(const u64 *)name;
        static const char stock[]="ItemSecretSeashell";
        if(owner && *(const u64 *)owner==main_base+0x1bc9408 &&
           *(const unsigned short *)(owner+0xa0)==0x87 &&
           *(const u8 *)(owner+0x2e8)==22 && *(const u32 *)(owner+0xc0)==3 &&
           span[0] && span[1]==sizeof stock-1 &&
           bytes_equal((const u8 *)span[0],(const u8 *)stock,sizeof stock-1)){
            unsigned index=*(const u32 *)(owner+0xbc);
            for(unsigned i=0;i<WORLD_VISUAL_COUNT;i++){
                if(WORLD_VISUALS[i].native==22 && WORLD_VISUALS[i].index==index){
                    name=(u64)&WORLD_VISUALS[i].name;
                    log_value("LAS_AP_WORLD shell index=",index);
                    log_value("LAS_AP_WORLD visual ordinal=",WORLD_VISUALS[i].ordinal);
                    break;
                }
            }
        }
    }
#endif
    extern u64 forward_world_npc(u64,u64,u64,u64,u64,u64,u64,u64);
    return forward_world_npc(component,context,name,a3,a4,a5,a6,a7);
}
__attribute__((visibility("default")))
u64 las_add(u64 item,u64 count,u64 index,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7) {
    additions++;
    log_value("LAS_AP_PROBE add item=",item);
    log_value("LAS_AP_PROBE add count=",count);
    log_value("LAS_AP_PROBE add index=",index);
#if PROBE_BRIDGE
    if((u32)index==0x4C420001u){if(item==6)deathlink_pending=0;return 0;}
    if((u32)index==0x4C420002u){if(item==6)hint_pending=0;return 0;}
    if((u32)index==0x4C420000u){
        if(item==6)finish_event_reward();
        return 0;
    }
#endif
#if PROBE_MANAGED
    if(!reward_active){
        for(unsigned i=0;i<MANAGED_SHELL_COUNT;i++)if(item==MANAGED_SHELLS[i].native && index==MANAGED_SHELLS[i].index){
            managed_check(MANAGED_SHELLS[i].ordinal);return 0;
        }
    }
    for(unsigned i=0;i<MANAGED_DIRECT_COUNT;i++)if(item==MANAGED_DIRECT[i][0]){
        managed_check(MANAGED_DIRECT[i][1]);return 0;
    }
    for(unsigned i=0;i<MANAGED_VISUAL_COUNT;i++)if(item==MANAGED_VISUAL_IDS[i]){
        debug("LAS_AP_MANAGED display-only inventory grant rejected\n");return 0;
    }
    if((u32)index>=0x4C410000u && (u32)index<0x4C420000u) {
        unsigned ordinal=(u32)index-0x4C410000u;
        if(item!=6 || ordinal>=MANAGED_COUNT) {
            debug("LAS_AP_MANAGED invalid marker/item rejected; no inventory effect\n");
            return 0;
        }
        managed_check(ordinal);
        return 0;
    }
#endif
#if PROBE_REWARD_TEST & 2
    if((u32)index==0x4C415300u) {
        debug("LAS_AP_PROBE CHECK " PROBE_CHECK_LABEL "; original inventory reward suppressed\n");
        return 0;
    }
#endif
    return forward_add(item,count,index,a3,a4,a5,a6,a7);
}
__attribute__((visibility("default")))
u64 las_frame(u64 a0,u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7) {
    u64 result=forward_frame(a0,a1,a2,a3,a4,a5,a6,a7);
    frames++;
#if PROBE_BRIDGE
    u64 bridge_manager=*(volatile u64 *)(main_base+GAME_MANAGER);
    if(bridge_manager && *(volatile u64 *)(bridge_manager+0x4b8))player_stable_frames++;
    else player_stable_frames=0;
    if(player_stable_frames>=60){
        u8 *save=(u8 *)(main_base+LIVE_SAVE);
        // A genuinely new slot must be able to receive AP starting inventory
        // before its first randomized check. Never bind an already completed
        // vanilla save merely because its ending flag is present.
        if((save[0x5544]||save[0x5545]) &&
           !(save[0x5DC0+258/8]&(1u<<(258%8))) &&
           !(save[0x5DC0+NATIVE_VICTORY_FLAG/8]&(1u<<(NATIVE_VICTORY_FLAG%8))) &&
           *(volatile u32 *)(main_base+0x1CC1390)==256 &&
           *(volatile u64 *)(main_base+0x1CC1388)==(u64)(save+0x5DC0) &&
           *(volatile u64 *)(main_base+0x1CC1368)==(u64)(save+0x54C0)){
            save_enter();las_state_bind(save+NATIVE_STATE_OFFSET,MANAGED_FP);save_leave();
        }
    }
    if(event_pending){
        u8 *save=(u8 *)(main_base+LIVE_SAVE),*s=save+NATIVE_STATE_OFFSET;
        // Loading another snapshot aborts the pending event, never writes its
        // receipt into that snapshot. A fatal trap can interrupt its own flow.
        if(las_state_prepare(s,MANAGED_FP,event_cursor,event_previous,event_next)){
            event_pending=0;save_transaction_active=0;
        }else if(!save[0x5544]&&!save[0x5545])finish_event_reward();
    }
    if(deathlink_pending&&!((u8 *)(main_base+LIVE_SAVE))[0x5544]&&!((u8 *)(main_base+LIVE_SAVE))[0x5545])deathlink_pending=0;
    extern void bridge_transport_tick(void);
    bridge_transport_tick();
#endif
#if PROBE_RECEIPT
    receipt_tick();
#endif
#if PROBE_NETWORK
    extern void network_probe_tick(void);
    network_probe_tick();
#endif
#if PROBE_REWARD_TEST & 1
    u64 manager=*(volatile u64 *)(main_base+GAME_MANAGER);
    u64 player=manager ? *(volatile u64 *)(manager+0x4b8) : 0;
    if(player) player_stable_frames++; else player_stable_frames=0;
    // Isolated diagnostic only: demonstrate one known reward through the real game
    // entry point. Not AP delivery; no receipt/persistence capability is claimed.
    if(!gave_test_reward && player_stable_frames==360) {
        gave_test_reward=1;
        u32 before=*(volatile u32 *)(main_base+LIVE_SAVE+0x5540);
        ((Call8)(main_base+0x7E18B0))(105,1,(u64)-1,0,0,0,0,0);
        u32 after=*(volatile u32 *)(main_base+LIVE_SAVE+0x5540);
        log_value("LAS_AP_PROBE TEST rupees before=",before);
        log_value("LAS_AP_PROBE TEST rupees after=",after);
        debug("LAS_AP_PROBE TEST reward complete; not an AP receipt\n");
    }
#endif
    if(frames==1 || frames%600==0) {
        log_value("LAS_AP_PROBE frame=",frames);
        u64 gm=*(volatile u64 *)(main_base+GAME_MANAGER);
        log_value("LAS_AP_PROBE player=",gm ? *(volatile u64 *)(gm+0x4b8) : 0);
        log_value("LAS_AP_PROBE save=",main_base+LIVE_SAVE);
    }
    return result;
}
__attribute__((visibility("default")))
void las_init(void) {
#if PROBE_BRIDGE
    debug("LAS_AP native runtime initialized; network delivery enabled\n");
#elif PROBE_MANAGED
    debug("LAS_AP_MANAGED generated check markers enabled; AP delivery not yet enabled\n");
#elif PROBE_RECEIPT
    debug("LAS_AP_RECEIPT copied-save persistence diagnostic enabled; one saved 50-rupee receipt\n");
#elif PROBE_REWARD_TEST & 1
    debug("LAS_AP_PROBE isolated reward test enabled: one 50-rupee diagnostic grant\n");
#elif PROBE_REWARD_TEST & 2
    debug("LAS_AP_PROBE isolated chest test enabled; no automatic reward grant\n");
#else
    debug("LAS_AP_PROBE module init; no rewards or save data are changed\n");
#endif
    MemInfo m; u64 address=0; unsigned found=0;
    // Match a full offline-generated profile, not a hard-coded ASLR address.
    while(address < (1ull<<39)) {
        if(query(&m,address) || !m.size || m.addr+m.size<=address) break;
        if(m.perm==5 && m.size>=TEXT_SIZE) {
            const u8 *base=(const u8 *)m.addr;
            log_value("LAS_AP_PROBE candidate=",m.addr);
            log_value("LAS_AP_PROBE candidate type=",m.type);
            log_value("LAS_AP_PROBE signature=",bytes_equal(base,MAIN_SIGNATURE,sizeof MAIN_SIGNATURE));
            log_value("LAS_AP_PROBE add gate=",bytes_equal(base+ADD_OFFSET,ADD_GATE,sizeof ADD_GATE));
            log_value("LAS_AP_PROBE frame gate=",bytes_equal(base+FRAME_OFFSET,FRAME_GATE,sizeof FRAME_GATE));
            if(bytes_equal(base,MAIN_SIGNATURE,sizeof MAIN_SIGNATURE) &&
               bytes_equal(base+ADD_OFFSET,ADD_GATE,sizeof ADD_GATE) &&
               bytes_equal(base+FRAME_OFFSET,FRAME_GATE,sizeof FRAME_GATE) &&
               bytes_equal(base+HAS_OFFSET,HAS_GATE,sizeof HAS_GATE) &&
               bytes_equal(base+FACTORY_OFFSET,FACTORY_GATE,sizeof FACTORY_GATE)) {
                main_base=m.addr;found++;
            }
        }
        address=m.addr+m.size;
    }
    if(found!=1) {debug("LAS_AP_PROBE ERROR: exact LAS executable profile not found\n");return;}
    original_add_tail=main_base+ADD_OFFSET+16;
    original_frame_tail=main_base+FRAME_OFFSET+16;
    original_has_tail=main_base+HAS_OFFSET+16;
    original_factory_tail=main_base+FACTORY_OFFSET+16;
#if NATIVE_WORLD_VISUALS
    if(!bytes_equal((const u8 *)(main_base+WORLD_NPC_OFFSET),WORLD_NPC_GATE,sizeof WORLD_NPC_GATE)){
        debug("LAS_AP_WORLD NPC constructor gate mismatch; installation refused\n");return;
    }
    original_world_npc_tail=main_base+WORLD_NPC_OFFSET+16;
    *(volatile u64 *)(main_base+MAILBOX+32)=(u64)&las_world_npc;
#endif
    *(volatile u64 *)(main_base+MAILBOX)=(u64)&las_add;
    *(volatile u64 *)(main_base+MAILBOX+8)=(u64)&las_frame;
    *(volatile u64 *)(main_base+MAILBOX+16)=(u64)&las_has;
    *(volatile u64 *)(main_base+MAILBOX+24)=(u64)&las_factory;
#if PROBE_SAVE
    original_memcpy=*(CopyFn *)(main_base+MEMCPY_GOT);
    original_memmove=*(CopyFn *)(main_base+MEMMOVE_GOT);
    if(original_memcpy && original_memmove) {
        *(CopyFn *)(main_base+MEMCPY_GOT)=las_memcpy;
        *(CopyFn *)(main_base+MEMMOVE_GOT)=las_memmove;
        debug("LAS_AP_SAVE copy observation installed; copied bytes remain unchanged\n");
    }
    original_write_file=*(WriteFn *)(main_base+WRITE_FILE_GOT);
    if(original_write_file) {
        *(WriteFn *)(main_base+WRITE_FILE_GOT)=las_write_file;
        debug("LAS_AP_SAVE write observation installed; file writes remain unchanged\n");
    }
#endif
    __asm__ volatile("dmb ish" ::: "memory");
    log_value("LAS_AP_PROBE installed; main=",main_base);
}
__attribute__((visibility("default"))) void _init(void) { las_init(); }
