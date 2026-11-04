/* Standalone LAS 1.0.0 indexed-source ownership. MIT.
 * No networking, AP manifest, receipt state or injected world graphics.
 */
#include "profile.h"
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef struct {u64 addr,size;u32 type,attr,perm,ipc,device,pad;} MemInfo;
u64 original_add_tail, original_has_tail;
static u64 main_base;
static unsigned reward_active;
extern u64 forward_add(u64,u64,u64,u64,u64,u64,u64,u64);
extern u64 forward_has(u64,u64,u64,u64,u64,u64,u64,u64);
static int equal(const u8 *a,const u8 *b,unsigned n){while(n--)if(*a++!=*b++)return 0;return 1;}
static u32 query(MemInfo *m,u64 addr){
    register u64 x0 __asm__("x0")=(u64)m;
    register u64 x1 __asm__("x1");
    register u64 x2 __asm__("x2")=addr;
    __asm__ volatile("svc #6":"+r"(x0),"=r"(x1),"+r"(x2)::"x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    return (u32)x0;
}
static u8 *flags(void){
    u64 p=*(volatile u64 *)(main_base+0x1CC1388ull);
    u64 size=*(volatile u64 *)(main_base+0x1CC1390ull);
    return p==main_base+0x1CBB220ull+0x5DC0 && size==256 ? (u8 *)p : 0;
}
__attribute__((visibility("default")))
u64 las_add(u64 item,u64 count,u64 index,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7){
    /* Tagged real collectible grants bypass source ownership interception. */
    if((item==22 || item==58) && ((u32)index & 0xFFFF0000u)==0x53470000u){
        unsigned actual=(u32)index & 0xFFFFu;
        if(actual>=(item==22?50u:32u))return 0;
        reward_active++;
        u64 result=forward_add(item,count,actual,a3,a4,a5,a6,a7);
        reward_active--;
        return result;
    }
    for(unsigned i=0;i<SOURCE_COUNT;i++){
        const Source *s=&SOURCES[i];
        if(item==s->item && (s->index<0 || index==(u64)s->index)){
            u8 *p=flags();
            if(!p)return s->pending>=0 ? 0 : forward_add(item,count,index,a3,a4,a5,a6,a7);
            /* Shop dummy grants queue an event reward at the next PlayerStart.
             * Indexed shell grants are replaced by ItemCommon itself. */
            if(s->pending>=0)__atomic_fetch_or(p+s->pending/8,1u<<(s->pending%8),__ATOMIC_RELAXED);
            return 0;
        }
    }
    return forward_add(item,count,index,a3,a4,a5,a6,a7);
}
__attribute__((visibility("default")))
u64 las_has(u64 item,u64 count,u64 index,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7){
    if(!reward_active && count==1)for(unsigned i=0;i<SOURCE_COUNT;i++){
        const Source *s=&SOURCES[i];
        if(item==s->item && (s->index<0 || index==(u64)s->index)){
            u8 *p=flags();
            if(p)return !!(p[s->flag/8] & (1u<<(s->flag%8)));
        }
    }
    return forward_has(item,count,index,a3,a4,a5,a6,a7);
}
__attribute__((visibility("default"))) void _init(void){
    MemInfo m;u64 addr=0;unsigned found=0;
    while(addr<(1ull<<39)){
        if(query(&m,addr)||!m.size||m.addr+m.size<=addr)break;
        if(m.perm==5 && m.size>=TEXT_SIZE){
            const u8 *b=(const u8 *)m.addr;
            if(equal(b,MAIN_SIGNATURE,sizeof MAIN_SIGNATURE)&&equal(b+ADD_OFFSET,ADD_GATE,sizeof ADD_GATE)&&equal(b+HAS_OFFSET,HAS_GATE,sizeof HAS_GATE)){main_base=m.addr;found++;}
        }
        addr=m.addr+m.size;
    }
    if(found!=1)return;
    original_add_tail=main_base+ADD_OFFSET+16;
    original_has_tail=main_base+HAS_OFFSET+16;
    *(volatile u64 *)(main_base+MAILBOX)=(u64)&las_add;
    *(volatile u64 *)(main_base+MAILBOX+8)=(u64)&las_has;
    __asm__ volatile("dmb ish":::"memory");
}
