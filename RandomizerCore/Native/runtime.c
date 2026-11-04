/* Standalone LAS 1.0.0 indexed-source ownership. MIT.
 * No networking, AP manifest or receipt state.
 */
#include "profile.h"
typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned char uint8;
typedef struct {uint64 address,size;uint32 type,attributes,permissions,ipc_count,device_count,padding;} MemoryInfo;
uint64 original_add_tail, original_has_tail;
uint64 original_world_npc_tail;
static uint64 main_base;
static unsigned real_reward_depth;
extern uint64 forward_add(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64);
extern uint64 forward_has(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64);
static int bytes_equal(const uint8 *left_bytes,const uint8 *right_bytes,unsigned byte_count){while(byte_count--)if(*left_bytes++!=*right_bytes++)return 0;return 1;}
static uint32 query_memory(MemoryInfo *memory_info,uint64 address){
    register uint64 x0 __asm__("x0")=(uint64)memory_info;
    register uint64 x1 __asm__("x1");
    register uint64 x2 __asm__("x2")=address;
    __asm__ volatile("svc #6":"+r"(x0),"=r"(x1),"+r"(x2)::"x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    return (uint32)x0;
}
static uint8 *save_flags(void){
    uint64 flag_bytes=*(volatile uint64 *)(main_base+0x1CC1388ull);
    uint64 size=*(volatile uint64 *)(main_base+0x1CC1390ull);
    return flag_bytes==main_base+0x1CBB220ull+0x5DC0 && size==256 ? (uint8 *)flag_bytes : 0;
}
__attribute__((visibility("default")))
uint64 las_world_npc(uint64 component,uint64 component_context,uint64 npc_name,uint64 argument_3,uint64 argument_4,uint64 argument_5,uint64 argument_6,uint64 argument_7){
#if WORLD_VISUAL_COUNT
    if(component_context && npc_name){
        /* The owning actor is stored at offset 0x18 in this context. */
        uint64 actor_address=*(const uint64 *)(component_context+0x18);
        const uint64 *name_span=(const uint64 *)npc_name;
        static const char original_shell_name[]="ItemSecretSeashell";
        if(actor_address && *(const uint64 *)actor_address==main_base+0x1bc9408 &&
           *(const unsigned short *)(actor_address+0xa0)==0x87 &&
           *(const uint8 *)(actor_address+0x2e8)==22 && *(const uint32 *)(actor_address+0xc0)==3 &&
           name_span[0] && name_span[1]==sizeof original_shell_name-1 && bytes_equal((const uint8 *)name_span[0],(const uint8 *)original_shell_name,sizeof original_shell_name-1)){
            unsigned index=*(const uint32 *)(actor_address+0xbc);
            for(unsigned source_index=0;source_index<WORLD_VISUAL_COUNT;source_index++)if(WORLD_VISUALS[source_index].item==22 && WORLD_VISUALS[source_index].index==index){
                npc_name=(uint64)&WORLD_VISUALS[source_index].name;break;
            }
        }
    }
#endif
    extern uint64 forward_world_npc(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64);
    return forward_world_npc(component,component_context,npc_name,argument_3,argument_4,argument_5,argument_6,argument_7);
}
__attribute__((visibility("default")))
uint64 las_add(uint64 item,uint64 count,uint64 index,uint64 argument_3,uint64 argument_4,uint64 argument_5,uint64 argument_6,uint64 argument_7){
    /* A real shell or heart-piece reward must reach the normal inventory code. */
    if((item==22 || item==58) && ((uint32)index & 0xFFFF0000u)==0x53470000u){
        unsigned collectible_index=(uint32)index & 0xFFFFu;
        if(collectible_index>=(item==22?50u:32u))return 0;
        real_reward_depth++;
        uint64 result=forward_add(item,count,collectible_index,argument_3,argument_4,argument_5,argument_6,argument_7);
        real_reward_depth--;
        return result;
    }
    for(unsigned source_index=0;source_index<SOURCE_COUNT;source_index++){
        const Source *source=&SOURCES[source_index];
        if(item==source->item && (source->index<0 || index==(uint64)source->index)){
            uint8 *flag_bytes=save_flags();
            if(!flag_bytes)return source->pending>=0 ? 0 : forward_add(item,count,index,argument_3,argument_4,argument_5,argument_6,argument_7);
            /* Shop dummy grants queue an event reward at the next PlayerStart.
             * Indexed shell grants are replaced by ItemCommon itself. */
            if(source->pending>=0)__atomic_fetch_or(flag_bytes+source->pending/8,1u<<(source->pending%8),__ATOMIC_RELAXED);
            return 0;
        }
    }
    return forward_add(item,count,index,argument_3,argument_4,argument_5,argument_6,argument_7);
}
__attribute__((visibility("default")))
uint64 las_has(uint64 item,uint64 count,uint64 index,uint64 argument_3,uint64 argument_4,uint64 argument_5,uint64 argument_6,uint64 argument_7){
    /* Source completion is separate from the number of items received. */
    if(!real_reward_depth && count==1)for(unsigned source_index=0;source_index<SOURCE_COUNT;source_index++){
        const Source *source=&SOURCES[source_index];
        if(item==source->item && (source->index<0 || index==(uint64)source->index)){
            uint8 *flag_bytes=save_flags();
            if(flag_bytes)return !!(flag_bytes[source->flag/8] & (1u<<(source->flag%8)));
        }
    }
    return forward_has(item,count,index,argument_3,argument_4,argument_5,argument_6,argument_7);
}
__attribute__((visibility("default"))) void _init(void){
    /* Find exactly one matching game region before enabling any hooks. */
    MemoryInfo memory_info;uint64 address=0;unsigned matching_regions=0;
    while(address<(1ull<<39)){
        if(query_memory(&memory_info,address)||!memory_info.size||memory_info.address+memory_info.size<=address)break;
        if(memory_info.permissions==5 && memory_info.size>=TEXT_SIZE){
            const uint8 *right_bytes=(const uint8 *)memory_info.address;
            if(bytes_equal(right_bytes,MAIN_SIGNATURE,sizeof MAIN_SIGNATURE)&&bytes_equal(right_bytes+ADD_OFFSET,ADD_GATE,sizeof ADD_GATE)&&bytes_equal(right_bytes+HAS_OFFSET,HAS_GATE,sizeof HAS_GATE)){main_base=memory_info.address;matching_regions++;}
        }
        address=memory_info.address+memory_info.size;
    }
    if(matching_regions!=1)return;
    original_add_tail=main_base+ADD_OFFSET+16;
    original_has_tail=main_base+HAS_OFFSET+16;
#if WORLD_VISUAL_COUNT
    if(!bytes_equal((const uint8 *)(main_base+WORLD_NPC_OFFSET),WORLD_NPC_GATE,sizeof WORLD_NPC_GATE))return;
    original_world_npc_tail=main_base+WORLD_NPC_OFFSET+16;
    *(volatile uint64 *)(main_base+MAILBOX+16)=(uint64)&las_world_npc;
#endif
    *(volatile uint64 *)(main_base+MAILBOX)=(uint64)&las_add;
    *(volatile uint64 *)(main_base+MAILBOX+8)=(uint64)&las_has;
    /* Make the hook addresses visible before the game uses them. */
    __asm__ volatile("dmb ish":::"memory");
}
