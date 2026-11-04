/* Original native adapters for inspected LAS 1.0.0 game APIs. MIT.
 * Call order/arguments were checked against main+0xDAAF6C (Common event request)
 * and the actor factory. No recompilation runtime is linked. */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef u64 (*Call8)(u64,u64,u64,u64,u64,u64,u64,u64);
static u64 call(u64 base,u64 offset,u64 a,u64 b,u64 c){
    return ((Call8)(base+offset))(a,b,c,0,0,0,0,0);
}
static void release(u64 base,u64 control){if(control)call(base,0xBAE080,control,0,0);}
int native_request_common(u64 base,const char *entry){
    u64 resource_manager=*(u64 *)(base+0x1CC6DB8),manager=*(u64 *)(base+0x1CB24D8);
    if(!resource_manager||!manager)return 0;
    u64 scratch[32] __attribute__((aligned(16)));for(unsigned i=0;i<32;i++)scratch[i]=0;
    u8 *s=(u8 *)scratch;u64 length=0;while(entry[length]&&length<64)length++;
    if(!length||length==64)return 0;
    scratch[0]=base+0x16C2CA8;scratch[1]=19; // event/Common.bfevfl string view
    call(base,0xFBBD80,(u64)(s+0x60),resource_manager,(u64)s);
    if(scratch[12])call(base,0x3DC20,scratch[12],0,0);
    call(base,0x3D9F0,(u64)(s+0x30),(u64)(s+0x60),0);
    int accepted=0;
    if(scratch[6]){
        scratch[2]=(u64)entry;scratch[3]=length;
        call(base,0x80C290,(u64)(s+0x20),(u64)(s+0x30),(u64)(s+0x10));
        if(scratch[4]){
            call(base,0x80DB00,scratch[4],0,0);
            call(base,0x81F2E0,(u64)(s+0x50),manager,(u64)(s+0x20));
            accepted=scratch[10]!=0;
        }
    }
    const unsigned controls[]={11,5,7,13,15};
    for(unsigned i=0;i<5;i++)release(base,scratch[controls[i]]);
    return accepted;
}

extern int native_pool_index(u64,const char *);
static int empty_parameter_index(u64 base){return native_pool_index(base,"");}

int native_spawn_zol(u64 base,u32 receipt){
    u64 gm=*(u64 *)(base+0x1C97188),player=gm?*(u64 *)(gm+0x4B8):0;
    u64 collision=player?*(u64 *)(player+0x80):0;
    if(!gm||!collision||*(u64 *)collision!=base+0x1C501F0)return 0;
    int empty=empty_parameter_index(base);if(empty<0)return 0;
    u64 scene[2]={0,0};call(base,0x1B730,(u64)scene,*(u64 *)(gm+0x4A8),0);
    if(!scene[0]){release(base,scene[1]);return 0;}
    u64 holder=*(u64 *)(scene[0]+0x228);
    u64 room[2]={holder?*(u64 *)(holder+0x1B8):0,holder?*(u64 *)(holder+0x1C0):0};
    int spawned=0;
    if(room[0]&&room[1]){
        u8 info[0x1C0] __attribute__((aligned(16)));for(unsigned i=0;i<sizeof info;i++)info[i]=0;
        *(u64 *)info=0x4C41505A00000000ull|receipt;
        *(unsigned short *)(info+8)=0x1B; // EnemyZolGreen, verified against original room data
        *(u32 *)(info+12)=*(u32 *)(player+0xB0);
        for(unsigned i=0;i<8;i++){*(u32 *)(info+0x10+i*8)=(u32)empty;info[0x14+i*8]=5;}
        const float *position=(const float *)(collision+0x80);float *transform=(float *)(info+0x180);
        transform[0]=position[0];transform[1]=position[1]+0.5f;transform[2]=position[2];
        transform[7]=1.0f;transform[8]=transform[9]=transform[10]=1.0f;
        u64 actor[2]={0,0};call(base,0x8F5EA0,(u64)actor,(u64)room,(u64)info);
        spawned=actor[0]!=0;release(base,actor[1]);
    }
    release(base,scene[1]);return spawned;
}
