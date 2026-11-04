/* Original string-pool adapter for native actor parameters. MIT.
 * libc++ layout checked against the game's pool reader and LASRecomp's MIT
 * adapter. Existing entries and indexes are preserved when reserving space. */
typedef unsigned long long u64;
typedef unsigned char u8;
typedef u64 (*Call8)(u64,u64,u64,u64,u64,u64,u64,u64);
static unsigned pool_lock;
static int same(const char *a,const char *b,unsigned length){
    for(unsigned i=0;i<length;i++)if(a[i]!=b[i])return 0;return 1;
}
int native_pool_index(u64 base,const char *text){
    unsigned length=0;while(text[length]&&length<256)length++;
    if(length==256)return -1;
    ((Call8)(base+0x1D510))(0,0,0,0,0,0,0,0);
    while(__atomic_exchange_n(&pool_lock,1,__ATOMIC_ACQUIRE)){}
    u64 *v=(u64 *)(base+0x1CAB2D0);int result=-1;
    if(v[1]<v[0]||v[2]<v[1]||(v[1]-v[0])%32||v[1]-v[0]>512*32)goto done;
    unsigned count=(unsigned)((v[1]-v[0])/32);
    for(unsigned i=0;i<count;i++){
        u8 *p=(u8 *)(v[0]+i*32);
        unsigned n=(p[0]&1)?(unsigned)*(u64 *)(p+8):p[0]>>1;
        const char *s=(p[0]&1)?(const char *)*(u64 *)(p+16):(const char *)(p+1);
        if(n==length&&same(s,text,length)){result=(int)i;goto done;}
    }
    if(count==512)goto done;
    if(v[2]-v[1]<32){
        u64 memory=((Call8)(base+0x1431170))(512*32,0,0,0,0,0,0,0);
        if(!memory)goto done;
        for(unsigned i=0;i<count*32;i++)((u8 *)memory)[i]=((u8 *)v[0])[i];
        // Old vector storage is retained: no foreign allocator/free assumption.
        v[0]=memory;v[1]=memory+count*32;v[2]=memory+512*32;
    }
    u8 *entry=(u8 *)v[1];for(unsigned i=0;i<32;i++)entry[i]=0;
    if(length<23){entry[0]=(u8)(length*2);for(unsigned i=0;i<length;i++)entry[i+1]=(u8)text[i];}
    else{
        unsigned capacity=(length+16)&~15u;
        u64 buffer=((Call8)(base+0x1431170))(capacity,0,0,0,0,0,0,0);
        if(!buffer)goto done;
        for(unsigned i=0;i<=length;i++)((u8 *)buffer)[i]=(u8)text[i];
        *(u64 *)entry=capacity|1u;*(u64 *)(entry+8)=length;*(u64 *)(entry+16)=buffer;
    }
    *(u64 *)(entry+24)=1ull<<40;v[1]+=32;result=(int)count;
done:
    __atomic_store_n(&pool_lock,0,__ATOMIC_RELEASE);return result;
}
