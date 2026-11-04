/* Compact native receipt/check state. MIT. Game-save serialization is the adapter's responsibility. */
typedef unsigned char u8;
typedef unsigned int u32;
#include "generated_profile.h"
#define SIZE NATIVE_STATE_SIZE
static const u8 empty_hash[32]={0x4f,0x53,0xcd,0xa1,0x8c,0x2b,0xaa,0x0c,0x03,0x54,0xbb,0x5f,0x9a,0x3e,0xcb,0xe5,0xed,0x12,0xab,0x4d,0x8e,0x11,0xba,0x87,0x3c,0x2f,0x11,0x16,0x12,0x02,0xb9,0x45};
static int equal(const u8 *a,const u8 *b,unsigned n) {unsigned d=0;for(unsigned i=0;i<n;i++)d|=a[i]^b[i];return !d;}
u32 las_state_cursor(const u8 *s) {return (u32)s[20]|(u32)s[21]<<8|(u32)s[22]<<16|(u32)s[23]<<24;}
int las_state_validate(const u8 *s,const u8 *fingerprint) {
    if(s[0]!='A'||s[1]!='P'||s[2]!=NATIVE_STATE_VERSION||s[3])return -1;
    for(unsigned i=56+(NATIVE_CHECK_LIMIT+7)/8;i<SIZE;i++)if(s[i])return -1;
#if NATIVE_CHECK_LIMIT % 8
    if(s[56+NATIVE_CHECK_LIMIT/8]&~((1u<<(NATIVE_CHECK_LIMIT%8))-1))return -1;
#endif
    if(!las_state_cursor(s) && !equal(s+24,empty_hash,32))return -6;
    return equal(s+4,fingerprint,16)?0:-2;
}
int las_state_bind(u8 *s,const u8 *fingerprint) {
    unsigned any=0;for(unsigned i=0;i<SIZE;i++)any|=s[i];
    if(any)return las_state_validate(s,fingerprint);
    s[0]='A';s[1]='P';s[2]=NATIVE_STATE_VERSION;
    for(unsigned i=0;i<16;i++)s[4+i]=fingerprint[i];
    for(unsigned i=0;i<32;i++)s[24+i]=empty_hash[i];
    return 1;
}
int las_state_prepare(const u8 *s,const u8 *fp,u32 expected,const u8 *previous,const u8 *next) {
    int valid=las_state_validate(s,fp);if(valid)return valid;
    u32 cursor=las_state_cursor(s);
    if(expected!=0xffffffffu && cursor==expected+1 && equal(s+24,next,32))return 2;
    if(cursor!=expected || cursor==0xffffffffu)return -3;
    if(!equal(s+24,previous,32))return -4;
    return 0;
}
int las_state_commit(u8 *s,const u8 *fp,u32 expected,const u8 *previous,const u8 *next) {
    int status=las_state_prepare(s,fp,expected,previous,next);if(status)return status;
    u32 cursor=expected+1;
    for(unsigned i=0;i<4;i++)s[20+i]=(u8)(cursor>>(i*8));
    for(unsigned i=0;i<32;i++)s[24+i]=next[i];
    return 0;
}
int las_state_check(u8 *s,const u8 *fp,unsigned ordinal) {
    int valid=las_state_validate(s,fp);if(valid)return valid;
    if(ordinal>=NATIVE_CHECK_LIMIT)return -5;
    s[56+ordinal/8]|=(u8)(1u<<(ordinal%8));return 0;
}
