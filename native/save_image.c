/* LAS save checksums, matching the inspected main+0xDFAD00 implementation. MIT. */
typedef unsigned char u8;
typedef unsigned int u32;
static void put32(u8 *p,u32 n){for(unsigned i=0;i<4;i++)p[i]=(u8)(n>>(8*i));}
static u32 crc(const u8 *p,unsigned size,const u32 *table){
    u32 value=0xEDB88320u;
    for(unsigned i=0;i<size;i++)value=table[(value^p[i])&255]^(value>>8);
    return value;
}
void las_image_crc(u8 *image,const u32 *table){
    put32(image+4,0);put32(image+4,crc(image,0xE0,table));
    put32(image+0x5EC4,0);put32(image+0x5EC4,crc(image+0xE0,0x5E00,table));
}
