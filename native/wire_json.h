/* Original implementation, MIT. ASCII command keys use literal comparison. */
typedef struct {int start,end,next,count;char type;} WireToken;
typedef struct {const char *text;int size,pos,used;WireToken tokens[256];} WireJson;
int wire_parse(WireJson *,const char *,int);
int wire_equal(const WireJson *,int,const char *);
int wire_member(const WireJson *,int,const char *);
int wire_u32(const WireJson *,int,unsigned int *);
int wire_hash(const WireJson *,int,unsigned char[32]);
