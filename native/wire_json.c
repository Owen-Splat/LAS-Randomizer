/* Bounded JSON reader for native bridge commands. Original implementation, MIT. */
typedef unsigned int u32;
#include "wire_json.h"
typedef WireToken Token;
typedef WireJson Json;
static void space(Json *j){while(j->pos<j->size && (j->text[j->pos]==' '||j->text[j->pos]=='\t'||j->text[j->pos]=='\r'||j->text[j->pos]=='\n'))j->pos++;}
static int digit(char c){return c>='0'&&c<='9';}
static int hexdigit(char c){return digit(c)||(c>='a'&&c<='f')||(c>='A'&&c<='F');}
static int value(Json *,int);
static int string(Json *j){
    j->pos++;
    while(j->pos<j->size){
        unsigned char c=j->text[j->pos++];
        if(c=='"')return 1;
        if(c<32)return 0;
        if(c=='\\'){
            if(j->pos==j->size)return 0;
            c=j->text[j->pos++];
            if(c=='u'){for(int i=0;i<4;i++)if(j->pos==j->size||!hexdigit(j->text[j->pos++]))return 0;}
            else if(c!='"'&&c!='\\'&&c!='/'&&c!='b'&&c!='f'&&c!='n'&&c!='r'&&c!='t')return 0;
        }
    }
    return 0;
}
static int literal(Json *j,const char *s){while(*s)if(j->pos==j->size||j->text[j->pos++]!=*s++)return 0;return 1;}
static int value(Json *j,int depth){
    space(j);if(depth>16||j->pos==j->size||j->used==256)return -1;
    int n=j->used++;Token *t=&j->tokens[n];t->start=j->pos;t->count=0;
    char c=j->text[j->pos];t->type=c;
    if(c=='{'||c=='['){
        j->pos++;space(j);char end=c=='{'?'}':']';
        if(j->pos<j->size && j->text[j->pos]==end)j->pos++;
        else for(;;){
            if(c=='{'){
                space(j);if(j->pos==j->size||j->text[j->pos]!='"'||value(j,depth+1)<0)return -1;
                space(j);if(j->pos==j->size||j->text[j->pos++]!=':')return -1;
            }
            if(value(j,depth+1)<0)return -1;t->count++;space(j);
            if(j->pos==j->size)return -1;
            char sep=j->text[j->pos++];if(sep==end)break;if(sep!=',')return -1;
        }
    }else if(c=='"'){if(!string(j))return -1;}
    else if(c=='t'){if(!literal(j,"true"))return -1;}
    else if(c=='f'){if(!literal(j,"false"))return -1;}
    else if(c=='n'){if(!literal(j,"null"))return -1;}
    else{
        t->type='0';if(c=='-')j->pos++;
        if(j->pos==j->size||!digit(j->text[j->pos]))return -1;
        if(j->text[j->pos++]!='0')while(j->pos<j->size&&digit(j->text[j->pos]))j->pos++;
        if(j->pos<j->size&&j->text[j->pos]=='.'){
            j->pos++;int start=j->pos;while(j->pos<j->size&&digit(j->text[j->pos]))j->pos++;if(start==j->pos)return -1;
        }
        if(j->pos<j->size&&(j->text[j->pos]=='e'||j->text[j->pos]=='E')){
            j->pos++;if(j->pos<j->size&&(j->text[j->pos]=='+'||j->text[j->pos]=='-'))j->pos++;
            int start=j->pos;while(j->pos<j->size&&digit(j->text[j->pos]))j->pos++;if(start==j->pos)return -1;
        }
    }
    t->end=j->pos;t->next=j->used;return n;
}
int wire_parse(Json *j,const char *text,int size){
    if(size<1||size>65535)return -1;
    j->text=text;j->size=size;j->pos=j->used=0;
    if(value(j,0)!=0)return -1;space(j);return j->pos==size?0:-1;
}
int wire_equal(const Json *j,int n,const char *text){
    if(n<0||n>=j->used||j->tokens[n].type!='"')return 0;
    int p=j->tokens[n].start+1,end=j->tokens[n].end-1;
    while(p<end&&*text)if(j->text[p++]!=*text++)return 0;
    return p==end&&!*text;
}
int wire_member(const Json *j,int object,const char *name){
    if(object<0||object>=j->used||j->tokens[object].type!='{')return -1;
    int result=-1;
    for(int key=object+1;key<j->tokens[object].next;){
        int item=key+1;
        if(wire_equal(j,key,name)){if(result>=0)return -2;result=item;}
        key=j->tokens[item].next;
    }
    return result;
}
int wire_u32(const Json *j,int n,u32 *out){
    if(n<0||n>=j->used||j->tokens[n].type!='0')return -1;
    u32 v=0;for(int p=j->tokens[n].start;p<j->tokens[n].end;p++){
        char c=j->text[p];if(!digit(c)||v>429496729u||(v==429496729u&&c>'5'))return -1;
        v=v*10+(u32)(c-'0');
    }*out=v;return 0;
}
int wire_hash(const Json *j,int n,unsigned char out[32]){
    if(n<0||n>=j->used||j->tokens[n].type!='"'||j->tokens[n].end-j->tokens[n].start!=66)return -1;
    for(int i=0;i<32;i++){
        unsigned v=0;for(int k=0;k<2;k++){
            char c=j->text[j->tokens[n].start+1+2*i+k];if(!hexdigit(c))return -1;
            unsigned d=digit(c)?c-'0':c>='a'?c-'a'+10:c-'A'+10;v=v*16+d;
        }out[i]=(unsigned char)v;
    }return 0;
}
