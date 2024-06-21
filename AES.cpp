#include <iostream>
#include<string.h>
class AES
{unsigned char F1[256] =
 {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16},RC[10]={1,2,4,8,0x10,0x20,0x40,0x80,0x1b,0x36};
unsigned char F1i[255],* i2as=(unsigned char*) malloc(sizeof(char )*255),*a2is=(unsigned char*) malloc(sizeof(char )*255);
unsigned char * m2=(unsigned char*) malloc(sizeof(char )*255);
unsigned char * m3=(unsigned char*) malloc(sizeof(char )*255);
unsigned char * m9=(unsigned char*) malloc(sizeof(char )*255);
unsigned char * m11=(unsigned char*) malloc(sizeof(char )*255);
unsigned char * m13=(unsigned char*) malloc(sizeof(char )*255);
unsigned char * m14=(unsigned char*) malloc(sizeof(char )*255);
public:

   AES()
   {
      for(int i=0,ii=0;ii<256;i++)
{
 if(F1[i]==ii)F1i[ii]=i,ii++,i=0 ;//S inv
}F1i[0x63]=0;

for(char i=1,a=1,a2=0;i<256;i++,a2=0)
{
for(char j=1;j<256;j<<=1)
{
 a2^=((a&j)*3);
//////////////////////////////////////////////////////////////////////AES log alog 0x11b
}if(a2>255)a2^=0x11b;

a2is[i]=a2;
i2as[a2]=i;
a=a2;
}unsigned   short m[7]={0};
static unsigned char k[7]{2,3,9,11,13,14};
for(char i=0;i<256;i++){
for(char z=0;z<6;z++){
if(i) {
m[z]=(i2as[i]+i2as[k[z]]);     /////////////////mix////////
if(m[z]==510)m[z]=255;
if(m[z]!=255)m[z]=m[z]%255;
  m[z]=a2is[m[z]];}else m[z]=0;}
m2[i]=m[0];m3[i]=m[1];m9[i]=m[2];m11[i]=m[3];m13[i]=m[4];m14[i]=m[5];
}

   }

   private:
   void keyex(unsigned char *mm,unsigned char *l,char m)
   {int *w=(int*) malloc(sizeof(int )*50);
        int *key=(int*)mm;
    short *f;
unsigned char *gg=(unsigned char*)&key[0];
asm("xchg %0, %1;\n": "=r"(gg[0]), "+m"(gg[3]): "0"(gg[0]));
asm("xchg %0, %1;\n": "=r"(gg[1]), "+m"(gg[2]): "0"(gg[1]));
gg+=4;
w[0]=key[0];
asm("xchg %0, %1;\n": "=r"(gg[0]), "+m"(gg[3]): "0"(gg[0]));
asm("xchg %0, %1;\n": "=r"(gg[1]), "+m"(gg[2]): "0"(gg[1]));
w[1]=key[1];
gg+=4;
asm("xchg %0, %1;\n": "=r"(gg[0]), "+m"(gg[3]): "0"(gg[0]));
asm("xchg %0, %1;\n": "=r"(gg[1]), "+m"(gg[2]): "0"(gg[1]));
w[2]=key[2];
gg+=4;
asm("xchg %0, %1;\n": "=r"(gg[0]), "+m"(gg[3]): "0"(gg[0]));
asm("xchg %0, %1;\n": "=r"(gg[1]), "+m"(gg[2]): "0"(gg[1]));
w[3]=key[3];
for(char i=0,k=0;i<40;i+=4,k++)
{int f2=w[3+i];
asm("roll %1,%0":"+g"(f2):"cI"((unsigned char)8));
unsigned char  *kp=(unsigned char*)&f2;
*kp=F1[*kp] ;kp++;
*kp=F1[*kp] ;kp++;
*kp=F1[*kp] ;kp++;
*kp=F1[*kp] ;
*kp^=RC[k];
w[i+4]=f2^w[0+i];
w[i+5]=w[i+4]^w[1+i];
w[i+6]=w[i+5]^w[2+i];
w[i+7]=w[i+6]^w[3+i];
}unsigned char*u;
if(!m)se(w,u,l);
else sd(w,u,l);
free(w);
   }


   sd(int * w,unsigned char *u, unsigned char *l)
   {
   u=(unsigned char*)&w[40]+3;

    for(int I=0,x=0;I<11;I++){
      for(int i=0;i<4;i++)
       {
        for(int ii=0;ii<16;ii+=4,x++)
        {
          l[x]= u[ii-i];
        }
       }
    u-=16;}
   }



   se(int * w,unsigned char *u, unsigned char *l)
   {
   u=(unsigned char*)&w[0]+3;

for(char I=0,x=0;I<11;I++){
for(char i=0;i<4;i++)
{
   for(char ii=0;ii<16;ii+=4,x++)
   {
      l[x]= u[ii-i];

   }
}
u+=16;
}u=(unsigned char*)&w[0];


   }
public:






  void  decrypt(unsigned char *mm2,unsigned char *y)//mm2 -> key    y ->data
    {unsigned char *l=(unsigned char*) malloc(sizeof(char )*255),mm[17];
  for(char t=0;t<16;t++)asm("mov %0, %1;\n": "=r"(mm2[t]), "+m"(mm[t]): "0"(mm2[t]));
     keyex(mm,l,1)  ;
asm("xchg %0, %1;\n": "=r"(y[1]), "+m"(y[4]): "0"(y[1]));
asm("xchg %0, %1;\n": "=r"(y[2]), "+m"(y[8]): "0"(y[2]));
asm("xchg %0, %1;\n": "=r"(y[3]), "+m"(y[12]): "0"(y[3]));
asm("xchg %0, %1;\n": "=r"(y[6]), "+m"(y[9]): "0"(y[6]));
asm("xchg %0, %1;\n": "=r"(y[7]), "+m"(y[13]): "0"(y[7]));
asm("xchg %0, %1;\n": "=r"(y[11]), "+m"(y[14]): "0"(y[11]));
     for(unsigned char ro=0,M=0;ro<11;ro++,M+=16){
    unsigned char    *cc=&l[M];
printf("round NO. %d\n\n\n",ro);
int *o=(int*)y,o2;
printf("\nADD KEY\n ");
for(char i=0;i<16;i++)printf("%x  XOR %x =",y[i],cc[i]),y[i]=y[i]^cc[i],printf("%x \n",y[i]);
if(ro==10)break;
 unsigned   char s2=0,s[16]={0};
short int  m=0;
printf("MIX \n");
int *h=(int*)s;
if(ro!=0){

        s[0]=m14[y[0]]^m11[y[4]]^m13[y[8]]^m9[y[12]];
        s[4]=m9[y[0]]^m14[y[4]]^m11[y[8]]^m13[y[12]];
        s[8]=m13[y[0]]^m9[y[4]]^m14[y[8]]^m11[y[12]];
        s[12]=m11[y[0]]^m13[y[4]]^m9[y[8]]^m14[y[12]];

        s[1]=m14[y[1]]^m11[y[5]]^m13[y[9]]^m9[y[13]];//////////////mix
        s[5]=m9[y[1]]^m14[y[5]]^m11[y[9]]^m13[y[13]];
        s[9]=m13[y[1]]^m9[y[5]]^m14[y[9]]^m11[y[13]];
        s[13]=m11[y[1]]^m13[y[5]]^m9[y[9]]^m14[y[13]];


        s[2]=m14[y[2]]^m11[y[6]]^m13[y[10]]^m9[y[14]];
        s[6]=m9[y[2]]^m14[y[6]]^m11[y[10]]^m13[y[14]];
        s[10]=m13[y[2]]^m9[y[6]]^m14[y[10]]^m11[y[14]];
        s[14]=m11[y[2]]^m13[y[6]]^m9[y[10]]^m14[y[14]];

        s[3]=m14[y[3]]^m11[y[7]]^m13[y[11]]^m9[y[15]];
        s[7]=m9[y[3]]^m14[y[7]]^m11[y[11]]^m13[y[15]];
        s[11]=m13[y[3]]^m9[y[7]]^m14[y[11]]^m11[y[15]];
        s[15]=m11[y[3]]^m13[y[7]]^m9[y[11]]^m14[y[15]];
        for(int i=0;i<16;i++)printf("%x   ",s[i]);
o[0]=h[0];o[1]=h[1];o[2]=h[2];o[3]=h[3];
}
printf("\n ROR \n");
o=(int*)y;
asm("roll %1,%0":"+g"(o[1]):"cI"((unsigned char)8));
asm("roll %1,%0":"+g"(o[2]):"cI"((unsigned char)16));////rol
asm("roll %1,%0":"+g"(o[3]):"cI"((unsigned char)24));

for(int i=0;i<16;i++)printf("%x   ",y[i]);
printf("\n SBOX \n");
for(int i=0;i<16;i++)y[i]=F1i[y[i]],printf("%x   ",y[i]);//////////////////S box
putchar('\n');

}
asm("xchg %0, %1;\n": "=r"(y[1]), "+m"(y[4]): "0"(y[1]));
asm("xchg %0, %1;\n": "=r"(y[2]), "+m"(y[8]): "0"(y[2]));
asm("xchg %0, %1;\n": "=r"(y[3]), "+m"(y[12]): "0"(y[3]));
asm("xchg %0, %1;\n": "=r"(y[6]), "+m"(y[9]): "0"(y[6]));
asm("xchg %0, %1;\n": "=r"(y[7]), "+m"(y[13]): "0"(y[7]));
asm("xchg %0, %1;\n": "=r"(y[11]), "+m"(y[14]): "0"(y[11]));

free(l);
    }///////////////////////////////////////////////////////////////////////////////////////////////

   void encrypt(unsigned char *mm2, unsigned char *y)//m2 -> key y -> ciphertext
    {unsigned char *l=(unsigned char*) malloc(sizeof(char )*255),mm[17];
  for(char t=0;t<16;t++)asm("mov %0, %1;\n": "=r"(mm2[t]), "+m"(mm[t]): "0"(mm2[t]));
     keyex(mm,l,0)  ;
for(int i=0;i<176;i++)printf("%x ",l[i]);
asm("xchg %0, %1;\n": "=r"(y[1]), "+m"(y[4]): "0"(y[1]));
asm("xchg %0, %1;\n": "=r"(y[2]), "+m"(y[8]): "0"(y[2]));
asm("xchg %0, %1;\n": "=r"(y[3]), "+m"(y[12]): "0"(y[3]));
asm("xchg %0, %1;\n": "=r"(y[6]), "+m"(y[9]): "0"(y[6]));
asm("xchg %0, %1;\n": "=r"(y[7]), "+m"(y[13]): "0"(y[7]));
asm("xchg %0, %1;\n": "=r"(y[11]), "+m"(y[14]): "0"(y[11]));

   for(unsigned char ro=0,M=0;ro<11;ro++){
printf("round NO. %d\n\n\n",ro);
int *o=(int*)y,o2;
printf("\nADD KEY\n ");
for(char i=0;i<16;i++,M++)printf("%x  XOR %x =",y[i],l[M]),y[i]=y[i]^l[M],printf("%x \n",y[i]);
if(ro==10)break;
printf("\nS BOX \n");
for(int i=0;i<16;i++)y[i]=F1[y[i]],printf("%x   ",y[i]);//////////////////S box
printf("\n ROR \n");
o=(int*)y;

asm("rorl %1,%0":"+g"(o[1]):"cI"((unsigned char)8));
asm("rorl %1,%0":"+g"(o[2]):"cI"((unsigned char)16));////ror
asm("rorl %1,%0":"+g"(o[3]):"cI"((unsigned char)24));

for(int i=0;i<16;i++)printf("%x   ",y[i]);

putchar('\n');
 unsigned   char s[16]={0};
short int  m=0;

printf("MIX \n");
int *h=(int*)s;
if(ro!=9){

        s[0]=m2[y[0]]^m3[y[4]]^y[8]^y[12];
        s[4]=y[0]^m2[y[4]]^m3[y[8]]^y[12];
        s[8]=y[0]^y[4]^m2[y[8]]^m3[y[12]];
        s[12]=m3[y[0]]^y[4]^y[8]^m2[y[12]];

        s[1]=m2[y[1]]^m3[y[5]]^y[9]^y[13];
        s[5]=y[1]^m2[y[5]]^m3[y[9]]^y[13];
        s[9]=y[1]^y[5]^m2[y[9]]^m3[y[13]];
        s[13]=m3[y[1]]^y[5]^y[9]^m2[y[13]];

        s[2]=m2[y[2]]^m3[y[6]]^y[10]^y[14];
        s[6]=y[2]^m2[y[6]]^m3[y[10]]^y[14];
        s[10]=y[2]^y[6]^m2[y[10]]^m3[y[14]];
        s[14]=m3[y[2]]^y[6]^y[10]^m2[y[14]];

        s[3]=m2[y[3]]^m3[y[7]]^y[11]^y[15];
        s[7]=y[3]^m2[y[7]]^m3[y[11]]^y[15];
        s[11]=y[3]^y[7]^m2[y[11]]^m3[y[15]];
        s[15]=m3[y[3]]^y[7]^y[11]^m2[y[15]];
        for(int i=0;i<16;i++)printf("%x   ",s[i]);

o[0]=h[0];o[1]=h[1];o[2]=h[2];o[3]=h[3];
}

   }
asm("xchg %0, %1;\n": "=r"(y[1]), "+m"(y[4]): "0"(y[1]));
asm("xchg %0, %1;\n": "=r"(y[2]), "+m"(y[8]): "0"(y[2]));
asm("xchg %0, %1;\n": "=r"(y[3]), "+m"(y[12]): "0"(y[3]));
asm("xchg %0, %1;\n": "=r"(y[6]), "+m"(y[9]): "0"(y[6]));
asm("xchg %0, %1;\n": "=r"(y[7]), "+m"(y[13]): "0"(y[7]));
asm("xchg %0, %1;\n": "=r"(y[11]), "+m"(y[14]): "0"(y[11]));
free(l);
    }
~AES()
{
    free(i2as);free(a2is);free(m2);free(m3);free(m9);free(m11);free(m13);free(m14);
}
};
