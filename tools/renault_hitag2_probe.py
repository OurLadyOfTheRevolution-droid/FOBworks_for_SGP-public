#!/usr/bin/env python3
"""Renault V1 (Hitag2) Layer-2 epoch/key-recovery probe.

opens the Renault/Hitag2 work and shows the ProtoPirate 2^18 epoch
search does not converge on the corpus's one genuine Hitag2 capture, even widened
to 2^26. That is an important negative result — it says the epoch model, not the
search width, is what is missing — and this tool makes it reproducible so the next
attempt starts from the characterisation rather than rediscovering it.

It compiles a self-contained C++ probe (Layer-1 frame decode + the Hitag2 crypto
and both searches) extracted from nothing but this file, so it is independent of
the firmware and can be pointed at any capture:

    python3 tools/renault_hitag2_probe.py                 # the corpus Trafic file
    python3 tools/renault_hitag2_probe.py path/to/x.sub   # any Hitag2 capture

Two searches, both using the ProtoPirate IV construction and the serial
permutation it derives from the frame:

  narrow  2^18   the shipped ProtoPirate search (iv[0] fixed, iv[1] low 6 fixed)
  wide    2^26   frees all 8 bits of iv[0]

The frame is fully determined by cnt(16) + btn(4) + seed(16) = 36 bits; the wire
carries btn and cnt[9:0], so the genuine IV lives inside the wide space. A wide
miss therefore rules out the model for that capture rather than the search being
too small. The probe also reports the closest Hamming distance over the wide
sweep, because "distance 2" on a 32-bit output looks like a near miss but is the
expected number of chance neighbours at 2^26 draws (~77 of them).

Exit code is 0 when the frame decodes (Layer 1), regardless of whether Layer 2
converges — Layer 1 is the shipping behaviour and Layer 2 is known open.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"
DEFAULT = CORPUS / "European/Renault/Trafic 2011/Renault_trafic_2011_open_am1.sub"
CC = "clang++"

PROBE = r"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;

/* ── Layer 1: Hitag2 physical frame (tight sync) ── */
#define LO_MIN 1350U
#define LO_MAX 1850U
#define HI_MIN  870U
#define HI_MAX 1130U
#define HEADER_BITS 16U
#define KEY_END_BITS 80U
#define LONG_FRAME_BITS 104U
static const u8 TR[4]={0x01,0x91,0x9B,0xFB};
static bool hdrLow(u32 d){ return d>=LO_MIN&&d<=LO_MAX; }
static u32 dataThr(u16 te){ u32 t=(u32)te*3U; if(t<300U)return 150U; if(t>=422U)return 210U; return t/2U; }
static u16 adaptTe(u16 te,u32 d){ u32 m=(u32)te*7U+d; if(m<560U)return 70; if(m>=1488U)return 185; return (u16)(m/8U); }
static u8 frameXor(const u8 r[11]){ u8 v=0; for(int i=0;i<10;i++) v^=r[i]; return v; }
static void packKey(u64 key,u64 k2,u8 r[11]){ for(int i=0;i<8;i++) r[i]=(u8)(key>>(8*(7-i))); r[8]=(u8)(k2>>16); r[9]=(u8)(k2>>8); r[10]=(u8)k2; }

struct Dec {
  int step=0; u32 te_last=0; int mstate=0; u16 te_high=120,te_low=150;
  u64 acc=0; u32 cnt=0; u16 header=0; u64 data=0,key2=0;
  bool valid=false; u64 lastD=0,lastD2=0; bool got=false; u8 frame[11]={0}; u32 serial=0;
  void feed(bool level,u32 d){
    for(;;){
      if(step==0){ if(!level&&hdrLow(d)){ te_last=d; step=2; } return; }
      if(step==2){
        if(level){ if(d<HI_MIN||d>HI_MAX||te_last<LO_MIN||te_last>LO_MAX){ step=0; return; }
          acc=0; cnt=0; mstate=0; te_high=120; te_low=150; step=3; return; }
        step=0; if(hdrLow(d)){ te_last=d; step=2; } return;
      }
      if(d<=49U) return;
      if(d>520U){ step=0; continue; }
      u16* te = level? &te_high : &te_low; int ev;
      if(d>dataThr(*te)) ev = level?6:4; else { ev=level?2:0; *te=adaptTe(*te,d); }
      int ns=(TR[mstate]>>ev)&0x3; bool hb=false,bit=false;
      if(ns==mstate) ns=1; else if(ns==2){ hb=true; } else if(ns==1){ hb=true; bit=true; }
      mstate=ns; if(!hb) return;
      acc=(acc<<1)|(bit?1ULL:0ULL); cnt++;
      if(cnt==HEADER_BITS){ header=(u16)~acc; acc=0; return; }
      if(cnt==KEY_END_BITS){ data=~acc; acc=0; return; }
      if(cnt==LONG_FRAME_BITS){
        key2=(~acc)&0xFFFFFFULL;
        if(header==1U){
          u8 r[11]; packKey(data,key2,r);
          if(frameXor(r)==r[10] && !(valid&&lastD==data&&lastD2==key2)){
            memcpy(frame,r,11); serial=(u32)(data>>32); valid=true; got=true;
          }
        }
        acc=0; cnt=0; step=3;
      }
      return;
    }
  }
};

/* ── Layer 2: Hitag2 crypto + epoch search ── */
static u8 bb(u8 b,u8 i){ return (u8)((b>>i)&1U); }
static u8 tr_(u32 t,u8 i){ return (u8)((t>>i)&1U); }
static u8 fidx(u8 a,u8 b,u8 c,u8 d){ return (u8)((a<<3)|(b<<2)|(c<<1)|d); }
static u8 filt(const u8 s[6]){
  u8 g=0;
  g|=tr_(0x2C79U,fidx(bb(s[0],1),bb(s[0],2),bb(s[0],4),bb(s[0],5)));
  g|=(u8)(tr_(0x6671U,fidx(bb(s[1],0),bb(s[1],1),bb(s[1],3),bb(s[1],7)))<<1);
  g|=(u8)(tr_(0x6671U,fidx(bb(s[3],5),bb(s[2],0),bb(s[2],2),bb(s[2],6)))<<2);
  g|=(u8)(tr_(0x6671U,fidx(bb(s[4],6),bb(s[3],0),bb(s[3],2),bb(s[3],3)))<<3);
  g|=(u8)(tr_(0x2C79U,fidx(bb(s[5],1),bb(s[5],3),bb(s[5],4),bb(s[4],5)))<<4);
  return tr_(0x7907287BUL,g);
}
static u8 par8(u8 v){ v^=(u8)(v>>4); v^=(u8)(v>>2); v^=(u8)(v>>1); return (u8)(v&1); }
static u8 fb(const u8 s[6]){ static const u8 m[6]={0xB3,0x80,0x83,0x22,0x00,0x73}; u8 f=0;
  for(u8 i=0;i<6;i++) f^=par8((u8)(s[i]&m[i])); return (u8)(f&1); }
static void shs(u8 s[6],u8 in){ for(u8 i=0;i<5;i++) s[i]=(u8)((s[i]<<1)|(s[i+1]>>7)); s[5]=(u8)((s[5]<<1)|(in&1)); }
static void sh32(u8 b[4],u8 in){ u8 b0=b[0],b1=b[1],b2=b[2],b3=b[3];
  b[3]=(u8)((b2>>7)|(b3<<1)); b[2]=(u8)((b1>>7)|(b2<<1)); b[1]=(u8)((b0>>7)|(b1<<1)); b[0]=(u8)((b0<<1)|(in&1)); }
static void clk(u8 s[6],u8 w[4],u8 o[4]){
  for(u8 i=0;i<32;i++){ u8 fl=filt(s); u8 mx=(w[3]&0x80)?(fl?0:1):(fl?1:0); if(o[3]&0x80) mx^=5;
    shs(s,(u8)(mx&1)); sh32(w,0); sh32(o,(u8)((mx>>2)&1)); }
  for(u8 i=0;i<32;i++){ sh32(w,0); if(filt(s)) w[0]|=1; shs(s,fb(s)); }
}
static u8 eb(u32 v,u8 lsb,u8 w){ return (u8)((v>>lsb)&((1U<<w)-1U)); }
static void permute(const u8 se[4],u8 p[6]){
  const u8 s0=se[0],s1=se[1],s2=se[2],s3=se[3]; u8 a;
  a=(u8)(((s0>>6)&2)|((s1>>4)&8)|eb((u32)(s0^0x10),4,1));
  a|=(u8)((~(u32)(s0<<2))&0x20); a|=(u8)((s0<<5)&0x40); a|=(u8)((s2<<1)&0x80);
  a|=(u8)((~(u32)(s2>>5))&4); a|=(u8)((~(u32)(s0>>2))&0x10); p[0]=a;
  const u8 i1=(u8)~(s1>>3), i3=(u8)~(s3<<3);
  a=(u8)(eb(s1,5,1)|(i1&4)|(s0&0x20)); a|=(u8)(i3&8); a|=(u8)((~(u32)(s2<<2))&0x10); a|=(u8)((~(u32)(s2<<3))&0x40); a|=0x80; p[1]=a;
  const u8 s0s3=(u8)(s0>>3);
  a=(u8)(eb(s0,2,1)|(s0s3&2)|((~(u32)(s3>>2))&4)|(s1&0x10)); a|=(u8)((~(u32)(s1<<4))&0x20); a|=(u8)(i3&0x40); a|=0x80; p[2]=a;
  const u8 i2=(u8)~(s2<<6);
  a=(u8)(((s0>>2)&2)|((s1>>3)&8)|eb((u32)(s2^0x20),5,1)); a|=(u8)((s1<<5)&0x20); a|=(u8)((s3<<1)&0x40);
  a|=(u8)(((u8)~s0s3)&4); a|=(u8)(i1&0x10); a|=(u8)(i2&0x80); p[3]=a;
  u8 p4=(u8)(((s3<<2)&8)|((s0<<4)&0x10)|eb((u32)(s0^4),2,1)); p4|=(u8)((~(u32)(s3>>1))&2); p4|=(u8)((~(u32)(s1>>4))&4);
  u8 p4h=(u8)((~(u32)(s0<<4))&0x20); p4h|=(u8)(i2&0x40); const u8 i1s=(u8)~(s1<<3); p4h|=(u8)(i1s&0x80); p[4]=(u8)(p4|p4h);
  u8 p5=(u8)(((s3>>2)&0x10)|((s2>>3)&2)|(((u8)~s0)&0x80)); p5|=(u8)((~(u32)(s0<<3))&8); p5|=(u8)((s0>>2)&0x10);
  p5|=(u8)(i1s&0x20); p5|=(u8)((s3>>1)&0x40); p5|=(u8)((~(u32)(s1>>1))&4); p[5]=p5;
}
static void rear(u8 d[11]){
  const u8 f4=d[6]; u8 f5=d[5],f6=d[4],f7=d[3]; const u8 f8=d[2],f9=d[1];
  u8 h0=(u8)(((f4&1)<<7)|(f5>>1)); f5=(u8)(((f5&1)<<7)|(f6>>1));
  const u8 h0h=(u8)(h0>>1); h0=(u8)(h0&1); h0=(u8)((h0<<7)|(f5>>1));
  f6=(u8)(((f6&1)<<7)|(f7>>1)); f5=(u8)(((f5&1)<<7)|(f6>>1)); d[3]=f5;
  f7=(u8)(((f7&1)<<7)|(f8>>1)); const u8 h2=(u8)(((f6&1)<<7)|(f7>>1));
  f6=(u8)(((f8&1)<<7)|(f9>>1)); d[6]=(u8)(((f9&1)<<7)|(f4>>2));
  d[1]=(u8)(((f7&1)<<7)|(f6>>1)); d[5]=(u8)(h0h|(((f4>>1)&1)<<7)); d[2]=h2; d[4]=h0;
}
static void prep(const u8 fr[11],u8 se[4],u8 p[6],u8 ht[4],u8* iv0,u8* fp){
  u8 d[11]; for(int i=0;i<11;i++) d[i]=fr[10-i]; rear(d);
  ht[0]=d[1]; ht[1]=d[2]; ht[2]=d[3]; ht[3]=d[4];
  *iv0=(u8)((fr[4]>>4)|(d[5]<<4)); *fp=(u8)((d[5]>>4)|((d[6]&3)<<4));
  se[0]=fr[0]; se[1]=fr[1]; se[2]=fr[2]; se[3]=fr[3]; permute(se,p);
}
static int ham32(const u8 a[4],const u8 b[4]){ int d=0; for(int i=0;i<4;i++){ u8 x=(u8)(a[i]^b[i]); while(x){d+=x&1;x>>=1;} } return d; }
static bool run(const u8 fr[11],int wide,u8 ivout[4],u32* seed,int* bestham){
  u8 se[4],p[6],ht[4],iv0=0,fp=0; prep(fr,se,p,ht,&iv0,&fp);
  int best=99; u8 biv[4]={0,0,0,0};
  u32 c0lo=wide?0:1, c0hi=wide?256:1;
  for(u32 c0=c0lo;c0<c0hi;c0++){
   for(u32 cand=0;cand<0x40000;cand++){
    u8 iv[4]; iv[0]=(u8)c0; iv[1]=(u8)(fp|((cand&3)<<6)); iv[2]=(u8)(cand>>2); iv[3]=(u8)(cand>>10);
    u8 s[6],w[4],o[4];
    s[0]=se[0];s[1]=se[1];s[2]=se[2];s[3]=se[3];s[4]=p[4];s[5]=p[5];
    w[0]=p[0];w[1]=p[1];w[2]=p[2];w[3]=p[3];
    o[0]=iv[0];o[1]=iv[1];o[2]=iv[2];o[3]=iv[3];
    clk(s,w,o);
    int dd=ham32(w,ht);
    if(dd<best){ best=dd; biv[0]=iv[0];biv[1]=iv[1];biv[2]=iv[2];biv[3]=iv[3];
      if(dd==0){ memcpy(ivout,iv,4); *seed=((u32)iv[0]<<24)|((u32)iv[1]<<16)|((u32)iv[2]<<8)|iv[3];
        if(bestham)*bestham=0; return true; } }
   }}
  if(bestham)*bestham=best;
  if(ivout) memcpy(ivout,biv,4);
  return false;
}

int main(int argc,char**argv){
  FILE*f=fopen(argv[1],"r"); if(!f){printf("cannot open %s\n",argv[1]);return 2;}
  std::vector<int> v; int x;
  while(fscanf(f,"%d",&x)==1) v.push_back(x);
  fclose(f);
  Dec d; for(size_t i=0;i<v.size();i++){ int p=v[i]; d.feed(p>0,(u32)(p<0?-p:p)); }
  printf("capture pulses=%zu  frame=%s\n",v.size(), d.got?"yes":"NO");
  if(!d.got) return 1;
  printf("  raw   = ");
  for(int i=0;i<11;i++) printf("%02X", d.frame[i]);
  printf("\n  serial= 0x%08X\n", d.serial);
  u8 iv[4]; u32 seed=0; int bh=0;
  bool n=run(d.frame,0,iv,&seed,&bh);
  printf("  narrow 2^18 : %s\n", n?"FOUND":"MISS");
  bool w=run(d.frame,1,iv,&seed,&bh);
  printf("  wide   2^26 : %s   closest Hamming distance=%d  iv=%02X%02X%02X%02X\n",
         w?"FOUND":"MISS", bh, iv[0],iv[1],iv[2],iv[3]);
  if(w) printf("  recovered seed=0x%08X\n", seed);
  return 0;
}
"""


def parse_signed(path):
    raw = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            raw.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
    return raw


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT)
    if not Path(src).exists():
        print(f"capture not found: {src}")
        return 2
    raw = parse_signed(src)
    if len(raw) < 200:
        print(f"capture too short ({len(raw)} pulses)")
        return 2
    with tempfile.TemporaryDirectory() as td:
        cpp = Path(td) / "probe.cpp"
        cpp.write_text(PROBE)
        exe = Path(td) / "probe"
        r = subprocess.run([CC, "-O2", "-w", "-o", str(exe), str(cpp)],
                           capture_output=True, text=True)
        if r.returncode:
            print("probe did not compile:\n" + r.stderr[:800])
            return 2
        pf = Path(td) / "in.txt"
        pf.write_text("\n".join(str(x) for x in raw))
        # The wide sweep is ~1e9 clock-cipher evaluations; allow a couple of minutes.
        out = subprocess.run([str(exe), str(pf)], capture_output=True, text=True)
        print(out.stdout.rstrip())
        if out.stderr.strip():
            print(out.stderr.rstrip()[:400])
    print()
    print("Layer 1 is the shipping behaviour. A 'MISS' on both searches means the")
    print("ProtoPirate epoch model does not cover this capture;")
    print("the wide space contains the genuine IV, so width is not the limit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
