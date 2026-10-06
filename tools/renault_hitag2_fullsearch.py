#!/usr/bin/env python3
"""Exhaustive 2^32 IV search for one Renault V1 (Hitag2) frame.

Why this exists: the ProtoPirate Layer-2 recovery brute-forces a
constrained 2^18 subset of the 32-bit IV, and it misses the genuine Trafic frame
even widened to 2^26. In this cipher the *entire* cipher state is derived from the
serial (known from the frame) — there is no secret key in the state — so the one
unknown is the 32-bit IV. That makes the decisive experiment cheap to state:

  * search all 2^32 IVs for one frame; if one reproduces the hop, the model is
    right and the frame's IV/seed is recovered;
  * if the space is exhausted with no hit, the serial-only model is wrong for
    Renault — the fob carries a real secret key (so recovery needs key
    extraction, not an epoch search).

Same crypto primitives as tools/renault_hitag2_probe.py, which was validated
byte-for-byte against the ProtoPirate reference (encoder<->recovery 400/400).

  python3 tools/renault_hitag2_fullsearch.py            # benchmark, then full run
  python3 tools/renault_hitag2_fullsearch.py --bench    # benchmark only
"""
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRAME = bytes.fromhex("3270FD2B25715BD1FE2A9E")   # cnt 0x15C, hop 0x56F47F8A
HOPT = bytes.fromhex("56F47F8A")
FULL = 1 << 32

SRC = r"""
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <vector>
#include <atomic>
#include <algorithm>
static double now_s(){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

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
int main(int argc,char**argv){
  u64 limit = (argc>1)? strtoull(argv[1],0,0) : (1ULL<<32);
  u8 fr[11]; const char*hexs=(argc>2)?argv[2]:"3270FD2B25715BD1FE2A9E";
  for(int i=0;i<11;i++){ unsigned v; sscanf(hexs+2*i,"%2x",&v); fr[i]=(u8)v; }
  u8 hop_t[4]; for(int i=0;i<4;i++){ unsigned v; sscanf(((argc>3)?argv[3]:"56F47F8A")+2*i,"%2x",&v); hop_t[i]=(u8)v; }
  u8 d[11]; for(int i=0;i<11;i++) d[i]=fr[10-i]; rear(d);
  u8 se[4]={fr[0],fr[1],fr[2],fr[3]}, p[6]; permute(se,p);
  /* hop_target in the BF's own layout */
  u8 ht[4]={d[1],d[2],d[3],d[4]};
  (void)hop_t;
  std::atomic<int> found(0); std::atomic<uint32_t> fiv(0);
  unsigned nthreads = std::thread::hardware_concurrency();
  if(nthreads==0) nthreads=4;
  if(nthreads>16) nthreads=16;
  double t0=now_s();
  std::vector<std::thread> ts;
  for(unsigned ti=0; ti<nthreads; ti++){
    ts.emplace_back([&,ti]{
      u64 lo = (limit*ti)/nthreads, hi = (limit*(ti+1))/nthreads;
      u8 s0=se[0],s1=se[1],s2=se[2],s3=se[3];
      for(u64 c=lo; c<hi; c++){
        if((c & 0xFFFFFULL)==0 && found.load(std::memory_order_relaxed)) return;
        u32 iv=(u32)c;
        u8 s[6]={s0,s1,s2,s3,p[4],p[5]};
        u8 w[4]={p[0],p[1],p[2],p[3]};
        u8 o[4]={(u8)(iv>>24),(u8)(iv>>16),(u8)(iv>>8),(u8)iv};
        clk(s,w,o);
        if(w[0]==ht[0]&&w[1]==ht[1]&&w[2]==ht[2]&&w[3]==ht[3]){ found.store(1); fiv.store(iv); }
      }
    });
  }
  for(auto&t:ts) t.join();
  double dt=now_s()-t0;
  double rate=(double)limit/dt;
  printf("searched %llu ivs in %.2fs  (%.1f Miv/s)  threads=%u\n",
         (unsigned long long)limit, dt, rate/1e6, nthreads);
  if(found.load()){ u32 iv=fiv.load();
    printf("HIT iv=%08X  seed=0x%08X\n", iv, iv); }
  else printf("MISS (no iv in the searched range)\n");
  return found.load()?0:1;
}
"""


def build(td):
    cpp = Path(td) / "s.cpp"
    cpp.write_text(SRC)
    exe = Path(td) / "s"
    r = subprocess.run(
        ["clang++", "-O3", "-march=native", "-fopenmp", "-w", "-o", str(exe), str(cpp)],
        capture_output=True, text=True)
    if r.returncode:
        # retry without openmp
        r = subprocess.run(["clang++", "-O3", "-march=native", "-w", "-o", str(exe), str(cpp)],
                           capture_output=True, text=True)
        if r.returncode:
            print(r.stderr[:800])
            return None
        print("(built without OpenMP)")
    return exe


def main():
    bench_only = "--bench" in sys.argv
    with tempfile.TemporaryDirectory() as td:
        exe = build(td)
        if not exe:
            return 2
        # benchmark on 2^24
        print("benchmark (2^24 IVs):")
        r = subprocess.run([str(exe), str(1 << 24)], capture_output=True, text=True)
        print("  " + r.stdout.strip().replace("\n", "\n  "))
        if bench_only:
            return 0
        # extrapolate
        m = re.search(r"\(([\d.]+) Miv/s\)", r.stdout)
        if m:
            rate = float(m.group(1)) * 1e6
            est = (1 << 32) / rate
            print(f"  full 2^32 estimated: {est/60:.1f} min")
        print("\nfull 2^32 search (background-able; Ctrl-C to stop):")
        r = subprocess.run([str(exe), str(FULL)], capture_output=True, text=True)
        print(r.stdout.strip())
        return 0 if "HIT" in r.stdout else 2


if __name__ == "__main__":
    sys.exit(main())
