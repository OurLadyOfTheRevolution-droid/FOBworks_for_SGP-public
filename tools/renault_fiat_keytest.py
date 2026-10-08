#!/usr/bin/env python3
"""Test the FIAT-V1 keyed-Hitag2 model against real Renault V1 frames.

closed the "classic epoch/seed IV model" for Renault V1 with an
exhaustive 2^32 sweep: each frame returned exactly one (random) IV fixed point and
the seed byte was not constant across frames, so the model is wrong.

That leaves the reference's OTHER hypothesis (renault_v1.c): Renault V1 reuses
FIAT V1's *keyed* BCM authenticator, where the cipher state is uid || key[4..5] and
the only unknown is a secret 6-byte key. The reference ships 8 candidate keys.

This tool is the cheap end of that test: for each real captured frame it checks
whether any of the 8 known keys, over the full 2^18 epoch space and the reference's
button interpretations, reproduces the hop. A hit is genuine key recovery; a miss
says the key for this 2011 Trafic is not in the dictionary (not that the model is
wrong ��� a private key was always the likely case).

  python3 tools/renault_fiat_keytest.py [frame_hex ...]
"""
import subprocess
import sys
import tempfile
from pathlib import Path

FRAMES = [
    ("3270FD2B25715BD1FE2A9E", "cnt=0x15C"),
    ("3270FD2B25753BCF9E6EC0", "cnt=0x15D"),
    ("3270FD2B25795B5F4A7EF8", "cnt=0x15E"),
    ("3270FD2B257DFBD40F46AA", "cnt=0x15F"),
    ("3270FD2B2581E5593F6AD9", "cnt=0x160"),
]

SRC = r"""
#include <cstdio>
#include <cstdint>
#include <cstring>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
static u8 truth(u32 t,u8 i){ return (u8)((t>>i)&1U); }
static u8 fidx(u8 a,u8 b,u8 c,u8 d){ return (u8)((a<<3)|(b<<2)|(c<<1)|d); }
static u8 bit(u8 b,u8 i){ return (u8)((b>>i)&1U); }
static u8 filt(const u8 s[6]){
  u8 g=0;
  g|=truth(0x2C79U,fidx(bit(s[0],1),bit(s[0],2),bit(s[0],4),bit(s[0],5)));
  g|=(u8)(truth(0x6671U,fidx(bit(s[1],0),bit(s[1],1),bit(s[1],3),bit(s[1],7)))<<1);
  g|=(u8)(truth(0x6671U,fidx(bit(s[3],5),bit(s[2],0),bit(s[2],2),bit(s[2],6)))<<2);
  g|=(u8)(truth(0x6671U,fidx(bit(s[4],6),bit(s[3],0),bit(s[3],2),bit(s[3],3)))<<3);
  g|=(u8)(truth(0x2C79U,fidx(bit(s[5],1),bit(s[5],3),bit(s[5],4),bit(s[4],5)))<<4);
  return truth(0x7907287BUL,g);
}
static u8 par8(u8 v){ v^=(u8)(v>>4); v^=(u8)(v>>2); v^=(u8)(v>>1); return (u8)(v&1); }
static u8 fbk(const u8 s[6]){ static const u8 m[6]={0xB3,0x80,0x83,0x22,0x00,0x73}; u8 f=0;
  for(u8 i=0;i<6;i++) f^=par8((u8)(s[i]&m[i])); return (u8)(f&1); }
static void shs(u8 s[6],u8 in){ for(u8 i=0;i<5;i++) s[i]=(u8)((s[i]<<1)|(s[i+1]>>7)); s[5]=(u8)((s[5]<<1)|(in&1)); }
static u8 in_u32_be(u32 v,u8 i){ return (u8)((v>>(31-i))&1U); }
static u8 in_bytes_be(const u8*b,u8 i){ return (u8)((b[i>>3]>>(7-(i&7)))&1U); }
static u32 auth(u32 uid,u8 btn,u16 ctrl,const u8 key[6],u32 epoch){
  u8 s[6]={(u8)(uid>>24),(u8)(uid>>16),(u8)(uid>>8),(u8)uid,key[4],key[5]};
  u32 iv=((epoch&0x3FFFFUL)<<14U)|(((u32)ctrl&0x3FFUL)<<4U)|((u32)btn&0x0FUL);
  for(u8 i=0;i<32;i++){ u8 in=(u8)(in_u32_be(iv,i)^in_bytes_be(key,i)^filt(s)); shs(s,in); }
  u32 a=0; for(u8 i=0;i<32;i++){ a=(a<<1)|filt(s); shs(s,fbk(s)); }
  return a;
}
static const u8 KEYS[8][6]={
  {0xB7,0x92,0x80,0xAE,0xCC,0x37},{0xD4,0x24,0x28,0xF7,0xD9,0x66},
  {0x4D,0x34,0x3F,0xD4,0xE7,0xB6},{0x6D,0x6B,0xF2,0x1D,0x3A,0x1A},
  {0xA3,0xF3,0xAC,0xF7,0xB9,0x10},{0x4D,0x49,0x4B,0x52,0x4F,0x4E},
  {0xCD,0x49,0x4B,0x52,0x4F,0x4E},{0x33,0xFA,0x2F,0xCD,0xC3,0x3B},
};
int main(int argc,char**argv){
  int hits=0;
  for(int a=1;a<argc;a++){
    u8 fr[11]; for(int i=0;i<11;i++){ unsigned v; sscanf(argv[a]+2*i,"%2x",&v); fr[i]=(u8)v; }
    u32 uid=((u32)fr[0]<<24)|((u32)fr[1]<<16)|((u32)fr[2]<<8)|fr[3];
    u8 btn=fr[4]>>4; u16 cnt=((u16)(fr[4]&0x0F)<<6)|(fr[5]>>2);
    u32 hop=((u32)(fr[5]&3)<<30)|((u32)fr[6]<<22)|((u32)fr[7]<<14)|((u32)fr[8]<<6)|(fr[9]>>2);
    /* reference button interpretations (renault_v1 iv_button combos) + raw */
    u8 btns[5]={btn, (u8)(btn&0x0F), 2, 4, 1};
    int fh=0;
    for(int k=0;k<8;k++) for(int b=0;b<5;b++) for(u32 e=0;e<0x40000;e++){
      if(auth(uid,btns[b],cnt,KEYS[k],e)==hop){
        printf("  HIT frame%s  key#%d=%02X%02X%02X%02X%02X%02X  btn=%u epoch=%05X\n",
               argv[a],k,KEYS[k][0],KEYS[k][1],KEYS[k][2],KEYS[k][3],KEYS[k][4],KEYS[k][5],
               btns[b],e);
        fh++; hits++;
      }
    }
    printf("frame %s: uid=%08X btn=%u cnt=%03X hop=%08X -> %d key hit(s)\n",
           argv[a],uid,btn,cnt,hop,fh);
  }
  printf("total key hits: %d\n", hits);
  return hits?0:1;
}
"""


def main():
    frames = sys.argv[1:] or [f[0] for f in FRAMES]
    with tempfile.TemporaryDirectory() as td:
        cpp = Path(td) / "k.cpp"
        cpp.write_text(SRC)
        exe = Path(td) / "k"
        r = subprocess.run(["clang++", "-O3", "-march=native", "-w", "-o", str(exe), str(cpp)],
                           capture_output=True, text=True)
        if r.returncode:
            print(r.stderr[:700])
            return 2
        out = subprocess.run([str(exe)] + frames, capture_output=True, text=True)
    print("FIAT-V1 keyed-model test against real Renault frames")
    print("(8 known keys x 2^18 epochs x 5 button interpretations per frame)\n")
    print(out.stdout.strip())
    if "total key hits: 0" in out.stdout:
        print("\nNo dictionary key reproduces the hop. The keyed structure remains the")
        print("standing hypothesis for Renault V1, but this fob's key is")
        print("private — as expected for a 2011 vehicle — so recovery needs extraction")
        print("(side-channel) or a different attack, not a wider search.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
