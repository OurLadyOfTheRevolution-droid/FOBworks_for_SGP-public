#!/usr/bin/env python3
"""Dump every accepted Renault V1 (Hitag2) frame from a capture, in order.

The on-air path is dead on this board (RSSI-edge mode, no GDO0 — see
), so the real data available is the corpus recording, which carries a
run of consecutive frames as the counter walks. Layer-1 decode is all this needs;
no epoch search, no crypto, no model assumptions. Compiled from an embedded
source so it is independent of the firmware.

  python3 tools/renault_hopseq.py [capture.sub]
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
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define LO_MIN 1350U
#define LO_MAX 1850U
#define HI_MIN  870U
#define HI_MAX 1130U
static const u8 TR[4]={0x01,0x91,0x9B,0xFB};
static bool hdrLow(u32 d){ return d>=LO_MIN&&d<=LO_MAX; }
static u32 dataThr(u16 te){ u32 t=(u32)te*3U; if(t<300U)return 150U; if(t>=422U)return 210U; return t/2U; }
static u16 adaptTe(u16 te,u32 d){ u32 m=(u32)te*7U+d; if(m<560U)return 70; if(m>=1488U)return 185; return (u16)(m/8U); }
static u8 fx(const u8 r[11]){ u8 v=0; for(int i=0;i<10;i++) v^=r[i]; return v; }
static void pack(u64 key,u64 k2,u8 r[11]){ for(int i=0;i<8;i++) r[i]=(u8)(key>>(8*(7-i))); r[8]=(u8)(k2>>16); r[9]=(u8)(k2>>8); r[10]=(u8)k2; }
struct Dec{
  int step=0; u32 te_last=0; int ms=0; u16 teh=120,tel=150; u64 acc=0; u32 cnt=0; u16 hdr=0; u64 data=0,k2=0;
  u64 lastD=0,lastD2=0; bool have=false;
  void feed(bool level,u32 d){
    for(;;){
      if(step==0){ if(!level&&hdrLow(d)){ te_last=d; step=2; } return; }
      if(step==2){ if(level){ if(d<HI_MIN||d>HI_MAX||te_last<LO_MIN||te_last>LO_MAX){step=0;return;} acc=0;cnt=0;ms=0;teh=120;tel=150;step=3;return;} step=0; if(hdrLow(d)){te_last=d;step=2;} return; }
      if(d<=49U) return; if(d>520U){ step=0; continue; }
      u16* te=level?&teh:&tel; int ev; if(d>dataThr(*te)) ev=level?6:4; else { ev=level?2:0; *te=adaptTe(*te,d);}
      int ns=(TR[ms]>>ev)&3; bool hb=false,bit=false;
      if(ns==ms) ns=1; else if(ns==2) hb=true; else if(ns==1){ hb=true; bit=true; }
      ms=ns; if(!hb) return; acc=(acc<<1)|(bit?1:0); cnt++;
      if(cnt==16){ hdr=(u16)~acc; acc=0; return; }
      if(cnt==80){ data=~acc; acc=0; return; }
      if(cnt==104){ k2=(~acc)&0xFFFFFF; if(hdr==1U){ u8 r[11]; pack(data,k2,r); if(fx(r)==r[10] && !(have&&lastD==data&&lastD2==k2)){ lastD=data; lastD2=k2; have=true; print(r); } } acc=0;cnt=0;step=3; }
      return;
    }
  }
  static void print(const u8 r[11]){
    u16 c10=((u16)(r[4]&0x0F)<<6)|(r[5]>>2);
    u32 hop=((u32)(r[5]&3)<<30)|((u32)r[6]<<22)|((u32)r[7]<<14)|((u32)r[8]<<6)|(r[9]>>2);
    u8 btn=r[4]>>4, tail=r[9]&3;
    printf("sn=%02X%02X%02X%02X btn=%X cnt=%03X hop=%08X tail=%u raw=",
      r[0],r[1],r[2],r[3],btn,c10,hop,tail);
    for(int i=0;i<11;i++) printf("%02X",r[i]); printf("\n");
  }
};
int main(int argc,char**argv){
  FILE*f=fopen(argv[1],"r"); if(!f){printf("open fail\n");return 2;}
  std::vector<int> v; int x; while(fscanf(f,"%d",&x)==1) v.push_back(x); fclose(f);
  Dec d; for(size_t i=0;i<v.size();i++){ int p=v[i]; d.feed(p>0,(u32)(p<0?-p:p)); }
  return 0;
}
"""


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT)
    raw = []
    for line in Path(src).read_text(errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            raw += [int(x) for x in re.findall(r"-?\d+", line[9:])]
    if not raw:
        print("no RAW_Data in", src)
        return 2
    with tempfile.TemporaryDirectory() as td:
        cpp = Path(td) / "d.cpp"
        cpp.write_text(SRC)
        exe = Path(td) / "d"
        r = subprocess.run([CC, "-O2", "-w", "-o", str(exe), str(cpp)],
                           capture_output=True, text=True)
        if r.returncode:
            print(r.stderr[:600])
            return 2
        inp = Path(td) / "in.txt"
        inp.write_text("\n".join(str(x) for x in raw))
        out = subprocess.run([str(exe), str(inp)], capture_output=True, text=True)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    print(f"{src}\n{len(lines)} accepted frame(s):\n")
    prev = None
    for l in lines:
        m = re.search(r"cnt=([0-9A-F]+) hop=([0-9A-F]+)", l)
        extra = ""
        if m and prev is not None:
            dc = int(m.group(1), 16) - prev[0]
            extra = f"   dCnt=+{dc}  hop^prev=0x{int(m.group(2),16) ^ prev[1]:08X}"
        print("  " + l + extra)
        if m:
            prev = (int(m.group(1), 16), int(m.group(2), 16))
    # relationship probe: is hop a function of cnt alone across the run?
    seq = []
    for l in lines:
        m = re.search(r"cnt=([0-9A-F]+) hop=([0-9A-F]+)", l)
        if m:
            seq.append((int(m.group(1), 16), int(m.group(2), 16)))
    if len(seq) >= 3:
        print("\n  hop deltas (cnt-ordered):")
        seq.sort()
        for i in range(1, len(seq)):
            print(f"    cnt {seq[i-1][0]:03X}->{seq[i][0]:03X}  "
                  f"hop {seq[i-1][1]:08X}->{seq[i][1]:08X}  "
                  f"xor=0x{seq[i-1][1]^seq[i][1]:08X}  sub=0x{(seq[i][1]-seq[i-1][1])&0xFFFFFFFF:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
