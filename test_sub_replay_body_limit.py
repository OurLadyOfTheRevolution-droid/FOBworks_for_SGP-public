#!/usr/bin/env python3
"""Static regression checks for the bounded /api/sub_replay request path."""

from pathlib import Path
import re


FIRMWARE = Path(__file__).with_name("FOBworks_for_SGP.ino")
source = FIRMWARE.read_text(encoding="utf-8")

# The route must opt into WebServer's raw callback. Without the fourth callback,
# WebServer buffers the complete plain body before the final handler runs.
route = re.search(
    r'protectedRoute\("/api/sub_replay",HTTP_POST,\[\]\(\)\{(?P<body>.*?)'
    r'\},receiveSubReplayBody\);',
    source,
    re.DOTALL,
)
assert route, "/api/sub_replay is not registered with the streaming body callback"

handler = route.group("body")
assert 'srv.arg("plain")' not in handler, "handler copies the WebServer-buffered body"
assert "substring(" not in handler, "handler creates an avoidable body substring"
assert "srv.send(413" in handler, "oversized replay bodies do not return HTTP 413"

limit = re.search(r"SUB_REPLAY_MAX_BODY_BYTES\s*=\s*(\d+)", source)
# The property this check exists for is that the body is BOUNDED, not that the bound is
# 8192. It was raised to 16384 because the corpus's first trimmable frame sits at pulse
# 2517 and an 8192-byte body reaches only 1868 pulses -- so the smaller bound made the
# import refuse the very corpus it was written for. Assert a
# bounded value in a sane range, and that the 413 path below still guards it.
assert limit, "replay body limit is not defined"
limit_bytes = int(limit.group(1))
assert 4096 <= limit_bytes <= 65536, f"replay body limit {limit_bytes} is outside a sane range"
assert "raw.currentSize>SUB_REPLAY_MAX_BODY_BYTES-subReplayBody.length()" in source
assert "subReplayBody.concat((const char*)raw.buf" in source
assert "subReplayBody.reserve((size_t)contentLength)" in source
assert 'const char* authHeaders[]={"Authorization","Content-Type"}' in source

# Pulse parsing remains independently bounded even for a valid maximum-size
# request, and it no longer allocates one String per number.
parser = re.search(
    r"static bool parseSubReplayBody\(.*?\n\}(?=\n\nvoid setupRoutes)",
    source,
    re.DOTALL,
)
assert parser, "bounded replay parser is missing"
# Bounded, not "bounded at 512": the cap is now SUB_REPLAY_MAX_PULSES (3740), raised
# because a 512-pulse window could not reach the corpus frame at pulse 2517. The property
# this line exists for is that the loop cannot run unbounded.
assert re.search(r"pulseCount\s*<\s*(SUB_REPLAY_MAX_PULSES|\d+)", parser.group(0)), \
    "the replay parser is not bounded"
assert "substring(" not in parser.group(0)

print("sub replay body-limit checks passed")