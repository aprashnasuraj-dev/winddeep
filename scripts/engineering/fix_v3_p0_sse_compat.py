"""One-shot P0 SSE compatibility correction.

Preserve the legacy EventSource.onmessage contract while retaining monotonic
SSE ids and the versioned JSON event type. The UI must continue receiving
progress/finding/log events without requiring named-event listeners.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

server = ROOT / "app" / "server.py"
text = server.read_text(encoding="utf-8")
old = '        return f"{event_id}event: {event_type}\\ndata: {payload}\\n\\n"\n'
new = '        return f"{event_id}data: {payload}\\n\\n"\n'
if old not in text:
    if new not in text:
        raise RuntimeError("SSE frame marker changed")
else:
    text = text.replace(old, new, 1)
server.write_text(text, encoding="utf-8", newline="\n")

path = ROOT / "tests" / "test_v3_p0_post_and_sse.py"
test = path.read_text(encoding="utf-8")
test = test.replace('    assert "event: finding" in second\n', '    assert "event: finding" not in second\n    assert \'"type":"finding"\' in second\n')
test = test.replace('    assert "event: ranked" in third\n', '    assert "event: ranked" not in third\n    assert \'"type":"ranked"\' in third\n')
path.write_text(test, encoding="utf-8", newline="\n")
