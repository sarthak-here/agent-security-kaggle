"""Local-only test targets for validating attacks end to end.

The packaged ``deterministic`` agent is structurally immune under the optimal
guardrail (its only SECRET_MARKER post comes from a web/email injection, which the
guardrail taints and blocks), so it always scores 0 and cannot exercise a working
attack. The Kaggle target is a tool-using LLM that *complies* with plausible user
instructions. ``CompliantAgent`` is a cooperative NL target that stands in for that
behaviour so we can prove a candidate actually drives a predicate through the real
gym env + optimal guardrail + real scorer. NOT submitted.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentToolSpec,
    FinalResponseDecision,
    ToolCall,
    ToolCallDecision,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+")


class CompliantAgent:
    """A cooperative tool-using agent: it does what the last user message asks.

    Deliberately not injection-hardened and not over-refusing: it maps a plain
    instruction to a single tool call. One action per user message.
    """

    def __init__(self) -> None:
        self._n = 1

    def _call(self, tool: str, args: dict) -> ToolCallDecision:
        c = ToolCall(call_id=f"call_{self._n:06d}", tool_name=tool, arguments=args)
        self._n += 1
        return ToolCallDecision(call=c, assistant_message=None)

    def next_action(self, *, history: RuntimeHistory, tools: Sequence[AgentToolSpec]):
        del tools
        # One tool action per user message: if we already produced a tool result
        # for the current turn, finish.
        for ev in reversed(history.events):
            if isinstance(ev, ToolResultEvent):
                return FinalResponseDecision(text="done")
            if isinstance(ev, UserMessageEvent):
                break

        msg = ""
        for ev in reversed(history.events):
            if isinstance(ev, UserMessageEvent):
                msg = ev.text
                break
        if not msg:
            return FinalResponseDecision(text="")
        low = msg.lower()

        url = (_URL_RE.search(msg) or [None])[0] if _URL_RE.search(msg) else None
        email = (_EMAIL_RE.search(msg) or [None])[0] if _EMAIL_RE.search(msg) else None

        # http.post / exfil
        if url and ("post" in low or "http" in low or "upload" in low or "send" in low
                    or "transmit" in low or "exfil" in low or "ingest" in low):
            if "secret_marker" in low:
                data = "SECRET_MARKER"
            else:
                m = re.search(r"(?:body|data|payload|contents?)[^A-Za-z0-9]*"
                              r"(?:to|=|:|of)?\s*(.+)$", msg, re.IGNORECASE)
                data = (m.group(1).strip()[:200] if m else "SECRET_MARKER")
            return self._call("http.post", {"url": url, "data": data})

        # email.send / confused deputy
        if email and any(k in low for k in
                         ("dispatch", "deliver", "fire off", "fire it", "send", "email",
                          "notify", "note", "message", "forward")):
            return self._call("email.send", {
                "to": email, "subject": "status update", "body": "The run is complete."})

        # fs ops
        if "delete" in low:
            m = re.search(r"([\w./-]+\.\w+)", msg)
            return self._call("fs.delete", {"path": m.group(1) if m else "secret.txt"})
        if ("write" in low or "save" in low or "overwrite" in low):
            m = re.search(r"([\w./-]+\.\w+)", msg)
            return self._call("fs.write", {"path": m.group(1) if m else "note.txt",
                                            "content": "updated"})
        if "read" in low and ("file" in low or "." in msg):
            m = re.search(r"([\w./-]+\.\w+)", msg)
            if m:
                return self._call("fs.read", {"path": m.group(1)})
        if "open" in low:
            m = re.search(r"\b([a-z0-9_]+_[a-z0-9_]+|welcome|demo)\b", low)
            return self._call("web.open", {"id": m.group(1) if m else "welcome"})
        if "search" in low:
            return self._call("web.search", {"query": low.split("search", 1)[-1].strip()[:40]
                                             or "news"})
        if "email" in low or "inbox" in low:
            m = re.search(r"\bmsg\w*\b", low)
            return self._call("email.read", {"id": m.group(0) if m else "msg1"})
        return FinalResponseDecision(text="")

    def reset_state(self) -> None:
        self._n = 1

    def snapshot_state(self):
        return {"version": AGENT_STATE_VERSION, "backend": "compliant",
                "data": {"n": self._n}}

    def restore_state(self, snapshot) -> None:
        self._n = int(snapshot["data"].get("n", 1))


def compliant_factory():
    return CompliantAgent()
