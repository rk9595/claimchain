"""Thin client wrapper for the LLM Shield REST API.

Every call records an `Event` onto a bounded in-memory ring buffer so the UI
can render a live timeline of what the shield did on every request. This is
the single integration point the rest of the app uses - agents, tools, RAG,
and the red-team suite all go through `shield`.
"""

from __future__ import annotations

import os
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from threading import Lock
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Event log
# ---------------------------------------------------------------------------

@dataclass
class ShieldEvent:
    id: str
    ts: float
    kind: str                       # "input" | "output" | "rbac" | "agent_chat" | "register" | "error"
    agent_key: str
    user_role: str
    action: str                     # "allow" | "block" | "warn" | "redact" | "error"
    summary: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class EventLog:
    """Thread-safe, bounded ring buffer of recent ShieldEvents."""

    def __init__(self, maxlen: int = 500) -> None:
        self._events: deque[ShieldEvent] = deque(maxlen=maxlen)
        self._lock = Lock()

    def record(self, **kwargs: Any) -> ShieldEvent:
        ev = ShieldEvent(
            id=str(uuid.uuid4()),
            ts=time.time(),
            **kwargs,
        )
        with self._lock:
            self._events.append(ev)
        return ev

    def since(self, ts: float | None = None) -> list[dict]:
        with self._lock:
            items = list(self._events)
        if ts is None:
            return [e.to_dict() for e in items]
        return [e.to_dict() for e in items if e.ts > ts]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


event_log = EventLog()


# ---------------------------------------------------------------------------
# Shield client
# ---------------------------------------------------------------------------

class ShieldClient:
    """Thin wrapper over the LLM Shield REST API.

    Every HTTP call is wrapped in try/except so the host app never crashes
    if the shield is unreachable - instead it records an `error` event and
    returns a degraded-but-safe response.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        admin_key: str | None = None,
        runpod_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("LLM_SHIELD_URL", "http://localhost:8080")).rstrip("/")
        self.api_key = api_key or os.getenv("TENANT_API_KEY", "")
        self.admin_key = admin_key or os.getenv("SHIELD_ADMIN_KEY", "")
        # RunPod gateway requires a Bearer token in front of the Shield.
        self.runpod_token = runpod_token or os.getenv("RUNPOD_TOKEN", "")
        self.timeout = timeout
        self._session = requests.Session()

    # -- low-level ---------------------------------------------------------

    def _headers(self, agent_key: str = "", user_role: str = "", admin: bool = False) -> dict:
        h = {"Content-Type": "application/json"}
        if self.runpod_token:
            h["Authorization"] = f"Bearer {self.runpod_token}"
        if admin and self.admin_key:
            h["X-Admin-Key"] = self.admin_key
        if self.api_key:
            h["X-API-Key"] = self.api_key
        if agent_key:
            h["X-Agent-Key"] = agent_key
        if user_role:
            h["X-User-Role"] = user_role
        return h

    def _post(self, path: str, json: dict, agent_key: str = "", user_role: str = "",
              admin: bool = False) -> tuple[int, dict | str]:
        try:
            r = self._session.post(
                f"{self.base_url}{path}",
                json=json,
                headers=self._headers(agent_key, user_role, admin),
                timeout=self.timeout,
            )
        except Exception as e:  # noqa: BLE001
            return 599, {"error": str(e)}
        try:
            return r.status_code, r.json()
        except Exception:  # noqa: BLE001
            return r.status_code, r.text

    def _get(self, path: str, admin: bool = False) -> tuple[int, dict | str]:
        try:
            r = self._session.get(
                f"{self.base_url}{path}",
                headers=self._headers(admin=admin),
                timeout=self.timeout,
            )
        except Exception as e:  # noqa: BLE001
            return 599, {"error": str(e)}
        try:
            return r.status_code, r.json()
        except Exception:  # noqa: BLE001
            return r.status_code, r.text

    # -- guardrails --------------------------------------------------------

    def check_input(self, message: str, agent_key: str, user_role: str) -> dict:
        """Run `/guardrails/input` and log the decision.

        Returns a dict: `{"allowed": bool, "action": str, "results": [...], "raw": dict}`.
        Network/server errors fail-open (allowed=True) but are logged as errors
        so the operator can see when the shield is unreachable.
        """
        status, body = self._post(
            "/guardrails/input",
            json={"message": message},
            agent_key=agent_key,
            user_role=user_role,
        )
        if status != 200 or not isinstance(body, dict):
            event_log.record(
                kind="input", agent_key=agent_key, user_role=user_role,
                action="error", summary=f"input-guardrail error {status}",
                detail={"status": status, "body": body},
            )
            return {"allowed": True, "action": "allow", "results": [], "raw": body, "error": True}

        action = body.get("action", "allow")
        allowed = action != "block"
        triggered = [
            r.get("guardrail", "?") for r in body.get("guardrail_results", [])
            if r.get("action") in ("block", "warn", "redact")
        ]
        summary = (
            f"input BLOCKED by {', '.join(triggered) or 'guardrail'}"
            if action == "block"
            else f"input {action} ({', '.join(triggered) or 'all clean'})"
        )
        event_log.record(
            kind="input", agent_key=agent_key, user_role=user_role,
            action="block" if action == "block" else action,
            summary=summary,
            detail={"message": message[:500], "guardrail_results": body.get("guardrail_results", [])},
        )
        return {"allowed": allowed, "action": action, "results": body.get("guardrail_results", []), "raw": body}

    def check_output(self, text: str, agent_key: str, user_role: str) -> dict:
        """Run `/guardrails/output` and log the decision."""
        status, body = self._post(
            "/guardrails/output",
            json={"output": text},
            agent_key=agent_key,
            user_role=user_role,
        )
        if status != 200 or not isinstance(body, dict):
            event_log.record(
                kind="output", agent_key=agent_key, user_role=user_role,
                action="error", summary=f"output-guardrail error {status}",
                detail={"status": status, "body": body},
            )
            return {"allowed": True, "action": "allow", "text": text, "raw": body, "error": True}

        action = body.get("action", "allow")
        allowed = action != "block"

        # Shield's schema rejects `action: "redact"` for output guardrails, so
        # rules like `pii_detection` are configured with `action: "warn"`. The
        # engine still computes a redacted string, but it's nested one level
        # deeper than the top-level `text` field. Walk the guardrail results
        # and apply the deepest redaction found so the user never sees the
        # raw PII in the chat UI.
        redacted_text = body.get("redacted_text") or body.get("text") or text
        for r in body.get("guardrail_results", []):
            d = r.get("details") or {}
            nested = d.get("redacted_text") or d.get("redacted") or d.get("sanitized_text")
            if nested and nested != redacted_text:
                redacted_text = nested

        triggered = [
            r.get("guardrail", "?") for r in body.get("guardrail_results", [])
            if r.get("action") in ("block", "warn", "redact")
        ]
        summary = (
            f"output BLOCKED by {', '.join(triggered) or 'guardrail'}"
            if action == "block"
            else f"output {action} ({', '.join(triggered) or 'clean'})"
        )
        event_log.record(
            kind="output", agent_key=agent_key, user_role=user_role,
            action="block" if action == "block" else action,
            summary=summary,
            detail={"original": text[:500], "redacted": redacted_text[:500],
                    "guardrail_results": body.get("guardrail_results", [])},
        )
        return {
            "allowed": allowed, "action": action, "text": redacted_text,
            "results": body.get("guardrail_results", []), "raw": body,
        }

    # -- agent chat / RBAC -------------------------------------------------

    def agent_chat(
        self,
        messages: list[dict],
        agent_key: str,
        user_role: str,
        tools: list[dict] | None = None,
        llm_api_key: str | None = None,
        llm_model: str | None = None,
    ) -> dict:
        """Call `/v1/shield/chat/agent` which runs input guards, calls the LLM
        with tool definitions, and enforces RBAC on each tool call.
        """
        payload = {
            "messages": messages,
            "agent_key": agent_key,
            "user_role": user_role,
        }
        if tools:
            payload["tools"] = tools
        if llm_api_key:
            payload["llm_api_key"] = llm_api_key
        if llm_model:
            payload["llm_model"] = llm_model

        status, body = self._post(
            "/v1/shield/chat/agent",
            json=payload,
            agent_key=agent_key,
            user_role=user_role,
        )
        if status == 200 and isinstance(body, dict):
            for tc in body.get("tool_calls", []):
                rbac = tc.get("rbac", {}) or {}
                allowed = rbac.get("allowed", False)
                event_log.record(
                    kind="rbac", agent_key=agent_key, user_role=user_role,
                    action="allow" if allowed else "block",
                    summary=(f"RBAC {'ALLOW' if allowed else 'BLOCK'} "
                             f"{tc.get('tool_name')} for role={user_role}"),
                    detail={"tool_name": tc.get("tool_name"),
                            "arguments": tc.get("arguments"),
                            "rbac": rbac},
                )
            event_log.record(
                kind="agent_chat", agent_key=agent_key, user_role=user_role,
                action="allow",
                summary=f"agent_chat ok — {len(body.get('tool_calls', []))} tool call(s)",
                detail={"text": (body.get("text") or "")[:300],
                        "latency_ms": body.get("latency_ms")},
            )
            return body

        if isinstance(body, dict) and body.get("blocked"):
            event_log.record(
                kind="agent_chat", agent_key=agent_key, user_role=user_role,
                action="block",
                summary=f"agent_chat blocked at {body.get('stage')}: {body.get('block_reason')}",
                detail=body,
            )
            return body

        event_log.record(
            kind="agent_chat", agent_key=agent_key, user_role=user_role,
            action="error",
            summary=f"agent_chat error {status}",
            detail={"status": status, "body": body},
        )
        return {"error": True, "status": status, "body": body}

    # -- tool authorization (server-side decision) ------------------------

    def authorize_tool(self, agent_id: str, tool_name: str,
                       user_role: str, tool_input: dict | None = None) -> dict:
        """Ask Shield whether a (agent, role, tool) tuple is allowed.

        Calls `POST /v1/agents/authorize`, which evaluates, in order:
          1. Is the agent registered?
          2. Is `tool_name` in the agent's tools list?
          3. Is `user_role` listed in the agent's `role_permissions[tool_name]`?
          4. Is the tool policy's `role_restrictions[user_role]` == "block"?

        Returns the raw Shield response:
            {"allowed": bool, "reason": str,
             "agent_config": {...}, "tool_policy": {...}}

        On network error, fails CLOSED (`allowed=false`) and logs the error —
        we'd rather refuse a tool call than silently execute when Shield is
        unreachable.
        """
        payload = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "user_role": user_role,
            "tool_input": tool_input or {},
        }
        status, body = self._post(
            "/v1/agents/authorize",
            json=payload,
            agent_key=agent_id,
            user_role=user_role,
        )

        if status != 200 or not isinstance(body, dict):
            event_log.record(
                kind="rbac", agent_key=agent_id, user_role=user_role,
                action="error",
                summary=(f"authorize_tool error {status} — failing CLOSED "
                         f"for {tool_name}"),
                detail={"tool": tool_name, "status": status, "body": body},
            )
            return {
                "allowed": False,
                "reason": f"Shield authorize endpoint error ({status})",
                "error": True,
                "status": status,
                "body": body,
            }

        allowed = bool(body.get("allowed", False))
        event_log.record(
            kind="rbac", agent_key=agent_id, user_role=user_role,
            action="allow" if allowed else "block",
            summary=(f"RBAC {'ALLOW' if allowed else 'BLOCK'} {tool_name} "
                     f"for role={user_role} on {agent_id}"),
            detail={
                "tool": tool_name,
                "role": user_role,
                "reason": body.get("reason"),
                "tool_policy": body.get("tool_policy"),
            },
        )
        return body

    # -- registry ----------------------------------------------------------

    def register_agent(self, agent_id: str, name: str, description: str,
                       tools: list[str], role_permissions: dict[str, list[str]]) -> dict:
        payload = {
            "agent_id": agent_id,
            "name": name,
            "description": description,
            "tools": tools,
            "role_permissions": role_permissions,
        }
        status, body = self._post("/v1/agents/registry", json=payload)
        event_log.record(
            kind="register", agent_key=agent_id, user_role="",
            action="allow" if status in (200, 201) else "error",
            summary=f"register_agent {agent_id}: {status}",
            detail={"status": status, "body": body},
        )
        return {"status": status, "body": body}

    def list_unregistered(self) -> dict:
        status, body = self._get("/v1/agents/unregistered")
        return body if isinstance(body, dict) else {"error": body, "status": status}


# Module-level default client, wired up from environment variables.
shield = ShieldClient()
