"""Reproduce Railway LiteLLM requests outside the Insurance Agent app.

Usage:
    # PowerShell
    $env:LITELLM_API_KEY = "<railway-master-key>"
    python openshift/debug_litellm_payload.py

    # bash
    export LITELLM_API_KEY="<railway-master-key>"
    python openshift/debug_litellm_payload.py

The script intentionally does not hardcode secrets. It compares:
  - raw `requests` calls vs the OpenAI Python SDK
  - streaming vs non-streaming
  - with and without the per-request LiteLLM guardrails opt-in
  - simple prompts vs the full supervisor tool-calling payload

The app's OpenAI debug logs showed the deployed pod failing on the full
supervisor payload with `No connected db.` from the Railway proxy. This
script narrows down whether that comes from the body shape, the SDK
transport, or something specific to the pod environment.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from typing import Any

import requests

try:
    from openai import OpenAI
except Exception:  # noqa: BLE001
    OpenAI = None  # type: ignore[assignment]


BASE_URL = os.getenv(
    "LITELLM_BASE_URL",
    "https://litellm-guardrails-votal-ai-production.up.railway.app/v1",
).rstrip("/")
MODEL = os.getenv("LLM_MODEL", "gpt-4.1-mini")
GUARDRAILS = [
    g.strip()
    for g in os.getenv(
        "LITELLM_GUARDRAILS",
        "votal-input-guard,votal-output-guard",
    ).split(",")
    if g.strip()
]
API_KEY = os.getenv("LITELLM_API_KEY")


SUPERVISOR_SYSTEM = (
    "You are the GEICO supervisor. You read the customer's request, "
    "decide which specialist should handle it, and invoke exactly one "
    "delegation tool. You do NOT answer domain questions directly - "
    "you delegate. If the question is a general FAQ/quote, delegate "
    "to the intake agent (`delegate_to_claims_agent` should be used "
    "for claim-specific issues, `delegate_to_underwriting_agent` for "
    "policy purchase/credit, `delegate_to_fraud_agent` for suspected "
    "fraud). After delegation, summarize the specialist's answer back "
    "to the user in 1-3 sentences.\n\n"
    "Available delegations: delegate_to_intake_agent (FAQ, quotes), "
    "delegate_to_claims_agent (claim-specific), "
    "delegate_to_underwriting_agent (policy bind / credit / refund), "
    "delegate_to_fraud_agent (suspected fraud)."
)


SUPERVISOR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "delegate_to_claims_agent",
            "description": (
                "Hand off a task to the Claims Agent. Use when the customer "
                "needs to\n    open, update, or ask about a specific claim."
            ),
            "parameters": {
                "properties": {
                    "task": {"type": "string"},
                    "claim_id": {"default": "", "type": "string"},
                    "customer_id": {"default": "", "type": "string"},
                },
                "required": ["task"],
                "type": "object",
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_underwriting_agent",
            "description": (
                "Hand off a task to the Underwriting Agent. Use for new "
                "policy binding,\n    credit pulls, or underwriting questions."
            ),
            "parameters": {
                "properties": {
                    "task": {"type": "string"},
                    "customer_id": {"default": "", "type": "string"},
                },
                "required": ["task"],
                "type": "object",
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_fraud_agent",
            "description": (
                "Escalate to the Fraud Investigation Agent. Customer-facing "
                "agents\n    typically cannot invoke this directly — Shield "
                "RBAC should block them."
            ),
            "parameters": {
                "properties": {
                    "task": {"type": "string"},
                    "claim_id": {"default": "", "type": "string"},
                },
                "required": ["task"],
                "type": "object",
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_intake_agent",
            "description": (
                "Forward a general insurance FAQ, coverage question, or quote "
                "request to the customer-intake agent."
            ),
            "parameters": {
                "properties": {
                    "task": {
                        "description": "The customer question or request",
                        "type": "string",
                    }
                },
                "required": ["task"],
                "type": "object",
            },
        },
    },
]


def require_key() -> str:
    if not API_KEY:
        print("ERROR: set LITELLM_API_KEY before running this script.", file=sys.stderr)
        sys.exit(2)
    return API_KEY


def base_payload(*, stream: bool, guardrails: bool, full_supervisor: bool) -> dict[str, Any]:
    if full_supervisor:
        messages = [
            {"role": "system", "content": SUPERVISOR_SYSTEM},
            {"role": "user", "content": "What is accident forgiveness?"},
        ]
        tools = SUPERVISOR_TOOLS
    else:
        messages = [{"role": "user", "content": "What is accident forgiveness?"}]
        tools = [SUPERVISOR_TOOLS[-1]]

    payload: dict[str, Any] = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.2,
        "stream": stream,
        "tools": tools,
    }
    if guardrails:
        payload["guardrails"] = GUARDRAILS
    return payload


def trim(text: str, limit: int = 900) -> str:
    text = text.replace("\n", "\\n")
    return text[:limit] + ("..." if len(text) > limit else "")


def run_requests_case(name: str, payload: dict[str, Any]) -> None:
    print(f"\n=== requests: {name} ===")
    headers = {
        "Authorization": f"Bearer {require_key()}",
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(
            f"{BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=60,
            stream=bool(payload.get("stream")),
        )
        print("HTTP", response.status_code)
        if payload.get("stream"):
            chunks: list[str] = []
            for idx, line in enumerate(response.iter_lines(decode_unicode=True)):
                if line:
                    chunks.append(line)
                if idx >= 8:
                    break
            print(trim("\n".join(chunks)))
        else:
            print(trim(response.text))
    except Exception as exc:  # noqa: BLE001
        print(f"EXCEPTION: {type(exc).__name__}: {exc}")


def stream_preview(stream: Iterator[Any], max_chunks: int = 8) -> str:
    chunks: list[str] = []
    for idx, chunk in enumerate(stream):
        chunks.append(str(chunk))
        if idx >= max_chunks - 1:
            break
    return "\n".join(chunks)


def run_openai_case(name: str, payload: dict[str, Any]) -> None:
    print(f"\n=== openai-sdk: {name} ===")
    if OpenAI is None:
        print("SKIPPED: openai package is not installed in this Python environment.")
        return

    client = OpenAI(api_key=require_key(), base_url=BASE_URL)
    try:
        kwargs = {
            "model": payload["model"],
            "messages": payload["messages"],
            "temperature": payload["temperature"],
            "tools": payload["tools"],
            "stream": payload["stream"],
        }
        if "guardrails" in payload:
            kwargs["extra_body"] = {"guardrails": payload["guardrails"]}

        response = client.chat.completions.create(**kwargs)
        if payload["stream"]:
            print(trim(stream_preview(response)))
        else:
            print(trim(response.model_dump_json()))
    except Exception as exc:  # noqa: BLE001
        print(f"EXCEPTION: {type(exc).__name__}: {exc}")
        body = getattr(exc, "body", None)
        if body:
            print("body:", json.dumps(body, indent=2, default=str))


def main() -> None:
    require_key()
    print("BASE_URL:", BASE_URL)
    print("MODEL:", MODEL)
    print("GUARDRAILS:", GUARDRAILS)

    cases = [
        ("short tools, no guardrails, non-stream", False, False, False),
        ("short tools, guardrails, non-stream", False, True, False),
        ("short tools, guardrails, stream", True, True, False),
        ("full supervisor, no guardrails, non-stream", False, False, True),
        ("full supervisor, guardrails, non-stream", False, True, True),
        ("full supervisor, guardrails, stream", True, True, True),
    ]

    for name, stream, guardrails, full_supervisor in cases:
        payload = base_payload(
            stream=stream,
            guardrails=guardrails,
            full_supervisor=full_supervisor,
        )
        run_requests_case(name, payload)
        run_openai_case(name, payload)


if __name__ == "__main__":
    main()
