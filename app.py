"""FastAPI entrypoint: wires the Shield-protected multi-agent system to a
small HTTP surface consumed by `static/index.html`.

    GET  /              - redirect to /ui
    GET  /ui            - chat UI (single-page app)
    POST /api/chat      - run one turn through the supervisor
    GET  /api/events    - poll recent Shield events (for live panel)
    POST /api/events/clear
    GET  /api/config    - agent list, roles, red-team scenarios
    POST /api/redteam   - execute the red-team attack suite
    GET  /health
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

from shield_client import shield, event_log  # noqa: E402
from agents import AGENTS, SUPERVISOR, get_system  # noqa: E402
from red_team import RED_TEAM_SCENARIOS  # noqa: E402
from db import ensure_seeded  # noqa: E402


# Create and seed the SQLite DB on first startup so the agent tools have
# something to read/write immediately. Subsequent runs are a no-op.
ensure_seeded()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="GEICO Insurance Agent (Shield-protected)", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    role: str = "customer"
    session_id: str = "default"
    history: list[dict] | None = None


class RedTeamRequest(BaseModel):
    role: str = "customer"
    scenario_ids: list[str] | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse("/ui")


@app.get("/ui", response_class=HTMLResponse)
def ui() -> HTMLResponse:
    return HTMLResponse((ROOT / "static" / "index.html").read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict:
    return {"ok": True, "shield_url": shield.base_url,
            "tenant": os.getenv("TENANT_ID", "")}


@app.get("/api/config")
def get_config() -> dict:
    return {
        "shield_url": shield.base_url,
        "tenant_id": os.getenv("TENANT_ID", ""),
        "roles": ["customer", "adjuster", "underwriter",
                  "fraud_investigator", "admin"],
        "agents": [
            {"agent_id": a.agent_id, "name": a.name,
             "description": a.description,
             "tools": a.tool_names,
             "role_permissions": a.role_permissions}
            for a in list(AGENTS.values()) + [SUPERVISOR]
        ],
        "red_team_scenarios": [
            {"id": s["id"], "title": s["title"],
             "category": s["category"],
             "expected": s["expected"],
             "prompt": s["prompt"],
             "role": s.get("role", "customer")}
            for s in RED_TEAM_SCENARIOS
        ],
    }


@app.post("/api/chat")
def chat(req: ChatRequest) -> JSONResponse:
    start = time.time()

    # Step 1 - input guardrails (boundary of the system)
    gin = shield.check_input(req.message,
                             agent_key=SUPERVISOR.agent_id,
                             user_role=req.role)
    if not gin.get("allowed", True):
        return JSONResponse({
            "blocked": True, "stage": "input",
            "reply": "Your message was blocked by the input guardrails.",
            "guardrails": gin.get("results", []),
            "latency_ms": round((time.time() - start) * 1000, 1),
        })

    # Step 2 - run the supervisor-orchestrated agent system
    try:
        system = get_system()
        reply = system.run(req.message, role=req.role,
                           chat_history=[]) or ""
    except Exception as e:  # noqa: BLE001
        event_log.record(
            kind="error", agent_key=SUPERVISOR.agent_id,
            user_role=req.role, action="error",
            summary=f"agent error: {e}", detail={"error": str(e)},
        )
        return JSONResponse({
            "blocked": True, "stage": "agent",
            "reply": f"Agent error: {e}",
            "latency_ms": round((time.time() - start) * 1000, 1),
        })

    # Step 3 - output guardrails on the final text (boundary of the system)
    gout = shield.check_output(reply,
                               agent_key=SUPERVISOR.agent_id,
                               user_role=req.role)
    sanitized = gout.get("text") or reply
    allowed = gout.get("allowed", True)
    had_redaction = bool(sanitized) and sanitized != reply

    if allowed:
        final, stage, blocked = sanitized, "ok", False
    elif had_redaction:
        # Guardrail blocked the raw text but handed us a redacted version
        # (pii_detection, role_redaction). Deliver the redacted reply so
        # the demo shows inline sanitization rather than a terse placeholder.
        final, stage, blocked = sanitized, "redacted", False
    else:
        final, stage, blocked = (
            "[Response blocked by output guardrails]", "output", True,
        )

    return JSONResponse({
        "blocked": blocked,
        "stage": stage,
        "reply": final,
        "raw_reply": reply,
        "input_guardrails": gin.get("results", []),
        "output_guardrails": gout.get("results", []),
        "latency_ms": round((time.time() - start) * 1000, 1),
    })


@app.get("/api/events")
def events(since: float | None = None) -> dict:
    return {"events": event_log.since(since), "now": time.time()}


@app.post("/api/events/clear")
def events_clear() -> dict:
    event_log.clear()
    return {"ok": True}


@app.post("/api/redteam")
def redteam(req: RedTeamRequest) -> dict:
    """Run a selection of red-team scenarios against the live system and
    return a per-scenario verdict.
    """
    from red_team import run_scenario

    results = []
    scenarios = RED_TEAM_SCENARIOS
    if req.scenario_ids:
        wanted = set(req.scenario_ids)
        scenarios = [s for s in RED_TEAM_SCENARIOS if s["id"] in wanted]

    for scenario in scenarios:
        r = run_scenario(scenario, override_role=req.role)
        results.append(r)

    return {"results": results, "total": len(results),
            "blocked": sum(1 for r in results if r["was_blocked"]),
            "expected_block": sum(1 for r in results
                                  if r["expected"] == "block")}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "7860"))
    print(f"\n  GEICO Agent UI -> http://127.0.0.1:{port}/ui\n")
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
