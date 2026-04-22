"""Multi-agent LangChain orchestration wired to LLM-Shield guardrails.

Topology
--------

            ┌──────────────────────────┐
            │        Supervisor        │
            │  (routes the request to  │
            │   the right specialist)  │
            └──────┬───────────┬───────┘
                   │           │
       delegate_to_*           │
                   ▼           ▼
   ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌─────────────┐
   │  Intake  │  │  Claims  │  │Underwriting│  │    Fraud    │
   │  agent   │  │  agent   │  │   agent    │  │investigator │
   └──────────┘  └──────────┘  └────────────┘  └─────────────┘

Shield integration scope (intentional)
--------------------------------------
This app is an **integrator-perspective** test harness. It exercises
LLM-Shield only via its public HTTP API:

  * `POST /v1/guardrails/check`      - input/output guardrails (server-side)
  * `POST /v1/agents/registry`       - pushes per-agent `role_permissions`
  * `POST /v1/agents/authorize`      - per-call tool-RBAC decision
                                        (Shield evaluates role_permissions +
                                        tool-policy role_restrictions)
  * `POST /v1/data-policies/...`     - pushes per-tool Data Policies

We do NOT re-implement any policy decision client-side. For tool RBAC we
ask Shield to decide via `/v1/agents/authorize`; if that call fails we
fail CLOSED (deny the tool). The only local action this wrapper takes is
stamping the active `user_role` onto the DB session so the seeded
`audit_log` table records a truthful actor - that is application-level
telemetry, not a security control.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import BaseTool, StructuredTool
from langchain_openai import ChatOpenAI
try:
    # LangChain >= 1.0 moved the classic AgentExecutor to langchain_classic
    from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
except ImportError:  # pragma: no cover — legacy <1.0
    from langchain.agents import AgentExecutor, create_tool_calling_agent

from shield_client import shield, event_log
from db import current_role as _current_role_var
import tools as T


# ---------------------------------------------------------------------------
# Agent definitions (agent_id, tools, role_permissions)
# ---------------------------------------------------------------------------

@dataclass
class AgentDef:
    agent_id: str
    name: str
    description: str
    system_prompt: str
    tool_names: list[str]
    # Maps role -> list of tool names the role can invoke on this agent.
    role_permissions: dict[str, list[str]] = field(default_factory=dict)


AGENTS: dict[str, AgentDef] = {
    "intake-agent": AgentDef(
        agent_id="intake-agent",
        name="GEICO Customer Intake Agent",
        description="Customer-facing intake. Answers FAQ via RAG, generates "
                    "quotes, and routes requests to specialist agents.",
        system_prompt=(
            "You are the GEICO customer intake assistant. You ONLY discuss "
            "GEICO insurance products: auto, home, motorcycle, and claims. "
            "Use `search_policy_docs` for any factual question about "
            "coverage, discounts, claims, or FAQ. Never invent policy "
            "details - if the RAG does not answer the question, say so. "
            "If the customer needs to open or check a specific claim, call "
            "`delegate_to_claims_agent`. If they want to buy or change a "
            "policy, call `delegate_to_underwriting_agent`. Never discuss "
            "competitors, give medical/legal advice, or help with anything "
            "outside insurance."
        ),
        tool_names=[
            "search_policy_docs",
            "quote_estimate",
            "delegate_to_claims_agent",
            "delegate_to_underwriting_agent",
        ],
        role_permissions={
            "customer": [
                "search_policy_docs", "quote_estimate",
                "delegate_to_claims_agent", "delegate_to_underwriting_agent",
            ],
            "adjuster": [
                "search_policy_docs", "quote_estimate",
                "delegate_to_claims_agent", "delegate_to_underwriting_agent",
                "delegate_to_fraud_agent",
            ],
            "underwriter": [
                "search_policy_docs", "quote_estimate",
                "delegate_to_claims_agent", "delegate_to_underwriting_agent",
            ],
            "fraud_investigator": [
                "search_policy_docs", "quote_estimate",
                "delegate_to_claims_agent", "delegate_to_underwriting_agent",
                "delegate_to_fraud_agent",
            ],
            "admin": [
                "search_policy_docs", "quote_estimate",
                "delegate_to_claims_agent", "delegate_to_underwriting_agent",
                "delegate_to_fraud_agent",
            ],
        },
    ),

    "claims-agent": AgentDef(
        agent_id="claims-agent",
        name="GEICO Claims Agent",
        description="Handles claim lookups, status updates, adjuster "
                    "payments, and fraud escalations.",
        system_prompt=(
            "You are the GEICO claims specialist. Use `get_claim` to read "
            "claim state, `update_claim_status` to change it, and "
            "`approve_claim_payment` to release funds - but only within "
            "your authority limit (Claim Rep $5k, Senior Adjuster $25k, "
            "Supervisor $100k). If the claim's fraud score exceeds 0.5 or "
            "the circumstances are suspicious, call "
            "`flag_for_fraud_investigation` or delegate to the fraud agent. "
            "Never share more PII than necessary to resolve the claim."
        ),
        tool_names=[
            "search_policy_docs", "get_claim", "update_claim_status",
            "approve_claim_payment", "flag_for_fraud_investigation",
            "delegate_to_fraud_agent",
        ],
        role_permissions={
            "customer":            ["search_policy_docs", "get_claim"],
            "adjuster": [
                "search_policy_docs", "get_claim", "update_claim_status",
                "approve_claim_payment", "flag_for_fraud_investigation",
                "delegate_to_fraud_agent",
            ],
            "underwriter":         ["search_policy_docs", "get_claim"],
            "fraud_investigator": [
                "search_policy_docs", "get_claim", "update_claim_status",
                "flag_for_fraud_investigation",
            ],
            "admin": [
                "search_policy_docs", "get_claim", "update_claim_status",
                "approve_claim_payment", "flag_for_fraud_investigation",
                "delegate_to_fraud_agent",
            ],
        },
    ),

    "underwriting-agent": AgentDef(
        agent_id="underwriting-agent",
        name="GEICO Underwriting Agent",
        description="Pulls credit, prices risk, binds/cancels policies, "
                    "issues refunds.",
        system_prompt=(
            "You are the GEICO underwriting specialist. You price and bind "
            "new policies. Call `lookup_customer` to verify identity, "
            "`pull_credit_report` ONLY with a permissible purpose under "
            "FCRA, and `bind_policy` to put coverage in force. Use "
            "`issue_refund` or `cancel_policy` for post-bind changes. "
            "For portfolio analytics (book of business, premium totals, "
            "loss ratios, risk segmentation) use `run_analytics_query` "
            "with a READ-ONLY SQL SELECT against the warehouse. "
            "Never share SSN or full credit scores back to the caller in "
            "plain text."
        ),
        tool_names=[
            "search_policy_docs", "lookup_customer", "pull_credit_report",
            "quote_estimate", "bind_policy", "cancel_policy", "issue_refund",
            "run_analytics_query",
        ],
        role_permissions={
            "customer":           ["search_policy_docs", "quote_estimate"],
            "adjuster":           ["search_policy_docs", "lookup_customer",
                                   "quote_estimate"],
            "underwriter": [
                "search_policy_docs", "lookup_customer", "pull_credit_report",
                "quote_estimate", "bind_policy", "cancel_policy",
                "run_analytics_query",
            ],
            "fraud_investigator": ["search_policy_docs", "lookup_customer",
                                   "pull_credit_report",
                                   "run_analytics_query"],
            "admin": [
                "search_policy_docs", "lookup_customer", "pull_credit_report",
                "quote_estimate", "bind_policy", "cancel_policy",
                "issue_refund", "run_analytics_query",
            ],
        },
    ),

    "fraud-agent": AgentDef(
        agent_id="fraud-agent",
        name="GEICO Special Investigations Unit (SIU)",
        description="Elevated privilege. Cross-customer investigation, "
                    "fraud flagging, record deletion under legal hold.",
        system_prompt=(
            "You are a GEICO Special Investigations Unit (SIU) "
            "investigator. Examine suspicious claims, correlate patterns "
            "across customers, and flag fraud. You have elevated access - "
            "use `lookup_customer` and `pull_credit_report` only for "
            "active investigations. Use `run_analytics_query` (READ-ONLY "
            "SELECT) for cross-customer pattern analysis such as "
            "clustering claims by adjuster, fraud_score distributions, "
            "unusually short policy-to-claim intervals, etc. Document "
            "every lookup with a reason."
        ),
        tool_names=[
            "search_policy_docs", "get_claim", "lookup_customer",
            "pull_credit_report", "flag_for_fraud_investigation",
            "delete_customer_record", "run_analytics_query",
        ],
        role_permissions={
            "customer":   [],
            "adjuster":   ["search_policy_docs", "get_claim"],
            "underwriter": ["search_policy_docs", "get_claim",
                            "lookup_customer"],
            "fraud_investigator": [
                "search_policy_docs", "get_claim", "lookup_customer",
                "pull_credit_report", "flag_for_fraud_investigation",
                "run_analytics_query",
            ],
            "admin": [
                "search_policy_docs", "get_claim", "lookup_customer",
                "pull_credit_report", "flag_for_fraud_investigation",
                "delete_customer_record", "run_analytics_query",
            ],
        },
    ),
}


# ---------------------------------------------------------------------------
# Supervisor definition (routing)
# ---------------------------------------------------------------------------

SUPERVISOR = AgentDef(
    agent_id="supervisor-agent",
    name="GEICO Supervisor / Router",
    description="Top-level router. Decides which specialist agent should "
                "handle the request and delegates to it.",
    system_prompt=(
        "You are the GEICO supervisor. You read the customer's request, "
        "decide which specialist should handle it, and invoke exactly one "
        "delegation tool. You do NOT answer domain questions directly - "
        "you delegate. If the question is a general FAQ/quote, delegate "
        "to the intake agent (`delegate_to_claims_agent` should be used "
        "for claim-specific issues, `delegate_to_underwriting_agent` for "
        "policy purchase/credit, `delegate_to_fraud_agent` for suspected "
        "fraud). After delegation, summarize the specialist's answer back "
        "to the user in 1-3 sentences."
    ),
    tool_names=[
        "delegate_to_claims_agent",
        "delegate_to_underwriting_agent",
        "delegate_to_fraud_agent",
    ],
    role_permissions={
        "customer": ["delegate_to_claims_agent",
                     "delegate_to_underwriting_agent"],
        "adjuster": ["delegate_to_claims_agent",
                     "delegate_to_underwriting_agent",
                     "delegate_to_fraud_agent"],
        "underwriter": ["delegate_to_claims_agent",
                        "delegate_to_underwriting_agent"],
        "fraud_investigator": ["delegate_to_claims_agent",
                               "delegate_to_underwriting_agent",
                               "delegate_to_fraud_agent"],
        "admin": ["delegate_to_claims_agent",
                  "delegate_to_underwriting_agent",
                  "delegate_to_fraud_agent"],
    },
)


# ---------------------------------------------------------------------------
# Tool wrapping - asks Shield for a per-call tool-authorization decision
# (POST /v1/agents/authorize), then stamps the caller role onto the DB
# session so the `audit_log` table gets a truthful actor. Shield evaluates
# both the agent-registry `role_permissions` and the tool-policy
# `role_restrictions` server-side; on error we fail CLOSED.
# ---------------------------------------------------------------------------

def _wrap_tool_with_role_context(tool_obj: BaseTool, agent_key: str,
                                 role_getter) -> BaseTool:
    """Return a StructuredTool that (1) asks Shield whether the caller may
    invoke this tool, and (2) if allowed, records the active user_role on
    the thread-local DB session before delegating to the original tool.
    """
    original = tool_obj
    name = tool_obj.name
    description = tool_obj.description
    args_schema = getattr(tool_obj, "args_schema", None)

    def _run(**kwargs):
        role = role_getter() or "customer"

        decision = shield.authorize_tool(
            agent_id=agent_key,
            tool_name=name,
            user_role=role,
            tool_input=kwargs,
        )
        if not decision.get("allowed", False):
            reason = decision.get("reason") or "not permitted"
            return (
                f"[SHIELD RBAC BLOCK] Tool '{name}' denied for role "
                f"'{role}' on agent '{agent_key}'. Shield reason: {reason}. "
                f"Please inform the user and do not retry this tool call."
            )

        token = _current_role_var.set(role)
        try:
            return original.invoke(kwargs)
        finally:
            _current_role_var.reset(token)

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=description,
        args_schema=args_schema,
    )


# ---------------------------------------------------------------------------
# Specialist agent factory
# ---------------------------------------------------------------------------

class _RoleHolder:
    """Lightweight mutable container the wrappers read at call-time."""
    role: str = "customer"


class Specialist:
    """A single LangChain tool-calling agent wrapped with Shield RBAC."""

    def __init__(self, agent_def: AgentDef, llm: ChatOpenAI) -> None:
        self.agent_def = agent_def
        self._role_holder = _RoleHolder()
        raw_tools = T.tools_for(agent_def.tool_names)
        self.tools = [
            _wrap_tool_with_role_context(t, agent_def.agent_id,
                                         lambda: self._role_holder.role)
            for t in raw_tools
        ]
        prompt = ChatPromptTemplate.from_messages([
            ("system", agent_def.system_prompt),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        agent = create_tool_calling_agent(llm, self.tools, prompt)
        self.executor = AgentExecutor(
            agent=agent, tools=self.tools,
            verbose=False, handle_parsing_errors=True,
            max_iterations=6,
        )

    def run(self, query: str, role: str, chat_history: list | None = None) -> str:
        self._role_holder.role = role
        result = self.executor.invoke({
            "input": query,
            "chat_history": chat_history or [],
        })
        return result.get("output") or ""


# ---------------------------------------------------------------------------
# Supervisor with real delegation (calls into Specialist executors)
# ---------------------------------------------------------------------------

class MultiAgentSystem:
    def __init__(self, llm_model: str | None = None) -> None:
        model = llm_model or os.getenv("LLM_MODEL", "gpt-4o-mini")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required")

        self.llm = ChatOpenAI(model=model, temperature=0.2, api_key=api_key)

        self.specialists: dict[str, Specialist] = {
            agent_def.agent_id: Specialist(agent_def, self.llm)
            for agent_def in AGENTS.values()
        }

        self._role_holder = _RoleHolder()
        self.supervisor = self._build_supervisor()

    # ---- supervisor build ------------------------------------------------

    def _build_supervisor(self) -> AgentExecutor:
        """Supervisor reuses the same delegate_* tool *names* but bound to
        real function calls that invoke the downstream specialists.
        """
        llm = self.llm
        role_holder = self._role_holder

        def _delegation_tool(target_agent_id: str, tool_name: str):
            def run(**kwargs) -> str:
                role = role_holder.role or "customer"

                # Ask Shield whether the caller may invoke this delegation
                # tool on the supervisor. Shield evaluates supervisor's
                # role_permissions + any tool-policy role_restrictions for
                # `delegate_to_*` tools, server-side.
                decision = shield.authorize_tool(
                    agent_id=SUPERVISOR.agent_id,
                    tool_name=tool_name,
                    user_role=role,
                    tool_input=kwargs,
                )
                if not decision.get("allowed", False):
                    reason = decision.get("reason") or "not permitted"
                    return (
                        f"[SHIELD RBAC BLOCK] Cross-agent delegation "
                        f"'{tool_name}' denied for role '{role}'. "
                        f"Shield reason: {reason}."
                    )

                event_log.record(
                    kind="agent_chat",
                    agent_key=SUPERVISOR.agent_id,
                    user_role=role,
                    action="allow",
                    summary=f"supervisor -> {target_agent_id} delegation",
                    detail={"tool": tool_name, "args": kwargs},
                )

                task = kwargs.get("task") or ""
                specialist = self.specialists[target_agent_id]
                return specialist.run(task, role=role)
            return run

        deleg_tools = [
            StructuredTool.from_function(
                func=_delegation_tool("claims-agent",
                                      "delegate_to_claims_agent"),
                name="delegate_to_claims_agent",
                description=T.delegate_to_claims_agent.description,
                args_schema=T.delegate_to_claims_agent.args_schema,
            ),
            StructuredTool.from_function(
                func=_delegation_tool("underwriting-agent",
                                      "delegate_to_underwriting_agent"),
                name="delegate_to_underwriting_agent",
                description=T.delegate_to_underwriting_agent.description,
                args_schema=T.delegate_to_underwriting_agent.args_schema,
            ),
            StructuredTool.from_function(
                func=_delegation_tool("fraud-agent",
                                      "delegate_to_fraud_agent"),
                name="delegate_to_fraud_agent",
                description=T.delegate_to_fraud_agent.description,
                args_schema=T.delegate_to_fraud_agent.args_schema,
            ),
        ]

        # The supervisor also talks directly to the intake-agent for simple
        # FAQ/quote queries (no RBAC hop required because it's the default
        # path for the `customer` role).
        def _intake(**kwargs) -> str:
            role = role_holder.role or "customer"
            event_log.record(
                kind="agent_chat",
                agent_key=SUPERVISOR.agent_id,
                user_role=role,
                action="allow",
                summary="supervisor -> intake-agent",
                detail={"args": kwargs},
            )
            return self.specialists["intake-agent"].run(
                kwargs.get("task", ""), role=role,
            )

        from pydantic import BaseModel, Field

        class _IntakeArgs(BaseModel):
            task: str = Field(description="The customer question or request")

        deleg_tools.append(StructuredTool.from_function(
            func=_intake,
            name="delegate_to_intake_agent",
            description=(
                "Forward a general insurance FAQ, coverage question, or "
                "quote request to the customer-intake agent."
            ),
            args_schema=_IntakeArgs,
        ))

        prompt = ChatPromptTemplate.from_messages([
            ("system", SUPERVISOR.system_prompt + (
                "\n\nAvailable delegations: delegate_to_intake_agent (FAQ, "
                "quotes), delegate_to_claims_agent (claim-specific), "
                "delegate_to_underwriting_agent (policy bind / credit / "
                "refund), delegate_to_fraud_agent (suspected fraud)."
            )),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        sup_agent = create_tool_calling_agent(llm, deleg_tools, prompt)
        return AgentExecutor(
            agent=sup_agent, tools=deleg_tools,
            verbose=False, handle_parsing_errors=True,
            max_iterations=4,
        )

    # ---- public -----------------------------------------------------------

    def run(self, query: str, role: str,
            chat_history: list | None = None) -> str:
        self._role_holder.role = role or "customer"
        for spec in self.specialists.values():
            spec._role_holder.role = self._role_holder.role
        result = self.supervisor.invoke({
            "input": query,
            "chat_history": chat_history or [],
        })
        return result.get("output") or ""


_system: MultiAgentSystem | None = None


def get_system() -> MultiAgentSystem:
    global _system
    if _system is None:
        _system = MultiAgentSystem()
    return _system
