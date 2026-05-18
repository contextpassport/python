"""
LangGraph integration for Context Passport.

Drops a callback handler into a LangGraph invocation that emits a Context
Passport for every node execution. Passports are chained via parent_id, so
the resulting record forms a verifiable event chain of the agent run.

Install:
    pip install "context-passport[langgraph]"

Usage:
    from context_passport.integrations.langgraph import LangGraphPassportCallback

    handler = LangGraphPassportCallback(
        agent_id="research-agent",
        agent_name="Research Agent",
        provider="anthropic",
        model="claude-opus-4-6",
    )

    result = graph.invoke({"input": "..."}, config={"callbacks": [handler]})

    # All passports created during the run, in chain order:
    for p in handler.passports:
        print(p["id"], p["event"]["type"], p["payload"]["output"])

For real production usage, pass a `commit_fn` callable that persists each
passport as it is created (e.g., POST to a Context Passport receiving server, append to a
WORM store, write to disk). The in-memory list is for development only.
"""

from __future__ import annotations

from typing import Any, Callable, Optional
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as e:
    raise ImportError(
        "LangGraph integration requires langchain-core. "
        'Install with: pip install "context-passport[langgraph]"'
    ) from e

from ..passport import make_passport


CommitFn = Callable[[dict], None]


class LangGraphPassportCallback(BaseCallbackHandler):
    """
    LangChain/LangGraph callback handler that emits a Context Passport for
    each chain/node execution.

    The handler keeps an internal chain of passports linked via parent_id.
    Each new chain step creates a `commit` passport whose `parent` is the
    most recent passport created by this handler in this run.

    Parameters
    ----------
    agent_id : str
        Unique identifier of the agent. Should be stable across runs.
    agent_name : str
        Human-readable name for the agent.
    role : str, optional
        Semantic role (researcher, writer, etc.).
    provider : str, optional
        LLM provider (anthropic, openai, etc.).
    model : str, optional
        Specific model version string.
    branch_key : str, optional
        Branch name for this run. Defaults to "main".
    trace_id : str, optional
        Pipeline run grouping identifier.
    commit_fn : callable, optional
        Function called with each emitted passport. Use this to persist
        passports as they are created. If None, passports are only retained
        in memory on self.passports.
    parent : dict, optional
        Existing passport to chain from. Use this when the LangGraph
        invocation is part of a larger workflow.
    """

    # Tell LangChain this handler is thread-safe to use in async contexts.
    raise_error = False
    run_inline = False

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        *,
        role: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        branch_key: str = "main",
        trace_id: Optional[str] = None,
        commit_fn: Optional[CommitFn] = None,
        parent: Optional[dict] = None,
    ):
        super().__init__()
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.role = role
        self.provider = provider
        self.model = model
        self.branch_key = branch_key
        self.trace_id = trace_id
        self._commit_fn = commit_fn

        # The growing list of passports created during this handler's lifetime.
        self.passports: list[dict] = []
        # The most recent passport, used as parent for the next one.
        self._latest: Optional[dict] = parent
        # Track in-flight runs so we can pair on_chain_start with on_chain_end.
        self._pending: dict[UUID, dict[str, Any]] = {}

    # ----- LangChain hooks ------------------------------------------------

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Capture inputs at the start of a chain step."""
        self._pending[run_id] = {
            "node_name": self._extract_node_name(serialized),
            "inputs": _to_jsonable(inputs),
            "tags": tags or [],
            "metadata": metadata or {},
        }

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Emit a passport when a chain step finishes."""
        pending = self._pending.pop(run_id, None)
        if pending is None:
            return  # We never saw the start. Skip.

        payload = {
            "input":  pending["inputs"],
            "output": _to_jsonable(outputs),
            "memory": {
                "node":     pending["node_name"],
                "tags":     pending["tags"],
                "metadata": pending["metadata"],
            },
        }
        self._emit(event_type="commit", payload=payload)

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Emit an error event passport when a chain step fails."""
        pending = self._pending.pop(run_id, None)
        if pending is None:
            pending = {"node_name": "unknown", "inputs": None, "tags": [], "metadata": {}}

        payload = {
            "input":  pending["inputs"],
            "output": None,
            "memory": {
                "node":          pending["node_name"],
                "error_type":    type(error).__name__,
                "error_message": str(error),
            },
        }
        self._emit(event_type="error", payload=payload)

    # ----- internal helpers ----------------------------------------------

    def _emit(self, *, event_type: str, payload: dict) -> None:
        passport = make_passport(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            payload=payload,
            parent=self._latest,
            role=self.role,
            provider=self.provider,
            model=self.model,
            event_type=event_type,
            trace_id=self.trace_id,
            branch_key=self.branch_key,
        )
        self.passports.append(passport)
        self._latest = passport
        if self._commit_fn is not None:
            try:
                self._commit_fn(passport)
            except Exception:
                # Never let a commit_fn failure break the user's graph.
                pass

    @staticmethod
    def _extract_node_name(serialized: dict[str, Any]) -> str:
        if not isinstance(serialized, dict):
            return "unknown"
        for key in ("name", "id", "lc_id"):
            value = serialized.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, list) and value:
                return ".".join(str(p) for p in value)
        return "unknown"


def _to_jsonable(value: Any) -> Any:
    """Best-effort conversion of LangChain message/object types to JSON-safe values."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    # LangChain messages have a .content attribute
    content = getattr(value, "content", None)
    if isinstance(content, (str, list, dict)):
        return {"content": _to_jsonable(content), "type": type(value).__name__}
    # Fallback: stringify
    return repr(value)
