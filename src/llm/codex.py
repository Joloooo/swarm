"""ChatGPT subscription LLM via the Codex backend API.

Uses your existing Codex CLI OAuth tokens (~/.codex/auth.json) to call
the ChatGPT backend API at chatgpt.com/backend-api/codex/responses.
This lets you use GPT-5.x Codex models with your ChatGPT Plus/Pro
subscription — no API keys or extra costs.

Protocol details reverse-engineered from OpenCode v1.4.0 and the
OpenAI Codex CLI source code:
  - Client ID:  app_EMoamEEZ73f0CkXaXp7hrann
  - Issuer:     https://auth.openai.com
  - Endpoint:   https://chatgpt.com/backend-api/codex/responses
  - Wire format: OpenAI Responses API (SSE streaming)
  - Auth header: Authorization: Bearer {access_token}
  - Extra header: ChatGPT-Account-Id: {account_id}
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from contextlib import aclosing, closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

import httpx

logger = logging.getLogger(__name__)

# --- Constants (from OpenCode v1.4.0 / Codex CLI) ---

CODEX_API_ENDPOINT = "https://chatgpt.com/backend-api/codex/responses"
AUTH_ISSUER = "https://auth.openai.com"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_CODEX_HOME = Path.home() / ".codex"


# --- Token management ---

@dataclass
class CodexTokens:
    access_token: str
    refresh_token: str
    account_id: str
    expires_at: float  # unix timestamp (seconds)


def load_tokens(codex_home: Path | None = None) -> CodexTokens:
    """Load OAuth tokens from the Codex CLI's auth.json."""
    auth_file = (codex_home or DEFAULT_CODEX_HOME) / "auth.json"
    if not auth_file.exists():
        raise FileNotFoundError(
            f"No Codex auth found at {auth_file}. "
            "Run `codex` and sign in with ChatGPT first."
        )

    data = json.loads(auth_file.read_text())
    tokens = data.get("tokens") or {}
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")

    if not access_token:
        raise ValueError("No access_token in Codex auth.json. Re-authenticate with `codex`.")

    # Extract account_id (directly stored, or from JWT claims)
    account_id = tokens.get("account_id", "")
    if not account_id:
        account_id = _extract_account_id_from_jwt(access_token)

    # Extract expiry from JWT
    expires_at = _extract_jwt_expiry(access_token)

    return CodexTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        account_id=account_id,
        expires_at=expires_at,
    )


def refresh_access_token(tokens: CodexTokens) -> CodexTokens:
    """Refresh the access token using the refresh token."""
    resp = httpx.post(
        f"{AUTH_ISSUER}/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": tokens.refresh_token,
        },
        timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()

    new_access = data["access_token"]
    new_refresh = data.get("refresh_token", tokens.refresh_token)
    new_expiry = _extract_jwt_expiry(new_access)
    new_account_id = tokens.account_id or _extract_account_id_from_jwt(new_access)

    logger.info("Refreshed Codex access token (expires %.0fs from now)", new_expiry - time.time())

    return CodexTokens(
        access_token=new_access,
        refresh_token=new_refresh,
        account_id=new_account_id,
        expires_at=new_expiry,
    )


def _extract_jwt_expiry(token: str) -> float:
    """Extract exp claim from a JWT without verification."""
    try:
        payload = _decode_jwt_payload(token)
        return float(payload.get("exp", 0))
    except Exception:
        return 0.0


def _extract_account_id_from_jwt(token: str) -> str:
    """Extract chatgpt_account_id from JWT claims."""
    try:
        payload = _decode_jwt_payload(token)
        auth_claims = payload.get("https://api.openai.com/auth", {})
        return auth_claims.get("chatgpt_account_id", "")
    except Exception:
        return ""


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload (no signature verification — we trust our own tokens)."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# --- Responses API SSE client ---

def _parse_sse_lines(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    """Parse SSE text lines into JSON event dicts."""
    data_lines: list[str] = []
    for raw in lines:
        line = raw.rstrip("\n")
        if not line:
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                if payload.strip() == "[DONE]":
                    continue
                try:
                    yield json.loads(payload)
                except json.JSONDecodeError:
                    continue
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())

    if data_lines:
        payload = "\n".join(data_lines)
        if payload.strip() != "[DONE]":
            try:
                yield json.loads(payload)
            except json.JSONDecodeError:
                pass


def _build_reasoning_block(
    effort: str | None, summary: str | None
) -> dict[str, str] | None:
    """Build the ``reasoning`` JSON sub-object for a Codex request.

    Mirrors the upstream Codex CLI logic
    (``codex-rs/core/src/client.rs::create_reasoning_param``). When the
    summary is ``"none"``, the wire field is omitted entirely (matches the
    Rust ``ReasoningSummaryConfig::None`` → ``None`` branch). Returns
    ``None`` when neither effort nor a real summary is set, so the whole
    ``reasoning`` key is dropped from the body.
    """
    block: dict[str, str] = {}
    if effort:
        block["effort"] = effort
    # "none" disables summaries — omit the field rather than sending it.
    if summary and summary != "none":
        block["summary"] = summary
    return block or None


def stream_codex(
    tokens: CodexTokens,
    *,
    model: str,
    input_items: list[dict],
    instructions: str = "",
    tools: list[dict] | None = None,
    tool_choice: str | None = None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
    reasoning_effort: str | None = None,
    reasoning_summary: str | None = None,
    timeout: float = 120.0,
) -> Iterator[dict[str, Any]]:
    """Stream SSE events from the Codex Responses API.

    ``reasoning_effort`` valid values: "none" | "minimal" | "low" |
    "medium" | "high" | "xhigh" (lowercase, exact).
    ``reasoning_summary`` valid values: "auto" | "concise" | "detailed" |
    "none" (lowercase, exact). When ``"none"`` the field is dropped.
    """
    body: dict[str, Any] = {
        "model": model,
        "input": input_items,
        "store": False,
        "stream": True,
        # "reasoning.encrypted_content" is the opaque blob used for
        # multi-turn chaining of internal reasoning. Human-readable
        # summaries are NOT requested via this array — they come back
        # automatically when ``reasoning.summary`` is set in the body
        # (see ``_build_reasoning_block``).
        "include": ["reasoning.encrypted_content"],
    }
    reasoning_block = _build_reasoning_block(reasoning_effort, reasoning_summary)
    if reasoning_block:
        body["reasoning"] = reasoning_block
    if instructions:
        body["instructions"] = instructions
    if tools:
        body["tools"] = tools
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    if temperature is not None:
        body["temperature"] = temperature
    if max_output_tokens is not None:
        body["max_output_tokens"] = max_output_tokens

    headers = {
        "Authorization": f"Bearer {tokens.access_token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if tokens.account_id:
        headers["ChatGPT-Account-Id"] = tokens.account_id

    # Some parameters are silently unsupported by certain models.
    # Retry once with the offending parameter removed on 400.
    # ``reasoning`` is included so older models that don't support it
    # gracefully fall back instead of erroring.
    removable_keys = [
        "temperature", "max_output_tokens", "tool_choice", "reasoning",
    ]

    try:
        with httpx.Client(timeout=timeout) as client:
            while True:
                with client.stream("POST", CODEX_API_ENDPOINT, json=body, headers=headers) as resp:
                    if resp.status_code == 400:
                        resp.read()
                        error_text = resp.text.lower()
                        removed = False
                        for key in removable_keys:
                            if key in body and key in error_text:
                                logger.debug("Removing unsupported param '%s' and retrying", key)
                                del body[key]
                                removable_keys.remove(key)
                                removed = True
                                break
                        if removed:
                            continue
                        raise CodexAPIError(
                            f"Codex API returned 400: {resp.text[:500]}",
                            status_code=400,
                        )
                    if resp.status_code >= 400:
                        resp.read()
                        raise CodexAPIError(
                            f"Codex API returned {resp.status_code}: {resp.text[:500]}",
                            status_code=resp.status_code,
                        )
                    yield from _parse_sse_lines(resp.iter_lines())
                    return
    except httpx.HTTPError as e:
        # Translate httpx transport errors (connection reset, peer-closed,
        # incomplete chunked read, read timeout, ...) into a retryable
        # CodexTransportError so the existing _generate retry loop picks
        # them up. Without this they used to crash workers / the planner.
        raise CodexTransportError(
            f"Codex transport error ({type(e).__name__}): {e}"
        ) from e


async def astream_codex(
    tokens: CodexTokens,
    *,
    model: str,
    input_items: list[dict],
    instructions: str = "",
    tools: list[dict] | None = None,
    tool_choice: str | None = None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
    reasoning_effort: str | None = None,
    reasoning_summary: str | None = None,
    timeout: float = 120.0,
) -> Any:
    """Async stream SSE events from the Codex Responses API.

    Reasoning controls — see ``stream_codex`` docstring for valid values.
    """
    body: dict[str, Any] = {
        "model": model,
        "input": input_items,
        "store": False,
        "stream": True,
        "include": ["reasoning.encrypted_content"],
    }
    reasoning_block = _build_reasoning_block(reasoning_effort, reasoning_summary)
    if reasoning_block:
        body["reasoning"] = reasoning_block
    if instructions:
        body["instructions"] = instructions
    if tools:
        body["tools"] = tools
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    if temperature is not None:
        body["temperature"] = temperature
    if max_output_tokens is not None:
        body["max_output_tokens"] = max_output_tokens

    headers = {
        "Authorization": f"Bearer {tokens.access_token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if tokens.account_id:
        headers["ChatGPT-Account-Id"] = tokens.account_id

    removable_keys = [
        "temperature", "max_output_tokens", "tool_choice", "reasoning",
    ]

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            while True:
                async with client.stream("POST", CODEX_API_ENDPOINT, json=body, headers=headers) as resp:
                    if resp.status_code == 400:
                        await resp.aread()
                        error_text = resp.text.lower()
                        removed = False
                        for key in removable_keys:
                            if key in body and key in error_text:
                                logger.debug("Removing unsupported param '%s' and retrying", key)
                                del body[key]
                                removable_keys.remove(key)
                                removed = True
                                break
                        if removed:
                            continue
                        raise CodexAPIError(
                            f"Codex API returned 400: {resp.text[:500]}",
                            status_code=400,
                        )
                    if resp.status_code >= 400:
                        await resp.aread()
                        raise CodexAPIError(
                            f"Codex API returned {resp.status_code}: {resp.text[:500]}",
                            status_code=resp.status_code,
                        )
                    # Parse SSE from async line iterator
                    data_lines: list[str] = []
                    async for raw in resp.aiter_lines():
                        line = raw.rstrip("\n")
                        if not line:
                            if data_lines:
                                payload = "\n".join(data_lines)
                                data_lines = []
                                if payload.strip() == "[DONE]":
                                    continue
                                try:
                                    yield json.loads(payload)
                                except json.JSONDecodeError:
                                    continue
                            continue
                        if line.startswith("data:"):
                            data_lines.append(line[5:].lstrip())
                    return
    except httpx.HTTPError as e:
        # See ``stream_codex`` for the rationale — translate httpx
        # transport errors into retryable CodexTransportError. Catching
        # here (inside the async generator, before the ``async with``
        # contexts unwind) also fixes the "error during closing of
        # asynchronous generator" warnings that appeared at process
        # shutdown when an httpx error left the stream half-open.
        raise CodexTransportError(
            f"Codex transport error ({type(e).__name__}): {e}"
        ) from e


class CodexAPIError(Exception):
    """Base for all Codex API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


# ── Stream-level failure taxonomy ──────────────────────────────────────────
#
# The Codex Responses API can terminate a stream with three event types:
#
#   response.completed / response.done   — happy path, normal output.
#   response.failed                      — request errored mid-stream.
#                                          Carries an ``error`` dict with
#                                          a ``code`` and ``message``.
#   response.incomplete                  — partial output cut off (e.g.
#                                          ``max_output_tokens`` exceeded).
#
# Before this taxonomy existed, the parser silently returned an empty
# CodexResponse on failed/incomplete events because ``_is_terminal`` only
# matched the happy path. That looked like an empty AIMessage to the
# LangGraph agent loop, which interpreted "no tool call, no content" as
# "the agent decided to stop" — every worker died after one rate-limit
# event with zero findings. See logs/run-XBEN-006-24-20260503T211810-*
# for the failure mode this taxonomy + retry logic was added to fix.
#
# The error-code → exception mapping mirrors the upstream Codex CLI in
# codex-rs/codex-api/src/sse/responses.rs (process_responses_event /
# is_*_error / try_parse_retry_after). When OpenAI adds new error codes,
# update both this taxonomy and ``_classify_response_failed`` below.

class CodexStreamError(CodexAPIError):
    """Raised by the SSE parser on a terminal failure event.

    Subclasses set ``code`` (the upstream OpenAI error code) and
    ``retryable`` (whether reissuing the request can plausibly succeed).
    A retry hint extracted from the error message — common on
    ``rate_limit_exceeded`` ("try again in 1.898s") — is exposed via
    ``retry_after`` (seconds, ``None`` when absent).
    """

    code: str = "stream_error"
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        retry_after: float | None = None,
    ):
        super().__init__(message)
        if code:
            self.code = code
        self.retry_after = retry_after


class CodexRateLimitError(CodexStreamError):
    """TPM/RPM rate limit. Retryable; honors ``retry_after`` if present."""
    code = "rate_limit_exceeded"
    retryable = True


class CodexServerOverloadedError(CodexStreamError):
    """Upstream is overloaded ("server_is_overloaded" / "slow_down")."""
    code = "server_is_overloaded"
    retryable = True


class CodexContextWindowError(CodexStreamError):
    """Input exceeded the model's context window. NOT retryable —
    the same input won't fit on retry; the caller must trim history."""
    code = "context_length_exceeded"


class CodexQuotaExceededError(CodexStreamError):
    """Account quota exceeded ("insufficient_quota"). NOT retryable
    within this run."""
    code = "insufficient_quota"


class CodexCyberPolicyError(CodexStreamError):
    """Cyber-policy refusal. NOT retryable — the request itself is
    blocked. Caller may want to rephrase / re-emphasize authorization."""
    code = "cyber_policy"


class CodexInvalidPromptError(CodexStreamError):
    """``invalid_prompt`` — the request body is malformed or the prompt
    triggers an upstream validation rule. NOT retryable as-is."""
    code = "invalid_prompt"


class CodexUsageNotIncludedError(CodexStreamError):
    """``usage_not_included`` — the ChatGPT plan doesn't include this
    model. NOT retryable; user must change plan or model."""
    code = "usage_not_included"


class CodexIncompleteError(CodexStreamError):
    """Raised on ``response.incomplete`` — partial output cut off,
    typically by ``max_output_tokens`` or a content-filter trigger."""
    code = "incomplete"


class CodexTransportError(CodexStreamError):
    """Raised when the underlying HTTP transport fails — connection
    reset, peer-closed-connection, read timeout, partial chunked read,
    DNS error, etc.

    These are usually transient and worth retrying. We translate
    httpx exceptions into this type so the same retry loop that
    handles rate-limits / server-overloaded can handle network blips
    too, instead of letting them bubble all the way up to the planner
    and force a premature ``report``.
    """
    code = "transport_error"
    retryable = True


# Matches the "try again in <N> seconds." / "in <N>ms." hint that OpenAI
# embeds in rate-limit error messages. Mirrors codex-rs's
# ``rate_limit_regex`` (codex-rs/codex-api/src/sse/responses.rs:582).
_RETRY_AFTER_RE = re.compile(
    r"(?i)try again in\s*(\d+(?:\.\d+)?)\s*(s|ms|seconds?)"
)


def _parse_retry_after(error: dict) -> float | None:
    """Return retry-after seconds parsed from a Codex error dict.

    Only fires when ``error.code == "rate_limit_exceeded"`` — the only
    code where OpenAI consistently emits a retry hint. Returns ``None``
    if no parseable hint is present.
    """
    if error.get("code") != "rate_limit_exceeded":
        return None
    msg = error.get("message") or ""
    m = _RETRY_AFTER_RE.search(msg)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2).lower()
    if unit.startswith("ms"):
        return value / 1000.0
    return value


# ── Retry policy for retryable stream failures ───────────────────────────
# Applied in ``ChatCodex._generate`` / ``_agenerate``. Triggered on
# CodexRateLimitError, CodexServerOverloadedError, and any generic
# CodexStreamError marked ``.retryable``. Non-retryable errors
# (context-window, quota, cyber-policy, invalid-prompt) bubble up
# immediately — re-issuing the request can't fix them.
#
# MAX_API_ATTEMPTS = total attempts including the first call.
# BASE_RETRY_DELAY_S × 2^(attempt-1) is the backoff schedule when the API
# does NOT include a ``try again in <N>s`` hint; honoring the hint takes
# priority. MAX_RETRY_DELAY_S caps each sleep so we never park a worker
# for minutes on a slow_down event.
#
# Lives at module scope (not on ChatCodex) because ChatCodex inherits
# from a Pydantic BaseModel and underscored class attributes get
# rewritten into ``ModelPrivateAttr`` instances.
MAX_API_ATTEMPTS = 4
BASE_RETRY_DELAY_S = 2.0
MAX_RETRY_DELAY_S = 30.0


def _retry_delay(err: CodexStreamError, attempt: int) -> float:
    """Pick the sleep duration before the next attempt.

    If the error includes a server-side ``retry_after`` hint, honor it
    (capped by ``MAX_RETRY_DELAY_S``). Otherwise fall back to exponential
    backoff anchored at ``BASE_RETRY_DELAY_S``.
    """
    if err.retry_after is not None:
        return min(err.retry_after, MAX_RETRY_DELAY_S)
    return min(BASE_RETRY_DELAY_S * (2 ** attempt), MAX_RETRY_DELAY_S)


def _classify_response_failed(error: dict | None) -> CodexStreamError:
    """Map a ``response.failed`` event's ``error`` dict to a typed exception.

    Mirrors the upstream classifier in
    ``codex-rs/codex-api/src/sse/responses.rs::process_responses_event``.
    Unknown codes fall back to a generic retryable ``CodexStreamError`` —
    matches upstream's ``ApiError::Retryable`` default.
    """
    if not isinstance(error, dict):
        return CodexStreamError("response.failed event with no error body")

    code = error.get("code") or ""
    msg = error.get("message") or "Codex API failure"

    if code == "context_length_exceeded":
        return CodexContextWindowError(msg)
    if code == "insufficient_quota":
        return CodexQuotaExceededError(msg)
    if code == "usage_not_included":
        return CodexUsageNotIncludedError(msg)
    if code == "cyber_policy":
        return CodexCyberPolicyError(msg)
    if code == "invalid_prompt":
        return CodexInvalidPromptError(msg)
    if code in ("server_is_overloaded", "slow_down"):
        return CodexServerOverloadedError(msg)
    if code == "rate_limit_exceeded":
        return CodexRateLimitError(msg, retry_after=_parse_retry_after(error))

    err = CodexStreamError(
        msg,
        code=code or "stream_error",
        retry_after=_parse_retry_after(error),
    )
    err.retryable = True
    return err


# --- Response parsing (accumulates from SSE stream) ---

@dataclass
class CodexResponse:
    """Parsed response accumulated from SSE stream events."""
    content: str
    tool_calls: list[dict[str, Any]]
    response_metadata: dict[str, Any]
    usage: dict[str, int] | None


def _is_terminal(event: dict) -> bool:
    return event.get("type") in {"response.done", "response.completed"}


def _extract_text_delta(event: dict) -> str | None:
    etype = str(event.get("type", ""))
    if etype.endswith("output_text.delta"):
        delta = event.get("delta")
        if isinstance(delta, str):
            return delta
    return None


# SSE event types that carry the model's HUMAN-READABLE chain-of-thought.
# Source of truth: the upstream Codex CLI parser at
# codex-rs/codex-api/src/sse/responses.rs (lines 325-423). Three event
# types are relevant:
#
#   response.reasoning_summary_text.delta   — the user-visible summary
#       text we want. Streamed as deltas; .delta has the chunk and
#       .summary_index correlates chunks to summary blocks.
#   response.reasoning_summary_part.added   — boundary marker between
#       summary blocks. We insert a "\n\n" separator so multiple
#       summary blocks in one response stay readable.
#   response.reasoning_text.delta           — the OPAQUE internal
#       reasoning stream. Useful only for stateful chaining via the
#       encrypted_content blob; not human-readable. We DROP this — the
#       summary stream above gives us debug visibility without spending
#       tokens parsing the raw reasoning.
_REASONING_SUMMARY_DELTA = "response.reasoning_summary_text.delta"
_REASONING_SUMMARY_PART_ADDED = "response.reasoning_summary_part.added"


def _extract_reasoning_delta(event: dict) -> str | None:
    """Return the reasoning-summary delta text, or a separator on a part
    boundary, or None if this event doesn't carry reasoning."""
    etype = str(event.get("type", ""))
    if etype == _REASONING_SUMMARY_DELTA:
        delta = event.get("delta")
        if isinstance(delta, str):
            return delta
    elif etype == _REASONING_SUMMARY_PART_ADDED:
        # New summary block starting — return a separator so concatenated
        # output stays readable across multiple blocks.
        return "\n\n"
    return None


def parse_stream_to_response(
    events: Iterator[dict],
    *,
    on_reasoning_delta: "Callable[[str], None] | None" = None,
) -> CodexResponse:
    """Consume an SSE event stream and build a CodexResponse.

    Raises a ``CodexStreamError`` (or one of its subclasses) when the
    stream terminates with ``response.failed`` or ``response.incomplete``.
    The retry policy lives in ``ChatCodex._generate`` — the parser's job
    is just to surface the error loudly instead of silently returning an
    empty response, which is what used to break worker agent loops on
    every TPM rate-limit blip.

    ``on_reasoning_delta``: optional callback fired with each
    chain-of-thought summary chunk as it arrives. Used by the live
    renderer to stream "the model is thinking…" text to stderr in
    verbose mode. Default is None — non-streaming callers (tests, the
    salvage path) get the same behaviour as before. Exceptions raised
    by the callback are swallowed so a misbehaving renderer never
    breaks the LLM call.
    """
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    usage: dict[str, int] | None = None

    for event in events:
        etype = str(event.get("type", ""))

        # Stream-level failure events terminate parsing immediately.
        # See the CodexStreamError taxonomy comment for why we can't
        # just ignore them.
        if etype == "response.failed":
            resp = event.get("response") or {}
            raise _classify_response_failed(resp.get("error"))
        if etype == "response.incomplete":
            resp = event.get("response") or {}
            details = resp.get("incomplete_details") or {}
            reason = details.get("reason") or "unknown"
            raise CodexIncompleteError(
                f"Codex returned response.incomplete (reason={reason})"
            )

        # Accumulate visible text deltas
        delta = _extract_text_delta(event)
        if delta:
            text_parts.append(delta)

        # Accumulate reasoning-summary deltas (the model's chain-of-thought
        # made visible — gpt-5.x's reasoning is the load-bearing step;
        # logging it gives us debug visibility into WHY each tool call
        # was chosen, not just what was emitted).
        rdelta = _extract_reasoning_delta(event)
        if rdelta is not None:
            reasoning_parts.append(rdelta)
            if on_reasoning_delta is not None:
                # Forward each chunk to the live renderer as it arrives.
                # Errors in the renderer must NOT break the LLM call —
                # observability is best-effort.
                try:
                    on_reasoning_delta(rdelta)
                except Exception:  # noqa: BLE001
                    pass

        # Capture completed function calls
        if etype == "response.output_item.done":
            item = event.get("item", {})
            if isinstance(item, dict) and item.get("type") == "function_call":
                tool_calls.append({
                    "name": item.get("name", ""),
                    "args": item.get("arguments", "{}"),
                    "id": item.get("call_id") or item.get("id"),
                })

        # Capture terminal event metadata
        if _is_terminal(event):
            resp = event.get("response", {})
            if isinstance(resp, dict):
                for key in ("id", "model", "status", "created_at"):
                    if key in resp:
                        metadata[key] = resp[key]
                # Finish reason
                if resp.get("status") in ("completed", "done"):
                    metadata["finish_reason"] = "tool_calls" if tool_calls else "stop"
                # Usage — including the separately-billed reasoning tokens
                # and the OpenAI Responses API's prompt-cache hit count.
                #
                # Paths:
                #   usage.input_tokens_details.cached_tokens
                #     — bytes that hit OpenAI's automatic prompt cache
                #       (≥ 1024-token stable prefixes; billed at a steep
                #       discount and served with reduced prefill latency).
                #       Reading this is the ONLY way to confirm whether
                #       caching is actually happening; the top-level
                #       ``input_tokens`` always reports the full prompt
                #       size (cached + uncached).
                #   usage.output_tokens_details.reasoning_tokens
                #     — the gpt-5.x chain-of-thought tokens (billed
                #       separately from visible output).
                # See codex-rs/codex-api/src/sse/responses.rs:174-177.
                u = resp.get("usage")
                if isinstance(u, dict):
                    # DIAGNOSTIC (2026-05-26): dump the raw usage dict
                    # once per process so we can see whether the Codex
                    # SSE backend exposes ``input_tokens_details`` (the
                    # OpenAI Responses-API field that reports prompt-
                    # cache hits) or strips it on this auth route. Remove
                    # once cache reporting is confirmed working.
                    global _USAGE_SHAPE_LOGGED
                    if not _USAGE_SHAPE_LOGGED:
                        _USAGE_SHAPE_LOGGED = True
                        try:
                            import json as _json
                            logger.warning(
                                "DIAGNOSTIC raw codex usage dict: %s",
                                _json.dumps(u, default=str),
                            )
                        except Exception:  # noqa: BLE001
                            logger.warning("DIAGNOSTIC raw codex usage dict (repr): %r", u)
                    out_details = u.get("output_tokens_details") or {}
                    in_details = u.get("input_tokens_details") or {}
                    usage = {
                        "input_tokens":     u.get("input_tokens", 0),
                        "output_tokens":    u.get("output_tokens", 0),
                        "reasoning_tokens": out_details.get("reasoning_tokens", 0),
                        "cached_tokens":    in_details.get("cached_tokens", 0),
                        "total_tokens":     u.get("total_tokens", 0),
                    }

    reasoning_summary = "".join(reasoning_parts).strip() or None
    if reasoning_summary:
        metadata["reasoning_summary"] = reasoning_summary

    return CodexResponse(
        content="".join(text_parts),
        tool_calls=tool_calls,
        response_metadata=metadata,
        usage=usage,
    )


# Module-level toggle for the one-shot diagnostic dump above.
_USAGE_SHAPE_LOGGED: bool = False


async def aparse_stream_to_response(
    events,
    *,
    on_reasoning_delta: "Callable[[str], None] | None" = None,
) -> CodexResponse:
    """Async version: consume an async SSE event stream.

    Mirrors :func:`parse_stream_to_response` — captures reasoning
    summary text and reasoning_tokens usage in addition to the visible
    response. See that function's docstring for details on the
    ``on_reasoning_delta`` hook.
    """
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    usage: dict[str, int] | None = None

    async for event in events:
        etype = str(event.get("type", ""))

        # Stream-level failure events terminate parsing immediately —
        # see ``parse_stream_to_response`` for the rationale.
        if etype == "response.failed":
            resp = event.get("response") or {}
            raise _classify_response_failed(resp.get("error"))
        if etype == "response.incomplete":
            resp = event.get("response") or {}
            details = resp.get("incomplete_details") or {}
            reason = details.get("reason") or "unknown"
            raise CodexIncompleteError(
                f"Codex returned response.incomplete (reason={reason})"
            )

        delta = _extract_text_delta(event)
        if delta:
            text_parts.append(delta)

        rdelta = _extract_reasoning_delta(event)
        if rdelta is not None:
            reasoning_parts.append(rdelta)
            if on_reasoning_delta is not None:
                # Same observability-best-effort pattern as the sync
                # parser — see parse_stream_to_response above.
                try:
                    on_reasoning_delta(rdelta)
                except Exception:  # noqa: BLE001
                    pass

        if etype == "response.output_item.done":
            item = event.get("item", {})
            if isinstance(item, dict) and item.get("type") == "function_call":
                tool_calls.append({
                    "name": item.get("name", ""),
                    "args": item.get("arguments", "{}"),
                    "id": item.get("call_id") or item.get("id"),
                })

        if _is_terminal(event):
            resp = event.get("response", {})
            if isinstance(resp, dict):
                for key in ("id", "model", "status", "created_at"):
                    if key in resp:
                        metadata[key] = resp[key]
                if resp.get("status") in ("completed", "done"):
                    metadata["finish_reason"] = "tool_calls" if tool_calls else "stop"
                u = resp.get("usage")
                if isinstance(u, dict):
                    out_details = u.get("output_tokens_details") or {}
                    in_details = u.get("input_tokens_details") or {}
                    usage = {
                        "input_tokens":     u.get("input_tokens", 0),
                        "output_tokens":    u.get("output_tokens", 0),
                        "reasoning_tokens": out_details.get("reasoning_tokens", 0),
                        "cached_tokens":    in_details.get("cached_tokens", 0),
                        "total_tokens":     u.get("total_tokens", 0),
                    }

    reasoning_summary = "".join(reasoning_parts).strip() or None
    if reasoning_summary:
        metadata["reasoning_summary"] = reasoning_summary

    return CodexResponse(
        content="".join(text_parts),
        tool_calls=tool_calls,
        response_metadata=metadata,
        usage=usage,
    )


# --- LangChain BaseChatModel implementation ---

from collections.abc import AsyncIterator
from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.messages.tool import ToolCall
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult


def _message_to_input_item(msg: BaseMessage) -> dict:
    """Convert a LangChain message to a Responses API input item."""
    if isinstance(msg, SystemMessage):
        return {
            "type": "message",
            "role": "developer",
            "content": [{"type": "input_text", "text": str(msg.content)}],
        }
    if isinstance(msg, HumanMessage):
        return {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": str(msg.content)}],
        }
    if isinstance(msg, AIMessage):
        items = []
        # Text content
        text = msg.content if isinstance(msg.content, str) else str(msg.content)
        if text:
            items.append({
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            })
        # Tool calls
        for tc in msg.tool_calls:
            items.append({
                "type": "function_call",
                "call_id": tc["id"],
                "name": tc["name"],
                "arguments": json.dumps(tc["args"]) if isinstance(tc["args"], dict) else tc["args"],
            })
        return items if len(items) != 1 else items[0]
    if isinstance(msg, ToolMessage):
        return {
            "type": "function_call_output",
            "call_id": msg.tool_call_id,
            "output": str(msg.content),
        }
    # Fallback
    return {
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": str(msg.content)}],
    }


def _messages_to_input_items(messages: list[BaseMessage]) -> list[dict]:
    """Convert LangChain messages to Responses API input items."""
    items = []
    for msg in messages:
        result = _message_to_input_item(msg)
        if isinstance(result, list):
            items.extend(result)
        else:
            items.append(result)
    return items


def _convert_tools_to_responses_format(tools: list[dict]) -> list[dict]:
    """Convert LangChain tool dicts to Responses API function tool format."""
    converted = []
    for t in tools:
        if t.get("type") == "function":
            # Already in OpenAI format
            fn = t["function"]
            converted.append({
                "type": "function",
                "name": fn["name"],
                "description": fn.get("description", ""),
                "parameters": fn.get("parameters", {}),
            })
        else:
            converted.append(t)
    return converted


def _build_reasoning_sink(
    agent_id: str,
    lc_run_id: Any,
) -> Callable[[str], None] | None:
    """Build a per-call sink that forwards reasoning deltas to the live
    renderer for ``agent_id`` / ``lc_run_id``.

    ``agent_id`` and ``lc_run_id`` are caller-supplied and read from the
    ``run_manager`` parameter of ``_generate`` / ``_agenerate`` — NOT
    from a ContextVar.

    Historical note: a prior version of this function read the calling
    identity from a ``CURRENT_LLM_CALL`` ContextVar populated by
    ``TokenLoggingCallback.on_chat_model_start``. The ContextVar
    appeared empty at every read site because LangChain dispatches
    async callbacks in a child task — its ``set`` mutated the child's
    context copy, never the parent's. The reasoning sink in the parent
    (``_agenerate``) saw ``None`` on every call and short-circuited;
    no reasoning summary ever reached the terminal. Verified by
    instrumenting both call sites with ``id(asyncio.current_task())``
    — the IDs always differed. Reading identity directly from
    ``run_manager`` avoids the cross-task isolation entirely. See
    ``tests/FAILURES.md`` 2026-05-13 for the full diagnosis.

    Returns ``None`` when ``agent_id`` is empty (caller didn't supply
    identity, e.g. salvage / ``ask_focused`` paths) so the parser
    short-circuits its streaming hook entirely. ``lc_run_id`` may be
    ``None`` — the live renderer tolerates it.
    """
    if not agent_id:
        return None

    def _sink(text: str) -> None:
        try:
            from src.observability import LIVE  # lazy — never break the LLM call
            LIVE.thinking_delta(agent=agent_id, run_id=lc_run_id, text=text)
        except Exception:  # noqa: BLE001
            pass

    return _sink


def _identity_from_run_manager(run_manager: Any) -> tuple[str, Any]:
    """Pull ``(agent_id, lc_run_id)`` out of a LangChain run_manager.

    Both fields are read directly from the run_manager (which lives in
    the same async task as ``_generate`` / ``_agenerate``) rather than
    from a ContextVar — see :func:`_build_reasoning_sink` for the
    history of why the ContextVar route was broken.

    Returns ``("", None)`` when the run_manager is absent or lacks
    metadata (sync-test paths, direct ``ChatCodex._generate`` calls
    that bypass LangChain's callback pipeline).
    """
    if run_manager is None:
        return "", None
    meta = getattr(run_manager, "metadata", None) or {}
    agent_id = str(
        meta.get("agent_id") or meta.get("ls_agent") or ""
    )
    lc_run_id = getattr(run_manager, "run_id", None)
    return agent_id, lc_run_id


def _build_additional_kwargs(resp: CodexResponse) -> dict[str, Any]:
    """Promote reasoning summary + reasoning-token count onto the AIMessage.

    These flow into ``additional_kwargs`` so they're automatically
    serialized into the per-node JSONL audit log (BaseNode.__call__
    dumps every message including additional_kwargs). That gives us
    end-to-end visibility into the model's chain-of-thought without
    extra state plumbing or a dedicated reasoning_log field.

    Returns an empty dict when neither piece of data is present, so the
    AIMessage stays clean for non-reasoning models.
    """
    extras: dict[str, Any] = {}
    summary = (resp.response_metadata or {}).get("reasoning_summary")
    if summary:
        extras["reasoning_summary"] = summary
    if resp.usage and resp.usage.get("reasoning_tokens"):
        extras["reasoning_tokens"] = resp.usage["reasoning_tokens"]
    return extras


class ChatCodex(BaseChatModel):
    """LangChain chat model that uses your ChatGPT subscription via the Codex backend.

    No API keys needed — uses OAuth tokens from the Codex CLI (~/.codex/auth.json).
    """

    model: str = "gpt-5.5"
    temperature: float | None = None
    max_tokens: int | None = None
    codex_home: str | None = None
    # ── Reasoning controls (see LLMConfig for valid values) ──
    # effort:  "none" | "minimal" | "low" | "medium" | "high" | "xhigh"
    # summary: "auto" | "concise" | "detailed" | "none"
    # Both default to None here — when None the request omits the
    # corresponding wire field, letting the upstream API fall back to the
    # model's own default. The user-facing knobs flow through LLMConfig
    # → ChatCodex(reasoning_effort=..., reasoning_summary=...) populated
    # by get_llm() in src/llm/provider.py.
    reasoning_effort: str | None = None
    reasoning_summary: str | None = None

    _tokens: CodexTokens | None = None

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "codex"

    def bind_tools(self, tools: list, *, tool_choice: str | None = None, **kwargs):
        """Bind tools to the model for function calling."""
        from langchain_core.tools import BaseTool
        from langchain_core.utils.function_calling import convert_to_openai_function

        formatted = []
        for t in tools:
            if isinstance(t, BaseTool):
                formatted.append({"type": "function", "function": convert_to_openai_function(t)})
            elif isinstance(t, dict):
                formatted.append(t)
            else:
                formatted.append({"type": "function", "function": convert_to_openai_function(t)})

        bind_kwargs: dict[str, Any] = {"tools": formatted}
        if tool_choice is not None:
            bind_kwargs["tool_choice"] = tool_choice
        return self.bind(**bind_kwargs)

    @property
    def _identifying_params(self) -> dict:
        return {"model": self.model}

    def _ensure_tokens(self) -> CodexTokens:
        """Load tokens, refreshing if expired."""
        if self._tokens is None:
            home = Path(self.codex_home) if self.codex_home else None
            self._tokens = load_tokens(home)

        # Refresh if expired (with 60s buffer)
        if self._tokens.expires_at and self._tokens.expires_at < time.time() + 60:
            try:
                self._tokens = refresh_access_token(self._tokens)
            except Exception as e:
                logger.warning("Token refresh failed: %s", e)

        return self._tokens

    def _build_request_kwargs(
        self,
        messages: list[BaseMessage],
        tools: list[dict] | None = None,
        tool_choice: str | None = None,
    ) -> dict:
        """Build kwargs for stream_codex / astream_codex."""
        # Extract system messages as instructions
        system_parts = []
        non_system = []
        for msg in messages:
            if isinstance(msg, SystemMessage):
                system_parts.append(str(msg.content))
            else:
                non_system.append(msg)

        input_items = _messages_to_input_items(non_system)

        # The Codex Responses API requires at least one non-system input item.
        # When an agent is first invoked with just a system prompt and empty
        # messages, inject a minimal user message so the LLM has something
        # to respond to.
        if not input_items:
            input_items = [{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Begin."}],
            }]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "input_items": input_items,
            "instructions": "\n\n".join(system_parts) if system_parts else "You are a helpful assistant.",
        }
        if tools:
            kwargs["tools"] = _convert_tools_to_responses_format(tools)
        if tool_choice is not None:
            kwargs["tool_choice"] = tool_choice
        # Reasoning controls — flow through to stream_codex / astream_codex
        # which build the wire-level ``reasoning`` block. None values are
        # dropped at the wire-build stage so non-reasoning models still work.
        if self.reasoning_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if self.reasoning_summary:
            kwargs["reasoning_summary"] = self.reasoning_summary
        # Note: temperature and max_tokens are not always supported by the
        # Codex backend (depends on the model). We pass them through and
        # let the stream function handle 400 errors by retrying without them.
        return kwargs

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        tokens = self._ensure_tokens()
        tools = kwargs.get("tools")
        tool_choice = kwargs.get("tool_choice")

        req = self._build_request_kwargs(messages, tools, tool_choice)

        # Build the reasoning-delta sink. Identity comes directly from
        # the run_manager (same async task as this method) — NOT from a
        # ContextVar, because async-callback dispatch puts the
        # ContextVar set in a child task whose mutation never reaches
        # the parent. See ``_build_reasoning_sink`` docstring.
        agent_id, lc_run_id = _identity_from_run_manager(run_manager)
        reasoning_sink = _build_reasoning_sink(agent_id, lc_run_id)

        for attempt in range(MAX_API_ATTEMPTS):
            try:
                # ``closing`` guarantees the SSE generator's ``with
                # httpx.Client() as client`` / ``client.stream(...) as
                # resp`` blocks unwind on every exit path — normal
                # return, break, and (the case that matters here)
                # exceptions raised by the parser when it sees a
                # ``response.failed`` event mid-stream. Without it,
                # CPython would close the generator via refcount on
                # the next line, but PyPy / cycle-creating callbacks
                # could defer that to GC. See ``_agenerate`` for the
                # async-path counterpart where this is not optional.
                with closing(stream_codex(tokens, **req)) as events:
                    resp = parse_stream_to_response(
                        events, on_reasoning_delta=reasoning_sink,
                    )
                break
            except CodexStreamError as e:
                # Attach the request payload to policy-refusal errors
                # so ``src/refusals/retry.py`` can dump it to the live
                # renderer for debugging. Defensive try/except: some
                # exception subclasses use ``__slots__`` and setattr
                # fails silently — that's acceptable since the dump
                # path is opt-in / best-effort.
                if isinstance(
                    e, (CodexCyberPolicyError, CodexInvalidPromptError),
                ):
                    try:
                        e._swarm_request = req  # type: ignore[attr-defined]
                    except (AttributeError, TypeError):
                        pass
                if not e.retryable or attempt == MAX_API_ATTEMPTS - 1:
                    raise
                delay = _retry_delay(e, attempt)
                logger.warning(
                    "Codex %s on attempt %d/%d — sleeping %.2fs before retry "
                    "(code=%s, msg=%r)",
                    type(e).__name__, attempt + 1, MAX_API_ATTEMPTS,
                    delay, e.code, str(e)[:200],
                )
                time.sleep(delay)

        # Build tool calls
        lc_tool_calls = []
        for tc in resp.tool_calls:
            args = tc["args"]
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    pass
            lc_tool_calls.append(ToolCall(name=tc["name"], args=args, id=tc["id"]))

        message = AIMessage(
            content=resp.content,
            tool_calls=lc_tool_calls,
            response_metadata=resp.response_metadata,
            usage_metadata=resp.usage,
            additional_kwargs=_build_additional_kwargs(resp),
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        tokens = self._ensure_tokens()
        tools = kwargs.get("tools")
        tool_choice = kwargs.get("tool_choice")

        req = self._build_request_kwargs(messages, tools, tool_choice)

        # Live-streaming sink for reasoning deltas — see ``_generate`` and
        # ``_build_reasoning_sink`` for why we read identity from
        # ``run_manager`` here instead of from a ContextVar.
        agent_id, lc_run_id = _identity_from_run_manager(run_manager)
        reasoning_sink = _build_reasoning_sink(agent_id, lc_run_id)

        for attempt in range(MAX_API_ATTEMPTS):
            try:
                # ``aclosing`` is the real fix here. ``astream_codex``
                # is an async generator holding open ``async with
                # httpx.AsyncClient(...)`` and ``async with
                # client.stream(...) as resp`` contexts at its
                # suspended ``yield``. When ``aparse_stream_to_response``
                # raises mid-stream (e.g. on a ``response.failed`` event
                # carrying a ``cyber_policy`` refusal), Python's async
                # iteration protocol does NOT auto-close the producer —
                # cleanup is purely GC-driven. Without ``aclosing`` the
                # generator stayed alive until shutdown, and the
                # asyncgen finalizer hook ran ``aclose()`` against an
                # already-tearing-down event loop, producing the
                # ``error: an error occurred during closing of
                # asynchronous generator <astream_codex / AsyncClient.
                # stream>`` warning wall at end-of-run. ``aclosing``
                # awaits ``events.aclose()`` deterministically on every
                # exit path (success, exception, break) so the httpx
                # contexts unwind on the same task that opened them,
                # while the loop is still healthy.
                async with aclosing(astream_codex(tokens, **req)) as events:
                    resp = await aparse_stream_to_response(
                        events, on_reasoning_delta=reasoning_sink,
                    )
                break
            except CodexStreamError as e:
                # Same pattern as the sync path — stash the request
                # payload on policy-refusal exceptions so the live
                # renderer can dump it. See ``_generate`` comment for
                # rationale.
                if isinstance(
                    e, (CodexCyberPolicyError, CodexInvalidPromptError),
                ):
                    try:
                        e._swarm_request = req  # type: ignore[attr-defined]
                    except (AttributeError, TypeError):
                        pass
                if not e.retryable or attempt == MAX_API_ATTEMPTS - 1:
                    raise
                delay = _retry_delay(e, attempt)
                logger.warning(
                    "Codex %s on attempt %d/%d — sleeping %.2fs before retry "
                    "(code=%s, msg=%r)",
                    type(e).__name__, attempt + 1, MAX_API_ATTEMPTS,
                    delay, e.code, str(e)[:200],
                )
                await asyncio.sleep(delay)

        lc_tool_calls = []
        for tc in resp.tool_calls:
            args = tc["args"]
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    pass
            lc_tool_calls.append(ToolCall(name=tc["name"], args=args, id=tc["id"]))

        message = AIMessage(
            content=resp.content,
            tool_calls=lc_tool_calls,
            response_metadata=resp.response_metadata,
            usage_metadata=resp.usage,
            additional_kwargs=_build_additional_kwargs(resp),
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    # Note: we intentionally don't implement _stream / _astream.
    #
    # LangChain's default streaming fallback will call _generate / _agenerate
    # and wrap the single result as one chunk. That's correct for tool-calling
    # agents: when the LLM responds with only tool calls (no text), a naive
    # text-delta-only _astream would yield zero chunks and LangChain would
    # crash with "No generations found in stream."
    #
    # Real-time token streaming isn't useful for SwarmAttacker's agent loop
    # anyway — agents spend most of their time waiting on tool execution
    # (nmap, curl, sqlmap), not on LLM text generation.
