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

import base64
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import httpx

from src.graph import budgets

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
    timeout: float | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream SSE events from the Codex Responses API."""
    if timeout is None:
        timeout = budgets.llm_request_timeout_s
    body: dict[str, Any] = {
        "model": model,
        "input": input_items,
        "store": False,
        "stream": True,
        "include": ["reasoning.encrypted_content"],
    }
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
    removable_keys = ["temperature", "max_output_tokens", "tool_choice"]

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
    timeout: float | None = None,
) -> Any:
    """Async stream SSE events from the Codex Responses API."""
    if timeout is None:
        timeout = budgets.llm_request_timeout_s
    body: dict[str, Any] = {
        "model": model,
        "input": input_items,
        "store": False,
        "stream": True,
        "include": ["reasoning.encrypted_content"],
    }
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

    removable_keys = ["temperature", "max_output_tokens", "tool_choice"]

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


class CodexAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


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


def parse_stream_to_response(events: Iterator[dict]) -> CodexResponse:
    """Consume an SSE event stream and build a CodexResponse."""
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    usage: dict[str, int] | None = None

    for event in events:
        # Accumulate text deltas
        delta = _extract_text_delta(event)
        if delta:
            text_parts.append(delta)

        # Capture completed function calls
        etype = str(event.get("type", ""))
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
                # Usage
                u = resp.get("usage")
                if isinstance(u, dict):
                    usage = {
                        "input_tokens": u.get("input_tokens", 0),
                        "output_tokens": u.get("output_tokens", 0),
                        "total_tokens": u.get("total_tokens", 0),
                    }

    return CodexResponse(
        content="".join(text_parts),
        tool_calls=tool_calls,
        response_metadata=metadata,
        usage=usage,
    )


async def aparse_stream_to_response(events) -> CodexResponse:
    """Async version: consume an async SSE event stream."""
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    usage: dict[str, int] | None = None

    async for event in events:
        delta = _extract_text_delta(event)
        if delta:
            text_parts.append(delta)

        etype = str(event.get("type", ""))
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
                    usage = {
                        "input_tokens": u.get("input_tokens", 0),
                        "output_tokens": u.get("output_tokens", 0),
                        "total_tokens": u.get("total_tokens", 0),
                    }

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


class ChatCodex(BaseChatModel):
    """LangChain chat model that uses your ChatGPT subscription via the Codex backend.

    No API keys needed — uses OAuth tokens from the Codex CLI (~/.codex/auth.json).
    """

    model: str = "gpt-5.4-mini"
    temperature: float | None = None
    max_tokens: int | None = None
    codex_home: str | None = None

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
        events = stream_codex(tokens, **req)
        resp = parse_stream_to_response(events)

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
        events = astream_codex(tokens, **req)
        resp = await aparse_stream_to_response(events)

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
