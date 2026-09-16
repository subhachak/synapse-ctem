import os
import sys
import traceback
import threading
from contextlib import contextmanager

import truststore

# Use the OS certificate store (macOS Keychain / Windows cert store) instead of
# certifi's bundled CA list, so the anthropic SDK's TLS handshake succeeds behind
# a TLS-inspecting corporate proxy whose root cert isn't in certifi but is trusted
# system-wide (e.g. Netskope, Zscaler). Must run before the Anthropic client is built.
truststore.inject_into_ssl()

from anthropic import Anthropic

_api_key = os.environ.get("ANTHROPIC_API_KEY")
_live_opt_in = os.environ.get("CTEM_LIVE_LLM", "").lower() in ("1", "true", "yes")
_request_timeout = float(os.environ.get("CTEM_LLM_TIMEOUT_SECONDS", "10"))
# A live advisory must never hold the authoritative pipeline hostage. Disable
# SDK retries (which can otherwise add minutes under throttling/network faults)
# and fall back deterministically after a short, configurable timeout.
_client = (
    Anthropic(api_key=_api_key, timeout=_request_timeout, max_retries=0)
    if _api_key and _live_opt_in else None
)

IS_LIVE_MODE = bool(_client)
_mode_lock = threading.Lock()
_offline_depth = 0
_saved_client = None


@contextmanager
def offline_reasoning():
    """Force deterministic narratives for reset/bootstrap reliability."""
    global _client, _offline_depth, _saved_client
    with _mode_lock:
        if _offline_depth == 0:
            _saved_client = _client
            _client = None
        _offline_depth += 1
    try:
        yield
    finally:
        with _mode_lock:
            _offline_depth -= 1
            if _offline_depth == 0:
                _client = _saved_client
                _saved_client = None


def llm_available() -> bool:
    """True when a live model call will actually reach Anthropic (opt-in + not forced offline)."""
    with _mode_lock:
        return _client is not None and _offline_depth == 0


def llm_reason(system_prompt: str, user_prompt: str) -> str:
    """
    Thin wrapper so every Layer 3 agent can ask an LLM for its narrative
    reasoning (the "LLM narrative agents for context" /
    "Adversarial Reasoning ... simulates attacker decision-making" language)
    while still running fully offline for a demo with no API key configured.
    """
    with _mode_lock:
        forced_offline = _offline_depth > 0
    if _client is None or forced_offline:
        return _offline_fallback(user_prompt)
    try:
        resp = _client.messages.create(
            model="claude-sonnet-5",
            max_tokens=400,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        for block in resp.content:
            if block.type == "text":
                return block.text
        return _offline_fallback(user_prompt)
    except Exception:
        # Fail closed to deterministic output rather than breaking the pipeline —
        # but log the real cause to stderr (visible in .run/backend.log under
        # run.sh) instead of swallowing it silently, so a live-mode failure
        # that isn't "no key" (bad key, network, SDK/model mismatch, etc.) is
        # actually diagnosable instead of looking identical to offline mode.
        print("[llm.py] live Anthropic call failed, falling back to offline text:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return _offline_fallback(user_prompt)


def llm_generate(system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> tuple[str | None, str]:
    """
    Longer-form generation for the agentic code fixer — e.g. rewriting a whole
    source file, which the 400-token llm_reason budget would truncate. Returns
    (text, "anthropic") on a live call, or (None, "offline") when disabled/forced
    offline or on error, so callers can use a deterministic fallback.
    """
    with _mode_lock:
        forced_offline = _offline_depth > 0
    if _client is None or forced_offline:
        return None, "offline"
    # Code generation is far slower than a one-line narrative, so it gets its own
    # (longer) timeout rather than the 10s narrative budget.
    code_timeout = float(os.environ.get("CTEM_LLM_CODE_TIMEOUT_SECONDS", "60"))
    try:
        resp = _client.with_options(timeout=code_timeout).messages.create(
            model="claude-sonnet-5",
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        for block in resp.content:
            if block.type == "text":
                return block.text, "anthropic"
        return None, "offline"
    except Exception:
        print("[llm.py] live code-generation call failed, falling back:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None, "offline"


def _offline_fallback(user_prompt: str) -> str:
    snippet = user_prompt[:180]
    return (
        "[deterministic fallback — live narrative unavailable or disabled for this run] "
        f"Summary generated from structured inputs: {snippet}..."
    )
