from __future__ import annotations

import json
import tempfile
from pathlib import Path

import tiktoken

from pry.output import DEFAULT_SPILL_TOKEN_LIMIT, write_output_result


TOKENIZER = "o200k_base"


def _token_count(text: str) -> int:
    return len(tiktoken.get_encoding(TOKENIZER).encode(text))


def test_default_spill_token_limit_is_10k():
    assert DEFAULT_SPILL_TOKEN_LIMIT == 10_000


def test_write_output_renders_small_payload_without_spill(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))

    result = write_output_result({"ok": True}, fmt="json", out_path=None, stem="small")

    payload = json.loads(result.rendered)
    assert payload["ok"] is True
    assert not result.spilled


def test_write_output_spills_large_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    payload = {"data": [f"item-{index:04d}" for index in range(1000)]}

    result = write_output_result(
        payload,
        fmt="json",
        out_path=None,
        stem="large",
        spill_token_limit=256,
    )

    assert result.spilled
    envelope = json.loads(result.rendered)
    artifact_root = tempfile.gettempdir()
    assert envelope["artifact_path"].startswith(artifact_root)
    artifact_text = Path(envelope["artifact_path"]).read_text()
    assert envelope["tokenizer"] == TOKENIZER
    assert envelope["tokens"] == _token_count(artifact_text)


def test_write_output_spills_text_payload_with_txt_suffix(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    payload = "\n".join(f"line {index} with distinctive content" for index in range(1000))

    result = write_output_result(
        payload,
        fmt="text",
        out_path=None,
        stem="large-text",
        spill_token_limit=256,
    )

    assert result.spilled
    envelope = json.loads(result.rendered)
    assert envelope["artifact_path"].endswith(".txt")


def test_write_output_uses_token_limit_not_byte_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    payload = "x" * 1000
    token_limit = _token_count(payload + "\n") + 1

    result = write_output_result(
        payload,
        fmt="text",
        out_path=None,
        stem="byte-heavy",
        spill_token_limit=token_limit,
    )

    assert result.rendered == payload + "\n"
    assert not result.spilled


def test_write_output_reports_exact_tokens_for_explicit_out_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))

    out_path = tmp_path / "artifacts" / "payload.json"
    result = write_output_result(
        {"message": "token-aware output"},
        fmt="json",
        out_path=out_path,
        stem="explicit-out",
    )

    envelope = json.loads(result.rendered)
    artifact_text = out_path.read_text()
    assert envelope["artifact_path"] == str(out_path)
    assert envelope["tokenizer"] == TOKENIZER
    assert envelope["tokens"] == _token_count(artifact_text)
