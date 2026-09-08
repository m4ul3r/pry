from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier

import pytest
import pry.output
import tiktoken

from pry.output import DEFAULT_SPILL_TOKEN_LIMIT, write_output_result


TOKENIZER = "o200k_base"


def _token_count(text: str) -> int:
    return len(tiktoken.get_encoding(TOKENIZER).encode(text))


def test_default_spill_token_limit_is_10k():
    assert DEFAULT_SPILL_TOKEN_LIMIT == 10_000


def test_write_output_renders_small_payload_without_spill(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))

    result = write_output_result({"message": "ready"}, fmt="json", out_path=None, stem="small")

    payload = json.loads(result.rendered)
    assert payload == {"message": "ready"}
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
    assert "ok" not in envelope
    assert envelope["artifact_path"].startswith(str(tmp_path / "spills"))
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
    assert "ok" not in envelope
    artifact_text = out_path.read_text()
    assert envelope["artifact_path"] == str(out_path)
    assert envelope["tokenizer"] == TOKENIZER
    assert envelope["tokens"] == _token_count(artifact_text)


def test_concurrent_spills_have_unique_immutable_valid_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))

    class FrozenDatetime:
        @staticmethod
        def now(tz):
            return datetime(2026, 9, 8, 12, 34, 56, tzinfo=timezone.utc)

    monkeypatch.setattr(pry.output, "datetime", FrozenDatetime)
    barrier = Barrier(8)
    payloads = [{"index": index, "data": str(index) * 40000} for index in range(8)]
    # Initialize the encoding before the workers contend for artifact creation.
    _token_count("")

    def spill(payload):
        barrier.wait(timeout=10)
        return write_output_result(
            payload, fmt="json", out_path=None, stem="concurrent", spill_token_limit=0
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(spill, payloads))

    envelopes = [json.loads(result.rendered) for result in results]
    paths = [Path(envelope["artifact_path"]) for envelope in envelopes]
    assert len(set(paths)) == len(payloads)
    before = [path.read_bytes() for path in paths]
    write_output_result(
        {"later": True}, fmt="json", out_path=None, stem="concurrent", spill_token_limit=0
    )
    for payload, envelope, path, content in zip(payloads, envelopes, paths, before):
        assert path.read_bytes() == content
        assert json.loads(content) == payload
        assert envelope["bytes"] == len(content)
        assert envelope["sha256"] == hashlib.sha256(content).hexdigest()
        assert "ok" not in envelope


@pytest.mark.parametrize("failure", ["write", "close"])
def test_failed_spill_removes_partial_artifact(tmp_path, monkeypatch, failure):
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    create_file = pry.output.tempfile.NamedTemporaryFile
    paths = []

    class FailingFile:
        def __init__(self, **kwargs):
            self.file = create_file(**kwargs)
            self.name = self.file.name
            paths.append(Path(self.name))

        def __enter__(self):
            return self

        def write(self, data):
            self.file.write(data[:5])
            if failure == "write":
                raise OSError("disk full")

        def __exit__(self, *exc):
            self.file.close()
            if failure == "close":
                raise OSError("disk full")

    monkeypatch.setattr(pry.output.tempfile, "NamedTemporaryFile", FailingFile)
    with pytest.raises(OSError, match="disk full"):
        write_output_result(
            {"data": "not complete"}, fmt="json", out_path=None,
            stem="failed", spill_token_limit=0,
        )
    assert len(paths) == 1
    assert not paths[0].exists()


def test_explicit_out_overwrites_requested_path(tmp_path):
    out_path = tmp_path / "result.json"
    out_path.write_text("old content that must not remain")
    result = write_output_result(
        {"new": True}, fmt="json", out_path=out_path, stem="explicit"
    )
    envelope = json.loads(result.rendered)
    assert envelope["artifact_path"] == str(out_path)
    assert json.loads(out_path.read_bytes()) == {"new": True}
    assert "ok" not in envelope


def test_summary_flags_truncated_keys():
    from pry.output import _summary

    big = {f"k{i:02d}": i for i in range(25)}
    summary = _summary(big)
    assert summary["kind"] == "object"
    assert summary["count"] == 25
    assert len(summary["keys"]) == 10
    assert summary["keys_truncated"] is True

    small = _summary({"a": 1, "b": 2})
    assert small["count"] == 2
    assert "keys_truncated" not in small
