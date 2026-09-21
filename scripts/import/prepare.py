#!/usr/bin/env python3
"""Prepare a private, offline QuoteVault review from an iMessage TXT export."""

import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from quote_candidates import _merged, _normalise, parse_export


ROOT = Path(__file__).parent
REVIEW_SCRIPT = (ROOT / "review-script.js").read_text(encoding="utf-8")


def _source_id(chat, sender, timestamp, raw_body):
    lines = []
    for line in raw_body.splitlines():
        if line.strip() == "Tapbacks:":
            break
        if _normalise(line) != "this message responded to an earlier message.":
            lines.append(line)
    value = [chat, sender, " ".join(timestamp.split()), _normalise("\n".join(lines))]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _alias(value, aliases):
    return aliases.get(_normalise(value), value)


def prepare_result(transcript, chat, self_name, aliases=None):
    """Parse transcript and add stable, display-only source metadata."""
    aliases = {_normalise(name): value for name, value in (aliases or {}).items()}
    result = parse_export(transcript)
    for candidate in result["candidates"]:
        raw_sender = candidate["source_sender"]
        candidate["source_id"] = _source_id(chat, raw_sender, candidate["source_timestamp"], candidate["raw_body"])
        candidate["source_chat"] = chat
        candidate["source_sender"] = _alias(self_name if raw_sender == "Me" else raw_sender, aliases)
        candidate["sender"] = candidate["source_sender"]
        for part in candidate["parts"]:
            part["author"] = " & ".join(
                candidate["source_sender"] if _normalise(name) == "me" else _alias(name, aliases)
                for name in re.split(r"\s*&\s*", part["author"]))
        candidate["text"], candidate["author"], _ = _merged(
            [(part["text"], part["author"], part["source_line"]) for part in candidate["parts"]])
        for correction in candidate["corrections"]:
            correction["sender"] = _alias(self_name if correction["sender"] == "Me" else correction["sender"], aliases)
        if candidate["corrections"]:
            candidate["context"] = "\n".join(
                "Correction from {}: {}".format(item["sender"], item["text"])
                for item in candidate["corrections"])
    result["source_fingerprint"] = hashlib.sha256(json.dumps(
        [candidate["source_id"] for candidate in result["candidates"]], separators=(",", ":")).encode()).hexdigest()
    return result


def _page(result, chat):
    data = json.dumps(result, ensure_ascii=True).replace("<", "\\u003c")
    script = "const DATA = " + data + ";\n" + REVIEW_SCRIPT
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    policy = ("default-src 'none'; script-src 'sha256-" + digest + "'; style-src 'unsafe-inline'; "
              "connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="''' + html.escape(policy, quote=True) + '''">
<title>QuoteVault — private quote review</title>
<style>
body{font:17px/1.5 system-ui,sans-serif;background:#f5f5f2;color:#202b32;max-width:850px;margin:32px auto;padding:0 20px}h1{font-size:30px;margin-bottom:8px}p{margin:8px 0}article{background:white;border:1px solid #cbd3d7;border-radius:10px;margin:18px 0;padding:20px}label{display:block;margin:10px 0;font-weight:600}textarea,input[type=text]{box-sizing:border-box;display:block;width:100%;font:inherit;padding:10px;border:1px solid #929ea5;border-radius:5px;margin-top:5px}input[type=checkbox]{width:20px;height:20px;vertical-align:middle}button{font:inherit;background:#155d57;color:white;border:0;border-radius:6px;padding:10px 16px;cursor:pointer}button:disabled{opacity:.5;cursor:default}.source{font-size:14px;color:#52616b}.warning{background:#fff3ce;padding:8px;border-radius:4px}.toolbar{position:sticky;top:0;background:#f5f5f2;border-bottom:1px solid #cbd3d7;padding:12px 0;z-index:1}#status{display:inline-block;margin-right:12px}:focus-visible{outline:3px solid #227bda;outline-offset:3px}
</style>
<h1>Private quote review</h1><p>Chat: ''' + html.escape(chat) + '''. This page runs locally and does not upload data.</p>
<p>Review the text, people quoted, and sender. Corrections are context for you to assess; they never replace quote text automatically.</p>
<div class="toolbar"><span id="status" role="status" aria-live="polite"></span><button id="download" disabled>Download selected quotes</button> <button id="draft">Save full draft</button><label>Restore full draft <input id="restore" type="file" accept=".json,application/json"></label></div>
<main id="records"></main><noscript>JavaScript is needed for this local review page.</noscript><script>''' + script + "</script></html>"


def _export(exporter, backup, chat):
    with tempfile.TemporaryDirectory(prefix="quotevault-import-") as temporary:
        os.chmod(temporary, 0o700)
        environment = {"TMPDIR": temporary}
        command = [str(exporter), "-f", "txt", "-a", "iOS", "-c", "disabled", "-p", str(backup),
                   "-o", temporary, "-t", "chat-name:" + chat]
        subprocess.run(command, check=True, env=environment)
        files = list(Path(temporary).rglob("*.txt"))
        if len(files) != 1:
            raise ValueError("Expected exactly one TXT export for the exact chat name.")
        return files[0].read_text(encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcript", nargs="?", type=Path, help="existing iMessage-exporter TXT transcript")
    parser.add_argument("--chat", required=True, help="exact chat name")
    parser.add_argument("--self-name", required=True, help="name to render for exported Me messages")
    parser.add_argument("--output", required=True, type=Path, help="private output directory")
    parser.add_argument("--aliases", type=Path, help="JSON object mapping exported names to display names")
    parser.add_argument("--exporter", type=Path, help="iMessage-exporter executable")
    parser.add_argument("--backup", type=Path, help="iOS backup directory used with --exporter")
    args = parser.parse_args(argv)
    if bool(args.exporter) != bool(args.backup) or bool(args.transcript) == bool(args.exporter):
        parser.error("provide a transcript, or both --exporter and --backup")
    aliases = json.loads(args.aliases.read_text(encoding="utf-8")) if args.aliases else {}
    if not isinstance(aliases, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in aliases.items()):
        parser.error("--aliases must be a JSON object of string names")
    os.umask(0o077)
    transcript = (_export(args.exporter, args.backup, args.chat)
                  if args.exporter else args.transcript.read_text(encoding="utf-8"))
    result = prepare_result(transcript, args.chat, args.self_name, aliases)
    args.output.mkdir(mode=0o700, parents=True)
    if stat.S_ISLNK(args.output.lstat().st_mode):
        raise ValueError("Output directory must not be a symlink.")
    def write_private(name, value):
        descriptor = os.open(args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
    write_private("quote-review-data.json", json.dumps(result, ensure_ascii=False, indent=2))
    write_private("quote-review.html", _page(result, args.chat))
    print(json.dumps({"candidates": len(result["candidates"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
