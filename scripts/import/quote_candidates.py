"""Conservative quote extraction for imessage-exporter TXT transcripts."""

import re
import unicodedata
from datetime import datetime


_TIMESTAMP_RE = re.compile(
    r"^(?P<date>[A-Z][a-z]{2} \d{1,2}, \d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)"
    r"(?:\s+\(.*\))?$"
)
_COMMENTARY_RE = re.compile(r"[,;:!?()\[\]{}]|\b(?:said|says|replied|wrote|"
                            r"added|continued|noted|asked|explained|who|because|"
                            r"after|before|later|quietly|joking)\b", re.IGNORECASE)


def _normalise(value):
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _indent(value):
    return len(value) - len(value.lstrip(" \t"))


def _messages(text):
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if _TIMESTAMP_RE.fullmatch(line.strip())]
    ancestors = []
    for number, start in enumerate(starts):
        end = starts[number + 1] if number + 1 < len(starts) else len(lines)
        indent = _indent(lines[start])
        while ancestors and ancestors[-1][0] >= indent:
            ancestors.pop()
        parent = ancestors[-1] if ancestors else None
        message = {
            "source_timestamp": _TIMESTAMP_RE.fullmatch(lines[start].strip()).group("date"),
            "source_message_line": start + 1,
            "sender": lines[start + 1].strip() if start + 1 < end else "",
            "body": "\n".join(line[indent:] if _indent(line) >= indent else line
                              for line in lines[min(start + 2, end):end]),
            "body_line": min(start + 2, end) + 1,
            "indent": indent,
            "parent_source_message_line": parent[1] if parent else None,
        }
        ancestors.append((indent, start + 1))
        yield message


def _quote(lines, start):
    line = lines[start].lstrip()
    if not line or line[0] not in '"“':
        return None
    close = '"' if line[0] == '"' else '”'
    parts = [line[1:]]
    for end in range(start, len(lines)):
        if close in parts[-1]:
            text, trailing = parts[-1].split(close, 1)
            parts[-1] = text
            return "\n".join(parts), end, trailing.strip()
        if end + 1 == len(lines):
            return None
        parts.append(lines[end + 1])


def _speaker(value):
    match = re.fullmatch(r"[ \t]*[-–—][ \t]*(.+?)[ \t]*", value)
    return match.group(1) if match else None


def _parts(message):
    lines = message["body"].splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "Tapbacks:":
            lines = lines[:index]
            break
    parts = []
    has_attribution = False
    index = 0
    while index < len(lines):
        item = _quote(lines, index)
        if item is None:
            index += 1
            continue
        text, end, trailing = item
        attribution = _speaker(trailing)
        next_index = end + 1
        if not trailing:
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            if next_index < len(lines):
                attribution = _speaker(lines[next_index])
                if attribution is not None:
                    end = next_index
        if attribution is not None:
            has_attribution = True
        if text.strip():
            author = attribution or ""
            if _normalise(author) == "guess who":
                author = ""
            parts.append((text.strip(), author, index))
        index = end + 1
    return parts, has_attribution


def _timestamp(message):
    return datetime.strptime(message["source_timestamp"], "%b %d, %Y  %I:%M:%S %p")


def _body_identity(body):
    return _normalise("\n".join(line for line in body.splitlines()
                                  if _normalise(line) != "this message responded to an earlier message."))


def _is_attribution_message(message):
    return _speaker(message["body"].strip())


def _is_correction(parts):
    return (len(parts) == 1 and _normalise(parts[0][1]) == "correction")


def _next_top_level(messages, index):
    for following in range(index + 1, len(messages)):
        message = messages[following]
        if message["indent"] == 0:
            return message
    return None


def _merged(parts):
    authors = list(dict.fromkeys(author for _, author, _ in parts if author))
    text = (parts[0][0] if len(parts) == 1 else
            "\n".join(f'{author or "Unknown speaker"}: “{text}”' for text, author, _ in parts))
    reasons = []
    if any(not author for _, author, _ in parts):
        reasons.append("some speakers are unknown; confirm the dialogue attribution")
    if any(_COMMENTARY_RE.search(author) for author in authors):
        reasons.append("attribution may contain commentary")
    return text, " & ".join(authors), "; ".join(reasons) or None


def parse_export(text):
    """Return message-level quote candidates with per-fragment attribution."""
    # ponytail: format-based heuristic; human review covers unusual quote styles.
    messages = list(_messages(text))
    unique_messages = []
    identities = {}
    for message in messages:
        identity = (message["source_timestamp"], _normalise(message["sender"]),
                    _body_identity(message["body"]))
        if identity not in identities:
            identities[identity] = len(unique_messages)
            unique_messages.append(message)
        elif message["indent"] > 0 and unique_messages[identities[identity]]["indent"] == 0:
            # The indented render retains the reply lineage that the duplicate omits.
            unique_messages[identities[identity]] = message
    candidates = {}
    by_message_line = {}
    corrections = []
    for index, message in enumerate(unique_messages):
        parsed, has_attribution = _parts(message)
        attribution = None
        attribution_message_line = None
        if (message["indent"] == 0 and parsed and not has_attribution and
                index + 1 < len(unique_messages)):
            neighbor = _next_top_level(unique_messages, index)
            if (neighbor is not None and neighbor["indent"] == 0 and
                    _normalise(neighbor["sender"]) == _normalise(message["sender"]) and
                    0 <= (_timestamp(neighbor) - _timestamp(message)).total_seconds() <= 60):
                attribution = _is_attribution_message(neighbor)
                if attribution is not None:
                    attribution_message_line = neighbor["source_message_line"]
        if not parsed or (not has_attribution and attribution is None):
            continue
        if attribution is not None:
            parsed = [(quote, attribution, offset) for quote, _, offset in parsed]
        if _is_correction(parsed):
            corrections.append((message, parsed[0]))
            continue
        # Resolve relative speakers before deduplication: two senders' "me" differ.
        parsed = [(quote, " & ".join(message["sender"] if _normalise(name) == "me" else name
                                    for name in re.split(r"\s*&\s*", author)), offset)
                  for quote, author, offset in parsed]
        quote, author, reason = _merged(parsed)
        source_line = message["body_line"] + parsed[0][2]
        parts = [{"text": item_text, "author": "" if _normalise(item_author) == "guess who"
                  else item_author, "source_line": message["body_line"] + offset}
                 for item_text, item_author, offset in parsed]
        occurrence = {
            "source_message_line": message["source_message_line"],
            "source_line": source_line,
            "source_timestamp": message["source_timestamp"],
        }
        key = tuple((_normalise(t), _normalise(a)) for t, a, _ in parsed)
        candidate = candidates.get(key)
        if candidate is None:
            candidate = {
                "text": quote, "author": author, "parts": parts, "raw_body": message["body"],
                **occurrence, "occurrences": [occurrence], "source_lines": [source_line],
                "count": 1, "needs_review": reason is not None, "sender": message["sender"],
                "source_sender": message["sender"],
                "parent_source_message_line": message["parent_source_message_line"],
                "attribution_message_line": attribution_message_line, "corrections": [],
            }
            if reason:
                candidate["reason"] = reason
            candidates[key] = candidate
            by_message_line[message["source_message_line"]] = candidate
        else:
            candidate["count"] += 1
            candidate["occurrences"].append(occurrence)
            candidate["source_lines"].append(source_line)
            candidate.setdefault("raw_bodies", [candidate["raw_body"]]).append(message["body"])
            by_message_line[message["source_message_line"]] = candidate

    for message, correction in corrections:
        parent = message["parent_source_message_line"]
        if parent in by_message_line:
            by_message_line[parent]["corrections"].append({
                "text": correction[0], "sender": message["sender"],
                "source_message_line": message["source_message_line"],
                "source_line": message["body_line"] + correction[2], "parent": parent,
            })

    return {
        "messages": len(messages),
        "first_timestamp": messages[0]["source_timestamp"] if messages else None,
        "last_timestamp": messages[-1]["source_timestamp"] if messages else None,
        "candidates": list(candidates.values()),
        "ignoredcount": 0,
    }
