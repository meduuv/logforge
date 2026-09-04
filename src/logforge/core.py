from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

FAILED_PATTERNS = (
    re.compile(
        r"failed password for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<ip>[0-9a-fA-F:.]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"authentication failure.*?rhost=(?P<ip>\S+)(?:.*?user=(?P<user>\S+))?",
        re.IGNORECASE,
    ),
)

SUCCESS_PATTERNS = (
    re.compile(
        r"accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)",
        re.IGNORECASE,
    ),
)


@dataclass(slots=True)
class Event:
    kind: str
    line: int
    ip: str | None
    user: str | None
    text: str


def _match_event(text: str, line_number: int) -> Event | None:
    for pattern in FAILED_PATTERNS:
        match = pattern.search(text)
        if match:
            groups = match.groupdict()
            return Event(
                kind="failed_auth",
                line=line_number,
                ip=groups.get("ip"),
                user=groups.get("user"),
                text=text,
            )

    for pattern in SUCCESS_PATTERNS:
        match = pattern.search(text)
        if match:
            groups = match.groupdict()
            return Event(
                kind="successful_auth",
                line=line_number,
                ip=groups.get("ip"),
                user=groups.get("user"),
                text=text,
            )

    return None


def parse(lines) -> list[Event]:
    events: list[Event] = []
    for line_number, raw_line in enumerate(lines, 1):
        text = raw_line.rstrip("\n")
        event = _match_event(text, line_number)
        if event is not None:
            events.append(event)
    return events


def analyze(events: list[Event], threshold: int = 5) -> dict:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    failed_sources = Counter(
        event.ip
        for event in events
        if event.kind == "failed_auth" and event.ip
    )
    failed_users = Counter(
        event.user
        for event in events
        if event.kind == "failed_auth" and event.user
    )

    suspicious_sources = [
        {"ip": ip, "failures": failures}
        for ip, failures in failed_sources.most_common()
        if failures >= threshold
    ]

    return {
        "events": len(events),
        "by_type": dict(Counter(event.kind for event in events)),
        "top_failed_ips": failed_sources.most_common(10),
        "top_failed_users": failed_users.most_common(10),
        "suspicious_sources": suspicious_sources,
    }
