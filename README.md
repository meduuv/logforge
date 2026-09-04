# LogForge

> Turn authentication logs into compact, useful security summaries.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-111111?style=flat-square)](LICENSE)

LogForge parses common SSH and authentication log lines into structured security summaries for **local log review, incident triage and security learning**.

## Features

- Recognizes common OpenSSH success and failure patterns
- Tracks repeated failures by source address
- Configurable suspicious-source threshold
- Human-readable summaries
- JSON event export
- Tolerates malformed and mixed-encoding log files

## Installation

```bash
git clone https://github.com/meduuv/logforge.git
cd logforge
pip install -e .
```

## Usage

```bash
logforge /var/log/auth.log
logforge ./auth.log --threshold 3
logforge ./auth.log --json
```

## Processing model

```text
log file
   ↓
pattern recognition
   ↓
normalized events
   ↓
aggregation
   ↓
security summary / JSON
```

LogForge analyzes files you provide. It does **not** connect to remote systems, attempt logins or modify log data.

## Use Cases

- Local authentication-log review
- Incident triage
- Security monitoring prototypes
- Learning how repeated authentication failures appear in system logs
- Feeding normalized events into other defensive tooling

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT. See [`LICENSE`](LICENSE).

Built by **Meduuv**.

[More projects](https://github.com/meduuv?tab=repositories) · [guns.lol/meduu](https://guns.lol/meduu)
