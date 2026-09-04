# LogForge

LogForge turns common SSH and authentication log lines into compact security summaries. It is built for local log review, incident triage and learning how repeated authentication failures appear in real system logs.

## Features

* Recognizes common OpenSSH success and failure patterns
* Tracks repeated failures by source address
* Configurable suspicious-source threshold
* Human-readable summaries
* Full JSON event export
* Tolerates malformed and mixed-encoding log files

## Install

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

LogForge analyzes files you provide. It does not connect to remote systems, attempt logins or alter log data.

## Development

```bash
python -m unittest discover -s tests -v
```

## Credits

Built by [meduuv](https://guns.lol/meduu).

## License

MIT
