# Contributing

Contributions are welcome when they improve parsing accuracy, portability, documentation or test coverage.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Pull requests

Keep parser changes narrow and include representative sanitized log lines in tests. New rules should avoid matching unrelated system messages and should document which log format they target.

LogForge is a defensive local-analysis project. Remote access, credential testing and exploitation features are outside its scope.

## Reporting issues

Sanitize usernames, addresses, hostnames and other private log data before posting examples publicly.
