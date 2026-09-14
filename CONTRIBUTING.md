# Contributing to Windeep

Thank you for improving Windeep. Contributions are welcome for authorized-security workflows, reliability, parsers, UI, packaging, documentation, and tests.

## Development requirements

- Python 3.11+
- Windows is required for installer validation; engine tests should remain cross-platform where practical.
- New Python code must include module docstrings and type hints on public functions.
- SQL must use bound parameters.
- Async cancellation must be preserved: catch `asyncio.CancelledError` only to clean up, then re-raise.
- External commands must use argv arrays rather than shell interpolation.

## Workflow

1. Fork or create a feature branch from `main`.
2. Keep each change focused and include tests.
3. Run `pytest` locally.
4. Open a pull request describing behavior, validation, and security impact.
5. Address review and CI feedback before merge.

## Testing

```powershell
pip install -r requirements.txt
pytest -q
```

For engine changes, cover successful execution, malformed input, cancellation, timeout/backpressure behavior, and concurrency/rate-limit edge cases.

## Security-tool contributions

A wrapper must declare its binary, arguments, input schema, timeout, retry policy, and output parser. Do not enable shell execution. Tool integrations must respect Windeep scope enforcement and should default to conservative concurrency/rate limits.

## Commit style

Use clear imperative commit subjects, for example:

- `feat: add wildcard event subscriptions`
- `fix: preserve scheduler cancellation`
- `test: cover wrapper retry exhaustion`

## Responsible use

Do not submit features intended to bypass authorization boundaries, persist on third-party hosts, steal credentials, deploy malware, or hide malicious activity. Windeep is for legitimate bug-bounty and security-assessment work within explicit scope.
