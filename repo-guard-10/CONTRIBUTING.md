# Contributing

Keep changes focused and explain the behaviour they alter. New detectors should include both positive and negative tests; avoid adding broad regular expressions without examples of the false positives they are intended to reject.

Before opening a pull request, run:

```bash
python3 -m compileall -q src repoguard.py tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 repoguard.py . --fail-on secret,scan-error
```

The runtime must remain dependency-free. Development tooling may be proposed separately, but the default test suite should continue to run with the Python standard library.

Do not commit real credentials as fixtures. Construct token-shaped values at runtime or suppress clearly fake values on the same line with `repo-guard: allow`.
