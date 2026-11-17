# Contributing

Issues and pull requests are welcome.

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Keep changes focused. The project does API keys for Istio and nothing else; features that belong in a general
   authorization engine are better served by [Authorino](https://github.com/Kuadrant/authorino).
3. Add or update tests. `make lint test chart-lint` must pass.
4. Update the README when you change a flag, a Secret annotation or the chart's values.

Commits should say what changed in one line in the imperative ("Add key expiry"). By contributing you agree that your
contribution is licensed under the Apache License 2.0.
