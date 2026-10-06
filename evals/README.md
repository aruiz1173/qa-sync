# AI golden evaluations

Each JSON fixture contains `expected` and `actual` objects with `title` and separated `steps` (`content`, `expected`). Keep screenshots and customer data outside this directory. Generate `actual` with the provider/model under evaluation, then run:

```sh
python3 scripts/run_ai_evals.py evals/golden
```

The runner is offline: it reports title accuracy, exact normalized step precision/recall, missing steps and unsupported steps without contacting TestRail or spending provider usage.
