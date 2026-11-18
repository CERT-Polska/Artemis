# Bug: Katana timeout makes detectors report OK instead of an error

## Symptom (incident of 18.11.2026)

Under heavy load, `test_lfi_detector_with_rce` and `test_sql_injection_detector`
(mysql and postgres variants) failed with `OK` instead of `INTERESTING`, although
the vulnerable apps were up and confirmed exploitable at the same time. The only
trace in the logs was:

    WARNING crawling.py - Katana timed out after 180s for http://...

The same tests pass by an order of magnitude faster on a quiet machine. Related
noise from the same cause: Nuclei per-link scans quietly degrade (empty link lists,
scan chunks pinned at ~180s).

## Root cause

`artemis/crawling.py` `_run_katana_uro`: on `subprocess.TimeoutExpired` katana is
killed and its partial - in the hang case empty - output becomes the crawl result.
`crawl_and_filter()` returns `[]` (and caches it for
`KATANA_TIMEOUT_CACHE_TTL_SECONDS`, so other tasks for that target inherit the
empty link list within that window). `get_links_to_scan()` then returns the base
URL only, and crawl-based detectors (`lfi_detector`, `sql_injection_detector`;
Nuclei's link batches too) draw their conclusions from a link-starved target:
nothing found -> `save_task_result(status=OK)`.

An infrastructure failure is thus recorded as a definitive "target is clean"
verdict, visible only as a log WARNING. No error, no retry.

## Reproduce (fast, no image rebuild)

`katana_timeout_returns_ok.py` rides the `./test` volume mount and shadows `katana`
with a never-terminating `sleep` - the same effect load had during the incident,
but deterministic and instant to set up. `KATANA_TIMEOUT_SECONDS=10` keeps phase 2
quick; the default 180 means phase 2 waits 3 minutes.

    # test stack up (image already built - cached, nothing to rebuild):
    docker compose -f docker-compose.test.yaml up -d
    docker compose -f docker-compose.test.yaml run --rm -e KATANA_TIMEOUT_SECONDS=10 \
        test python3 /opt/test/repro/katana_timeout_returns_ok.py

Phase 1 runs the LFI detector against `test-apache-with-lfi-and-rce.local` with a
working katana and must report `INTERESTING`. Phase 2 re-runs the exact same scan
with the shadowed katana and reports `OK`. That contrast is the bug.

## Expected behavior after the fix

A katana timeout is an infrastructure failure: the module should surface it
(raise / `TaskStatus.ERROR`, so karton can retry the task) rather than save a
definitive `OK` computed from a degraded crawl.
