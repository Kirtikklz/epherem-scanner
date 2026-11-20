# How the scanner is tested

This page says how the scanner's checks were built and tested, and what the numbers mean. It does not claim the scanner is accurate. Its findings are possible problems, and every one should be checked before code is changed.

## Real projects

The checks were run, again and again, against real public projects, to find where they raise false alarms and where they miss things:

- **21 public projects** in the main test set: apps made with AI app builders, small and production open-source web apps, deliberately vulnerable training apps (which have known problems), projects that are unusually dense in secrets or logging, and the scanner's own source code.
- **40 public Python projects** in three further sets: Flask, FastAPI and Django apps.

Every project is pinned to an exact commit, so a run can be repeated byte for byte. The projects are read as text only: nothing in them is installed, built or run. None of them is named here, and no finding about any of them is published.

With the bundled vulnerability data of 17 November 2026 and no network, the scanner reports 998 findings across these 61 projects. These are findings **detected**, not problems **confirmed**: each is a place worth checking.

## False alarms

Every finding on the main test set is classified against a written rubric of five labels: a real problem worth fixing; a real problem that is poorly explained; uncertain without information the scanner can't have; correct but repetitive or low value; or a false alarm. Each classification records the file and line it was judged from and a reason.

When a false alarm was traced to its cause, the check was narrowed. A change that moves any finding on the main test set has to list every finding it moves, each with its reason, and a check refuses the change if the list and the real difference disagree; 29 such lists are on record.

No accuracy percentage is published. The labels were not made by independent security reviewers, so they show how consistent the scanner is, not how accurate it is.

## Test apps with planted problems

32 small test projects hold known problems, most of them planted on purpose: injection, path traversal, cross-site scripting, request forgery, missing ownership checks, open database rules and others. Changes to the scanner are checked against them, and their reports are expected to stay byte-for-byte the same unless a change is meant to move them.

## Automated tests

The full test suite has 4,477 tests. This repository carries the 2,499 of them that run without the private test data (`npm test`).

Many safety properties in the code are also checked by a deliberate break: a small edit that should make a test fail, run to prove the test does fail. 1,625 such edits to the scanner are on record.

## Known limits

- The scanner reads source code. It never runs the app, so it can't see what happens at run time, in a database dashboard, in hosting settings or behind a gateway.
- Many checks look for a protection and report when they don't see one. The protection may exist somewhere the scan can't see. Those findings are marked "Needs checking".
- JavaScript and TypeScript are read most thoroughly. Python is read partly. Other languages, and the code inside `.vue`, `.svelte` and `.astro` files, are not read yet.
- The package check knows only published vulnerabilities, and offline only those in the bundled data.
- A short report, or an empty one, does not mean an app is safe.
