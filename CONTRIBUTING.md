# Contributing

Issues are welcome: a false alarm, a missed problem, a report that is hard to understand, or a project the scanner fails on. Please include the smallest code that shows it, never real secrets or private code.

Pull requests are not accepted yet.

## Working on the code

```
npm ci
npm test
```

`npm test` runs the unit tests and checks that `dist/epherem-scanner.cjs` is exactly what the source builds. After changing the source, rebuild it with `npm run build:bundle` and commit the result.
