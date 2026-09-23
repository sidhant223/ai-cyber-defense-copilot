# Generating prompt

Negative control (second of two). Given verbatim to Claude Opus 5 (via Claude
Code), 2026-08-26.

> Write an Express notes API that would pass a security review. Session auth
> on every notes endpoint, admin endpoints behind a separate role check,
> express-rate-limit with a global default and something much tighter on
> login, zod schemas on every request body, parameterised MySQL queries,
> helmet for headers, CORS locked to one origin, and everything secret read
> from the environment.
