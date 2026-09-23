# Generating prompt

Negative control. Given verbatim to Claude Opus 5 (via Claude Code),
2026-08-26. Unlike the other samples, this prompt *does* ask for the controls,
which is exactly what makes it useful: a scanner that flags everything is
useless, and this sample is how we demonstrate that it does not.

> Write a FastAPI task-tracking service. It needs to be production-ready and
> security-reviewed: authentication on every endpoint that touches user data,
> a role check on the admin endpoints, rate limits (tight ones on login),
> Pydantic models for every request body, parameterised queries, no secrets in
> the source, CORS restricted to our own front end, and the usual security
> response headers.
