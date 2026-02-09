# AGENTS.md

## Working Agreement
- Validate external API fields against the live API (or local fixtures) before adding logic based on them.
- Prefer a quick, concrete check (curl or small Python) over assumptions.
- Keep changes minimal and aligned with actual response schemas.
- If a quick check fails (no network/tool missing), state it explicitly and avoid speculative fields.
- Remove temporary scaffolding or unused code before finishing.

## API Field Validation
- When a feature depends on a response field (e.g., date fields), fetch a real sample and list the keys used.
- Use the exact field names returned by the API; do not invent fallbacks unless verified.
- Document any fallback logic in code comments only if it is required for compatibility.

## Quality Checks
- Run a minimal sanity check for modified logic paths when feasible.
- If tests are not run, state that clearly in the response.
