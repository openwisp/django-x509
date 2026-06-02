# AGENTS.md

## Project Overview

`django-x509` is a Django app for managing certification authorities and x509 certificates used by OpenWISP modules.

Core code lives in `django_x509/`:

- `base/` contains abstract models and core certificate/CA behavior.
- `models.py`, `admin.py`, `settings.py`, `templates/`, and `static/` provide concrete app behavior and UI.
- Tests live in `django_x509/tests/` and `tests/`.

## Source of Truth

- Use `README.rst` and `docs/` for setup, package usage, and baseline test commands.
- Use `.github/workflows/ci.yml` for CI-tested dependencies, QA/test commands, env vars, and supported Python/Django versions.
- Use GitHub issue/PR templates when asked to open issues or PRs.

If instructions conflict, repository config and CI workflows win first, docs next, and this file is supplemental.

## Development Notes

- Keep changes focused. Avoid unrelated refactors and formatting churn.
- Preserve public APIs, migrations, swappable model behavior, certificate generation semantics, and integration points unless explicitly required.
- Mark user-facing strings for translation with Django i18n helpers in Django code.
- Avoid unnecessary blank lines inside function and method bodies.
- Update docs when behavior, settings, public APIs, setup steps, or supported versions change.

## Testing and QA

- Add or update tests for every behavior change.
- For bug fixes, write the regression test first, run it against the unfixed code, confirm it fails for the expected reason, then implement the fix.
- Use targeted tests while iterating, then run the documented full test command before considering the change complete.
- Run `openwisp-qa-format` after editing when available.
- Run `./run-qa-checks` when present. Treat failures as blocking unless confirmed unrelated and reported.
- Prefer in-process tests so coverage tools can measure changed code.

## Django Notes

- Preserve object-level permissions and swappable model support when present.
- Be careful with certificate authority state, certificate revocation, serial numbers, extensions, private key handling, admin actions, and migrations.

## Security Notes

- Watch for private key exposure, unsafe file paths, weak certificate options, invalid extensions, and secrets.
- Preserve validation around CA material, certificate material, revocation, downloads, and uploaded/generated files.
- Write comments and docstrings only when they explain why code is shaped a certain way. Put comments before the relevant code block instead of scattering them inside it.

## Troubleshooting

- If setup, QA, or tests fail, check docs first, then compare with CI. If commands diverge, follow CI.
