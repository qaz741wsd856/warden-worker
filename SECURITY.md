# Security Policy

Warden is a self-hosted, Bitwarden-compatible backend for Cloudflare Workers. We take security seriously, but please note this project has not been formally security-audited.

## Reporting a Vulnerability

**Preferred:** Use GitHub’s private vulnerability reporting (Security tab → “Report a vulnerability”).

**Do not** open a public issue with exploit details.

When reporting, include:

- A clear description of the issue and impact.
- Steps to reproduce (ideally on your own deployment).
- Affected endpoint(s)/file(s) and any relevant configuration (e.g., `wrangler.toml` ratelimit bindings, Durable Objects offload, R2 attachments).
- Version/commit SHA and your deployment environment (Workers plan, Wrangler version if relevant).

## Disclosure Guidelines

- Please give us a reasonable amount of time to investigate and address the issue before public disclosure.
- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption.
- Do not perform denial-of-service testing against the demo instance.

## Supported Versions

Security fixes are provided on a best-effort basis for the latest release and the `main` branch. Older versions may not receive security patches.

## In Scope

- Backend implementation in `src/` (auth, crypto, handlers, database access).
- Worker entrypoint and edge concerns in `src/entry.js` (routing, attachment streaming, Durable Objects offload).
- Wrangler configuration in `wrangler.toml` (bindings, rate limiting, routes).
- Database schema and migrations (`sql/`, `migrations/`).
- Deployment tooling and scripts (`docs/`, `scripts/`, GitHub Actions workflows).
- UI overrides shipped by this repo (e.g., `public/css/`).

## Out of Scope / Exclusions

- Issues in upstream Bitwarden clients (mobile/desktop/browser extensions).
- Issues in the bundled upstream Web Vault build (`bw_web_builds`) that are not caused by this repository’s overrides.
- Vulnerabilities in the Cloudflare platform itself (Workers/D1/R2/DO); please report those to Cloudflare.
- Vulnerabilities in unmaintained/outdated deployments.
- Attacks requiring physical access to a user’s device.
- Social engineering, spam, and denial-of-service attempts.

## Deployment Hardening (Operators)

This project is "self-hosted": **your Cloudflare account is part of your security boundary**. Review the deployment docs and consider the following:

- Set strong secrets: `JWT_SECRET` and `JWT_REFRESH_SECRET` (>32 characters, random, unique per environment).
- Restrict who can register/log in (e.g., `ALLOWED_EMAILS`), and consider disabling open registration.
- Ensure rate limiting is configured (see `wrangler.toml` `[[ratelimits]]` bindings); missing bindings degrade gracefully and may reduce protection.
- Treat Cloudflare API tokens as highly sensitive; grant least privilege and rotate when needed.
- Protect backups and exports (D1 backups, logs) as they may contain sensitive metadata.

