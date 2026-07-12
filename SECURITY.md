# Security Policy

Warden is a self-hosted, Bitwarden-compatible password manager backend built for Cloudflare Workers.

While we take security seriously and follow industry best practices, **this project is maintained by the open-source community and has not been formally audited by professional security firms.** Please use it with an understanding of your own risk tolerance.

---

## 🛑 How to Report a Vulnerability

If you discover a security flaw, **do not open a public GitHub Issue.** Doing so exposes all users to immediate risk.

* **Preferred Method:** Use GitHub’s private vulnerability reporting feature (Go to the **Security** tab of this repository $\rightarrow$ Click **"Report a vulnerability"**).

When submitting a report, please include as much detail as possible to help us fix it quickly:

1. **Description & Impact:** What is the bug, and what could a malicious actor do with it?
2. **Steps to Reproduce:** A clear guide (or Proof of Concept code) to replicate the issue on a test deployment.
3. **Environment Details:** The exact version/commit SHA you are running, your Wrangler version, and your Cloudflare Workers plan.
4. **Configuration:** Mention if specific features are enabled (e.g., Durable Objects offloading, R2 attachments, or Rate Limiting).

### 🤝 Disclosure Guidelines

* **Give us time:** Please allow us a reasonable window to investigate and patch the issue before making any details public.
* **Act in good faith:** Avoid privacy violations, data destruction, or interrupting services for others during your testing.
* **Hands off the Demo:** Do not perform Denial of Service (DoS/DDoS) testing against our public demo instance.

---

## 🛠️ Security Scope

To help researchers, here is what we can patch versus what is out of our control:

### Supported Versions

We only provide security patches for the **latest official release** and the active `main` branch. Older versions are considered unsupported.

### What is IN Scope (We can fix this)

* 🔒 The backend code in `src/` (authentication, cryptography, data handlers, and database queries).
* 🌐 The Worker entry point logic in `src/entry.js` (routing, attachment streaming, and Durable Objects management).
* ⚙️ Default configuration templates like `wrangler.toml` (bindings, default rate limits).
* 🗄️ Database schemas, migrations, deployment scripts, and GitHub Actions workflows.
* 🎨 Custom UI style overrides provided by this repository (e.g., `public/css/`).

### What is OUT of Scope (We cannot fix this)

* **Official Bitwarden Apps:** Vulnerabilities in upstream Bitwarden clients (mobile apps, desktop apps, browser extensions).
* **The Web Vault Frontend:** Vulnerabilities inside the bundled `bw_web_builds` code, unless caused directly by our custom modifications.
* **Cloudflare Infrastructure:** Flaws in the Cloudflare platform itself (Workers, D1, R2, KV, Durable Objects). Please report these directly to Cloudflare.
* **User-End Attacks:** Attacks that require physical access to a user’s unlocked device, or social engineering/phishing attempts.

---

## 🛡️ Simple Hardening Guide (For Non-Technical Operators)

Because Warden is "self-hosted," **your personal Cloudflare account is the frontline defense for your passwords.** Think of Warden as a secure vault, but *you* are responsible for locking the front door.

Please ensure you follow these essential steps:

* **Generate Strong Master Keys:** When setting up `JWT_SECRET` and `JWT_REFRESH_SECRET`, do not type random words. Use a password generator to create unique, completely random strings of **at least 32 characters**.
* **Lock Down Registration:** By default, anyone who knows your Worker URL could theoretically register an account. Restrict this by using the `ALLOWED_EMAILS` feature or completely disabling open registration once your own account is created.
* **Do Not Skip Rate Limiting:** Ensure the `[[ratelimits]]` bindings in `wrangler.toml` are correctly configured. Without them, hackers could try to guess your master password millions of times without being blocked.
* **Guard Your Cloudflare Tokens:** Treat your Cloudflare API tokens like the keys to your house. Grant them the absolute minimum permissions required to deploy, and rotate them every few months.
* **Encrypt and Protect Backups:** Your D1 database backups contain your heavily encrypted passwords. While hackers cannot read them without your Master Password, the metadata (like your email and creation dates) is visible. Store these backups in a secure, private location.
