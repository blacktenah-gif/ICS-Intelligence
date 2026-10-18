# ICS Intelligence — secure backend starter

This is a runnable starter project based on the ICS Intelligence requirements. It includes a public website, separate administrator portal, server-side authentication, email verification codes, preset themes, and editable package prices.

## Included
- Public website and customer registration/login.
- Customer email verification before login.
- Administrator sign-in requires password plus an email one-time code.
- One-time first-administrator setup protected by `ADMIN_SETUP_TOKEN`.
- Passwords hashed with bcrypt; verification codes are hashed in the database, expire after 10 minutes, and are limited to five attempts.
- HTTP-only, SameSite session cookie; login rate limiting; Helmet security headers.
- Admin-only API routes for settings, users and audit logs.
- Themes: blue, green, purple and dark.
- Public users can save their selected theme to their account so it follows them across devices.
- Original prices: Daily 500 RWF, Weekly 2,500 RWF, Monthly 8,000 RWF, Annual 80,000 RWF.
- SQLite database created automatically on first run.

## Requirements
- Node.js 20 or newer
- An SMTP email account/provider to send real verification codes

## Run on Windows with VS Code
1. Extract the ZIP to a folder, for example `C:\ICS-Intelligence`.
2. Open that folder in VS Code.
3. Install Node.js 20+ if it is not already installed: https://nodejs.org/
4. In VS Code, open **Terminal → New Terminal**.
5. Run `npm install`.
6. Copy `.env.example` to a new file named `.env`.
7. Edit `.env`: create long random values for `SESSION_SECRET` and `ADMIN_SETUP_TOKEN`, then enter your SMTP provider's host, port, username, password and sender address. Do not share `.env` or commit it to source control.
8. Run `npm start`.
9. Open `http://localhost:3000` in your browser.
10. Click **● Demo Administrator**. Expand **First-time administrator setup**, enter the setup token and the administrator email/password, then use the code delivered to that email. Once the administrator is created, setup cannot create another administrator.
11. After setup, remove or rotate `ADMIN_SETUP_TOKEN` in `.env` and keep the `.env` file private.

## SMTP configuration
Real email codes will not work until SMTP is configured. If SMTP is absent, the app intentionally does not show or return codes in the browser. Use credentials from your email provider; many providers require an app password or a transactional email service.

## Important production checklist
This is a development starter, not a finished production deployment. Before exposing it to the internet:
- Deploy behind HTTPS and set `NODE_ENV=production`.
- Replace Express's default in-memory session store with a persistent store such as Redis or a database-backed store.
- Use PostgreSQL or another managed production database, automatic backups, migrations and monitoring.
- Add CSRF protections/origin checks, account recovery, email-change verification, MFA, stronger login monitoring, and a formal admin invitation/role-management workflow.
- Remove the one-time setup capability after first admin creation and securely rotate the setup token.
- Complete privacy, child-safety, consent, and applicable legal reviews.
- Implement family profiles, approval requests, country authorization workflow, subscription payment provider, and device/browser enforcement before presenting those features as operational.

## Important limitations
- The catalogue/site alone does not block websites on a child's device. Enforcement requires a browser extension or native device/OS integration.
- Payment processing is not implemented; prices are editable and displayed only.
- The starter provides the foundations for accounts and settings, but family approvals and country authorization are not yet wired to persistent business workflows.
- Existing prototype code was not attached to the chat when this package was created. This package preserves the described design requirements and prices, but it is a replacement starter rather than a line-by-line edit of the original file.
