# Security Policy

Server Command Center exposes operational host metadata such as process names, PIDs, storage devices and service state. Treat it as an administrative interface.

## Deployment guidance

- Keep authentication enabled for any non-loopback deployment.
- Use HTTPS when accessed outside the local machine.
- Prefer a reverse proxy, VPN, or zero-trust access layer rather than direct router port forwarding.
- Keep the authentication environment file mode `0600`.
- Never commit passwords, password hashes from a real deployment, session secrets, API keys, Tuya local keys, OAuth secrets, private SSH material, or production environment files.
- SCC is read-only by design; avoid adding start/stop/delete controls without a separate authorization model.

## Reporting a vulnerability

Please open a GitHub security advisory or issue without including live credentials or private host data.
