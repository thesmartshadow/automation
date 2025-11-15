# ReconPanel

ReconPanel is a web-based automation platform for orchestrating [subfinder](https://github.com/projectdiscovery/subfinder) and [nuclei](https://github.com/projectdiscovery/nuclei) scans. It provides a secure Flask UI for managing scans, reviewing findings, and inspecting logs. Background processing is handled with Celery workers and Redis.

## Features

- User authentication with hashed passwords.
- Dashboard summarizing recent scans and findings.
- Guided form for launching scans with controlled arguments.
- Celery-powered pipeline: wordlist subset → subfinder → nuclei → findings parsing.
- Persistent storage using SQLite (pluggable via `DATABASE_URL`).
- Log aggregation per scan and findings review pages.
- Docker image with subfinder and nuclei pre-installed.
- `docker-compose` stack with web app, Celery worker, and Redis broker.

## Prerequisites

- Docker 20.10+
- docker-compose v2+
- Wordlists available on the host for mounting into the container stack

## Configuration

Set the following environment variables before launching the stack:

- `RECONPANEL_SECRET_KEY` – Flask secret key for sessions and CSRF.
- `RECONPANEL_ADMIN_USERNAME` – Initial admin username created on first boot.
- `RECONPANEL_ADMIN_PASSWORD` – Password for the admin user (stored hashed).
- `DATABASE_URL` – Optional database URL. Defaults to `sqlite:////data/db/reconpanel.db`.

## Wordlists and Logs

Place your domain wordlists in a host directory (e.g., `./data/wordlists`). They will be mounted at `/data/wordlists` inside the containers. Logs are stored under `/data/logs` and persisted to `./data/logs` on the host. The SQLite database lives under `/data/db` (backed by the `reconpanel-db` volume) so the web app and Celery worker share the same state.

Clone the official nuclei templates locally (for example, `git clone https://github.com/projectdiscovery/nuclei-templates.git data/nuclei-templates`). The directory is mounted read-only at `/nuclei-templates` inside the containers and exposed in the UI when creating scans.

## Usage

1. Build and start the services:

   ```bash
   docker-compose up -d --build
   ```

2. Ensure port `9000` is reachable from the internet (e.g., `http://77.237.244.45:9000`).

3. Access the ReconPanel UI in your browser and log in with the admin credentials configured via environment variables.

4. Upload or manage wordlists in `./data/wordlists`, then create scans from the UI.

## Services

- **web** – Flask application served via Gunicorn on `0.0.0.0:9000`.
- **worker** – Celery worker executing scan pipelines.
- **redis** – Redis broker for Celery tasks.

## Running Celery Manually

To run an interactive worker for debugging:

```bash
celery -A reconpanel.celery_app worker --loglevel=info
```

## Development

- Install dependencies with `pip install -r requirements.txt`.
- Export environment variables (at minimum the secret key and admin credentials).
- Run the Flask development server: `flask --app reconpanel.app:create_app run --debug`.
- Start a Celery worker in another terminal as described above.

## Security Considerations

- Commands are executed via `subprocess.run` without `shell=True`.
- Wordlists and template directories are restricted to predefined safe paths.
- CSRF protection is enabled via Flask-WTF.
- Passwords are hashed using Werkzeug utilities.

## License

This project is provided as-is for security research enablement.
