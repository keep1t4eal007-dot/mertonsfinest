# SceneSpool shared server

This service connects the SceneSpool website to shared artist profiles, artist music uploads, and one-to-one and group messaging.

## Run locally

1. Install Docker Desktop.
2. From this folder, run `docker compose up --build`.
3. Open `http://localhost:3000`.

The local database uses a Docker volume. Its credentials and session secret in `docker-compose.yml` are for local development only.

## Deploy on Render

The `render.yaml` Blueprint creates one Docker web service and one PostgreSQL database in Frankfurt on Render's free tier. The web service sleeps after 15 minutes without incoming traffic; its first request after sleep can take about a minute to respond. Render's free PostgreSQL expires after 30 days. Treat this as a short beta only and upgrade/migrate before real users rely on stored accounts, messages, or music. The Blueprint generates the session secret in Render; no secrets belong in this repository or the website HTML.

Artist audio delivery is capped at 3.5 GB per calendar month. The database limits artist audio storage to 600 MB and each upload to 20 MB. Artists may upload up to 20 tracks each, with a server-verified maximum duration of 10 minutes. Reaching a cap blocks additional uploads or streaming until capacity is available again.

## Shared profiles and music

- Profiles and profile pictures are saved in PostgreSQL and shown in the public artist directory.
- Artist uploads are stored in PostgreSQL and are playable by anyone who visits the music shelf or radio.
- The server checks track duration with `ffprobe`; browser-side duration checks are only a convenience.
- Track streams support byte ranges so audio players can seek.
- The API accepts requests from the SceneSpool website origin and uses short-lived bearer tokens kept in browser `sessionStorage` for sign-in. The server stores token hashes, not the tokens.

## Messaging

- Passwords are stored as salted scrypt hashes.
- Artists can create direct and group conversations with up to 20 members.
- Message text is stored in PostgreSQL and protected in transit by HTTPS. Messages are not end-to-end encrypted, so the service operator can access stored message content.
- Signup does not verify email ownership; password reset email is not configured. Do not treat accounts as identity-verified.

## Privacy and operations

Artist directory details and uploaded tracks are public. Do not upload copyrighted audio without the rights to share it or add private information to a public profile. The privacy page should explain the actual data collected, retention, operator contact, and account-deletion process before inviting a wider community. The free PostgreSQL database expires after 30 days. Add a public operator contact and move to durable storage before inviting a wider community.
