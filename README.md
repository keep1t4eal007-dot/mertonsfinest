# SceneSpool shared server

This service connects the SceneSpool website to shared artist profiles, artist music uploads, and one-to-one and group messaging.

## Run locally

1. Install Docker Desktop.
2. From this folder, run `docker compose up --build`.
3. Open `http://localhost:3000`.

The local database uses a Docker volume. Its credentials and session secret in `docker-compose.yml` are for local development only.

## Deploy on Render

The `render.yaml` Blueprint creates one Docker web service and one PostgreSQL database in Frankfurt. It uses the smallest always-on web plan, sets the database to 1 GB, disables storage auto-growth, and restricts database connections to Render's private network. It generates the session secret in Render; no secrets belong in this repository or the website HTML.

The initial hosting estimate is about **$13 USD/month** for the web service and database. Render includes 5 GB of monthly bandwidth at the workspace level; artist audio delivery is capped at 3.5 GB per calendar month to leave room for API traffic. The database limits artist audio storage to 600 MB and each upload to 20 MB. Artists may upload up to 20 tracks each, with a server-verified maximum duration of 10 minutes. Reaching a cap blocks additional uploads or streaming until capacity is available again. Other Render services in this workspace could use some of the shared bandwidth allowance.

## Shared profiles and music

- Profiles and profile pictures are saved in PostgreSQL and shown in the public artist directory.
- Artist uploads are stored in PostgreSQL and are playable by anyone who visits the music shelf or radio.
- The server checks track duration with `ffprobe`; browser-side duration checks are only a convenience.
- Track streams support byte ranges so audio players can seek.
- The API accepts requests from the SceneSpool website origin and uses short-lived bearer tokens kept in browser `sessionStorage` for sign-in. The server stores token hashes, not the tokens.

## Encrypted messages

- Passwords are stored as salted scrypt hashes.
- The browser encrypts new message text with AES-GCM before it reaches the server. A separate random message key is wrapped for each conversation member using P-256 ECDH and HKDF-SHA-256.
- PostgreSQL stores ciphertext, key envelopes, account data, conversation membership, sender IDs, timestamps, and approximate message sizes. The service cannot read new message text from the stored ciphertext.
- Each artist creates a recovery phrase of at least 16 characters. PBKDF2-HMAC-SHA-256 with 600,000 iterations derives the key that encrypts the private-key backup. The recovery phrase is entered in the browser and is not sent to the server.
- Artists need the recovery phrase to unlock encrypted messages on a new device. If it is lost, the encrypted history cannot be recovered.
- Key fingerprints can be compared through a separate trusted channel. Keys are not automatically verified, and this version does not implement a Double Ratchet or forward secrecy.
- The website host controls the JavaScript delivered to visitors. A malicious code change could capture text before encryption or after decryption. This implementation has not had an independent security audit.
- Signup does not verify email ownership; password reset email is not configured. Do not treat accounts as identity-verified.

## Privacy and operations

Artist directory details and uploaded tracks are public. Do not upload copyrighted audio without the rights to share it or add private information to a public profile. The privacy page should explain the actual data collected, retention, operator contact, and account-deletion process before inviting a wider community. Back up the PostgreSQL database and review Render usage so the 1 GB storage and bandwidth caps remain sufficient.
