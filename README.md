# Moonslot

Private workspace with Google and GitHub sign-in (Firebase Auth) and a small Node.js API.

## Structure

```
public/            Everything the browser loads
  index.html
  css/styles.css
  js/app.js            UI + Firebase Auth
  js/firebase-config.js
  assets/              Logo mark and favicon (SVG)
server.js          Static files + API (no npm dependencies)
```

## Run

```bash
node server.js        # http://localhost:3000
```

Optional `.env` (never commit it): `PORT`, `API_KEYS`, `SIGNING_SECRET`, `REQUIRE_SIGNATURE`, `PAYLOAD_FILE`, `CORS_ORIGINS`, `TRUST_PROXY`.

## Enable sign-in providers

In Firebase Console > Authentication > Sign-in method:

1. **Google**: enable it.
2. **GitHub**: enable it, then create an OAuth App at GitHub > Settings > Developer settings > OAuth Apps.
   Set the callback URL to `https://moonslot-85d96.firebaseapp.com/__/auth/handler`, and paste the Client ID and Client secret into Firebase.
3. Add your domain (and `localhost`) under Authentication > Settings > Authorized domains.
