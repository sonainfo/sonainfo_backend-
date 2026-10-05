# Sonainfo Backend

Node.js + Express + PostgreSQL + WebSocket backend for the Sonainfo Executive Portal.

## Files

- `server.js` - complete API + WebSocket server
- `database.sql` - PostgreSQL schema
- `package.json` - dependencies and Render start command
- `.env.example` - required environment variables
- `scripts/seed.js` - optional admin-user seeder
- `.gitignore` - prevents secrets/node_modules from being committed

## Render

Create a **PostgreSQL** database first, then create a **Web Service** from this GitHub repository.

Build Command:
```text
npm install
```

Start Command:
```text
npm start
```

Environment variables:
- `DATABASE_URL` = Internal Database URL from Render PostgreSQL
- `JWT_SECRET` = long random secret
- `JWT_REFRESH_SECRET` = another long random secret
- `FRONTEND_URL` = `https://sonainfo.github.io`
- `NODE_ENV` = `production`
- `UPLOAD_DIR` = `uploads`
- `MAX_FILE_SIZE` = `10485760`

Render supplies `PORT` automatically.

## Database

After creating the Render PostgreSQL database, execute the contents of `database.sql` once in the database SQL console.

Then optionally seed an admin:
```text
SEED_ADMIN_EMAIL=...
SEED_ADMIN_PASSWORD=...
SEED_ADMIN_NAME=...
SEED_ADMIN_ROLE=admin
```
and run:
```text
npm run seed
```

## Health check

```text
GET /health
```

Expected:
```json
{"ok":true,"service":"sonainfo-backend","database":"connected"}
```

## Authentication

Register:
```http
POST /api/auth/register
Content-Type: application/json

{"email":"user@example.com","password":"strongpassword","name":"User","role":"member"}
```

Login:
```http
POST /api/auth/login
Content-Type: application/json

{"email":"user@example.com","password":"strongpassword"}
```

Use:
```http
Authorization: Bearer ACCESS_TOKEN
```

Refresh:
```http
POST /api/auth/refresh
{"refreshToken":"..."}
```

## Realtime

WebSocket endpoint:
```text
wss://YOUR-RENDER-SERVICE.onrender.com/ws
```

Immediately after opening the socket:
```js
ws.send(JSON.stringify({ type: "auth", token: accessToken }));
```

The server broadcasts events such as:
- `portal.updated`
- `user.updated`
- `leave.created`
- `leave.updated`
- `exam.created`
- `exam.updated`
- `notification.created`
- `case.created`
- `case.updated`
- `penalty.created`
- `finance_transaction.created`

## Important: Render local uploads

The included upload endpoint stores files in `uploads/`. On many Render plans the local filesystem is ephemeral, so uploaded files can disappear after a redeploy/restart. For permanent medical/official attachments, connect object storage (S3/R2/Cloudinary/etc.) before production use.
