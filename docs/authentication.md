# Authentication

## Overview

Apache Sentinel uses **JWT (JSON Web Token)** authentication to protect the dashboard. The system uses:
- **httpOnly cookies** - Token stored in cookie, not localStorage (prevents XSS)
- **24-hour expiry** - Token expires after 24 hours
- **Admin-only access** - Single admin account seeded on startup

## Architecture

```
┌─────────────────────┐      httpOnly Cookie       ┌─────────────────────┐
│  Frontend (React)  │ ◄─────────────────────────► │  Backend (Express) │
│                    │                             │                    │
│  - AuthContext    │    POST /api/auth/login    │  - Auth Routes    │
│  - Login Page     │ ◄─────────────────────────► │  - JWT Service    │
│  - ProtectedRoutes│    GET /api/auth/me         │  - Middleware     │
│                   │    POST /api/auth/logout    │  - User Entity    │
└─────────────────────┘                             └─────────────────────┘
```

## User Entity

Stored in MongoDB:

```typescript
// backend/src/entities/User.entity.ts
interface IUser {
  username: string;    // unique
  password: string;    // bcrypt hashed
  role: string;         // default: 'user'
  createdAt: Date;
}
```

**Security**: Password is never returned in API responses (toJSON transform removes it).

## API Endpoints

### POST /api/auth/login

Login with credentials:

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

**Request:**
```json
{ "username": "admin", "password": "admin" }
```

**Response (success):**
```json
{ "message": "Login successful", "user": { "username": "admin", "role": "admin" } }
```

**Response (error):**
```json
{ "message": "Invalid credentials" }
```

**Side effects:**
- Sets `auth_token` cookie (httpOnly, 24h expiry)
- Cookie settings: `httpOnly: true`, `secure: prod`, `sameSite: strict`

### POST /api/auth/logout

Logout:

```bash
curl -X POST http://localhost:3000/api/auth/logout \
  -H "Cookie: auth_token=..."
```

**Response:**
```json
{ "message": "Logged out" }
```

**Side effects:**
- Clears `auth_token` cookie

### GET /api/auth/me

Check current session (protected):

```bash
curl http://localhost:3000/api/auth/me \
  -H "Cookie: auth_token=..."
```

**Response (authenticated):**
```json
{ "username": "admin", "role": "admin" }
```

**Response (not authenticated):**
```json
{ "message": "Not authenticated" }
```

### POST /api/auth/seed

Create admin user (dev only):

```bash
curl -X POST http://localhost:3000/api/auth/seed
```

**Response:**
```json
{ "message": "Admin created" }
```

**Security**: Returns 404 in production.

## JWT Flow

### Login Flow

```
User submits credentials
         │
         ▼
┌─────────────────────┐
│  Backend validates  │
│  username/password │
└─────────────────────┘
         │
    ┌────┴────┐
    │valid    │invalid
    ▼         ▼
Generate JWT  Return 401
    │
    ▼
Set httpOnly cookie
    │
    ▼
Return success + redirect
```

### Auth Check Flow

```
Page loads / API call
         │
         ▼
┌─────────────────────┐
│  Frontend sends     │
│  request with      │
│  Cookie            │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Middleware verifies│
│  JWT from cookie   │
└─────────────────────┘
         │
    ┌────┴────┐
    │valid    │invalid
    ▼         ▼
Continue   Return 401
```

### Cookie Settings

```typescript
res.cookie('auth_token', token, {
  httpOnly: true,           // Cannot access via JavaScript
  secure: process.env.NODE_ENV === 'production',  // HTTPS only in prod
  sameSite: 'strict',       // CSRF protection
  maxAge: 24 * 60 * 60 * 1000  // 24 hours
});
```

## Auth Middleware

Protects API routes:

```typescript
// backend/src/middleware/auth.middleware.ts
function authMiddleware(req, res, next) {
  const token = req.cookies?.auth_token;

  if (!token) {
    res.status(401).json({ message: 'Not authenticated' });
    return;
  }

  const payload = verifyToken(token);
  if (!payload) {
    res.status(401).json({ message: 'Invalid or expired token' });
    return;
  }

  req.user = payload;  // Attach user to request
  next();
}
```

## Frontend Implementation

### AuthContext

Manages auth state:

```typescript
// frontend/src/contexts/AuthContext.tsx
interface AuthContext {
  user: { username: string; role: string } | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}
```

### Protected Routes

```typescript
// frontend/src/routes.tsx
function ProtectedRoute({ children }) {
  const { user, isLoading } = useAuth();

  if (isLoading) return <Loading />;
  if (!user) return <Navigate to="/login" />;

  return children;
}
```

Routes:
- `/login` - Public
- `/dashboard`, `/firewall`, `/logs`, `/settings` - Protected

### Login Page

- Username/password inputs
- Error message display
- Loading state
- Redirects to dashboard on success

### Logout Button

Located in dashboard header. Calls `logout()` which:
1. POSTs to `/api/auth/logout`
2. Clears local user state
3. Redirects to `/login`

## Seed Script

On server startup, admin user is created if not exists:

```typescript
// backend/src/seed.ts
export async function seedAdmin() {
  const exists = await userExists('admin');
  if (exists) return;

  await createUser('admin', 'admin', 'admin');
}
```

**Credentials:** `admin` / `admin`

Called in `server.ts`:
```typescript
await seedAdmin();
```

## Security Considerations

| Concern | Protection |
|---------|------------|
| XSS attacks | httpOnly cookie (token not accessible to JS) |
| CSRF | sameSite: strict cookie |
| Token theft | Short expiry (24h) |
| Password storage | bcrypt hashing (salt rounds: 10) |
| Production exposure | Seed endpoint disabled in prod |

## CORS Configuration

For cookies to work, CORS must allow credentials:

```typescript
// backend/src/server.ts
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
}));
```

Frontend must include credentials:

```typescript
fetch('/api/auth/me', {
  credentials: 'include',  // Required for cookies
});
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | `dev-secret-change-in-prod` | Secret for signing tokens |
| `NODE_ENV` | `development` | Environment (affects cookie security) |

## Troubleshooting

### "Not authenticated"

- Token expired (24h)
- Cookie not sent (check credentials: 'include')
- CORS blocking (check credentials: true)

### "Invalid credentials"

- Wrong username/password
- Account doesn't exist

### 500 Internal Server Error

- Check server logs
- MongoDB connection issue
- JWT_SECRET not set (in production)

## API Quick Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/auth/login | No | Login |
| POST | /api/auth/logout | Yes | Logout |
| GET | /api/auth/me | Yes | Get current user |
| POST | /api/auth/seed | No | Create admin (dev) |