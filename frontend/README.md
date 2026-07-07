# Kasra Frontend

Web dashboard for the Kasra AI Development Security Governance Platform.

## Tech Stack

- **Framework:** React 19 + TypeScript
- **Build:** Vite 5
- **Styling:** Tailwind CSS 3
- **Charts:** Recharts
- **Linting:** Oxlint

## Getting Started

```bash
# Install dependencies
npm install

# Development (requires backend on port 8080)
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

## Project Structure

```
src/
├── api/client.ts          # API client with auto-auth headers
├── auth.tsx               # Auth context (API key in localStorage)
├── App.tsx                # Layout + routing
├── pages/
│   ├── Login.tsx          # API key login
│   ├── Dashboard.tsx      # Stats, trends, top rules/users
│   ├── AuditLogs.tsx      # Paginated audit log viewer
│   ├── Rules.tsx          # Rule list with enable/disable toggle
│   └── UserBehavior.tsx   # User activity analysis
└── main.tsx               # Entry point
```

## Configuration

The development server proxies API requests to `http://localhost:8080` via Vite config.

In production, the built assets are served by the FastAPI backend directly from `frontend/dist/`.

## Build

```bash
npm run build    # Output: dist/
```

## Auth

All API calls automatically include the `X-API-Key` header from `localStorage('kasra_api_key')`.
The login page stores the key after successful verification against the `/health` endpoint.
