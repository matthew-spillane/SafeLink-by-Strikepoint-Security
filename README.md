# SafeLink

A full-stack phishing URL analyzer that runs 10 security checks against any URL and produces a detailed risk report.

## Features

- **VirusTotal Integration** — Checks URL against 70+ antivirus engines
- **Google Safe Browsing** — Cross-references Google's threat database
- **WHOIS / Domain Age** — Flags newly registered domains
- **SSL Certificate Validation** — Verifies HTTPS, issuer, and expiry
- **Redirect Chain Analysis** — Tracks up to 10 redirect hops
- **Suspicious Keyword Detection** — Scans URL for phishing keywords
- **Lookalike Domain Detection** — Fuzzy matching against major brands
- **IP Geolocation** — Identifies hosting provider and country
- **URL Structure Analysis** — Flags structural red flags (IP addresses, uncommon TLDs, etc.)
- **Page Content Sniffing** — Detects login forms, brand mismatches, and data exfiltration

## Tech Stack

| Layer    | Technology                     |
|----------|-------------------------------|
| Backend  | Python, FastAPI, SQLAlchemy   |
| Frontend | React, Tailwind CSS           |
| Database | SQLite                        |
| HTTP     | httpx (async)                 |

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Environment config
│   │   ├── database.py          # SQLAlchemy setup
│   │   ├── models/
│   │   │   ├── scan.py          # Database model
│   │   │   └── schemas.py       # Pydantic schemas
│   │   ├── routers/
│   │   │   └── scan.py          # API endpoints
│   │   └── services/
│   │       ├── analyzers.py     # 10 analysis checks
│   │       └── scanner.py       # Orchestrator + risk scoring
│   └── requirements.txt
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── api.js               # API client
│   │   ├── context/
│   │   │   └── ThemeContext.js   # Dark/light mode
│   │   ├── components/
│   │   │   ├── Header.js
│   │   │   ├── ScanInput.js
│   │   │   ├── ResultsDashboard.js
│   │   │   ├── RiskGauge.js
│   │   │   ├── VerdictBadge.js
│   │   │   ├── SummaryBar.js
│   │   │   ├── CheckCard.js
│   │   │   └── RedirectChain.js
│   │   └── pages/
│   │       ├── HomePage.js
│   │       ├── ScanPage.js
│   │       └── HistoryPage.js
│   └── package.json
├── .env.example
└── README.md
```

## Getting API Keys

### VirusTotal

1. Create a free account at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to your profile → API Key
3. Copy the key and set it as `VIRUSTOTAL_API_KEY`

### Google Safe Browsing

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable the **Safe Browsing API** from the API Library
4. Create an API key under Credentials
5. Set it as `GOOGLE_SAFE_BROWSING_API_KEY`

> Both API keys are optional. If not set, those checks will show as "skipped" in the report.

## Local Development

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm

### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp ../.env.example .env
# Edit .env with your API keys

# Run the server
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm start
```

The app will open at `http://localhost:3000`.

## API Endpoints

| Method | Endpoint           | Description                    |
|--------|--------------------|--------------------------------|
| POST   | `/api/scan`        | Submit a URL for analysis      |
| GET    | `/api/scan/{id}`   | Get a saved scan by ID         |
| GET    | `/api/history`     | Get the last 20 scans          |
| GET    | `/api/health`      | Health check                   |

## Risk Scoring

The risk score is calculated from 0–100 based on weighted check results:

| Check                          | Points              |
|--------------------------------|---------------------|
| VirusTotal flagged             | +40                 |
| Google Safe Browsing flagged   | +40                 |
| Domain age < 30 days           | +20                 |
| Domain age < 180 days          | +10                 |
| No SSL                         | +15                 |
| Expired SSL                    | +10                 |
| Redirect chain > 3 hops        | +10                 |
| Suspicious keywords            | +5 each (max +15)   |
| Lookalike domain               | +25                 |
| Abused VPS provider            | +10                 |
| URL structure red flags        | +5 each (max +20)   |
| Login form + domain mismatch   | +20                 |

### Verdicts

| Score   | Verdict          | Color  |
|---------|------------------|--------|
| 0–25    | Safe             | Green  |
| 26–50   | Suspicious       | Yellow |
| 51–75   | Likely Phishing  | Orange |
| 76–100  | Phishing         | Red    |

## Deployment

### Backend (Railway)

1. Create a new project on [Railway](https://railway.app/)
2. Connect your GitHub repo
3. Set the root directory to `/backend`
4. Add environment variables in the Railway dashboard
5. Railway will auto-detect the Python project. Set the start command:
   ```
   uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```

### Frontend (Vercel)

1. Import the repo on [Vercel](https://vercel.com/)
2. Set the root directory to `/frontend`
3. Set the environment variable:
   ```
   REACT_APP_API_URL=https://your-railway-backend-url.up.railway.app
   ```
4. Deploy — Vercel will auto-detect Create React App

## License

MIT
