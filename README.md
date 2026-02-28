# 🔒 AI-Powered Static Application Security Testing (SAST)

An AI-powered SAST tool that combines AST-based vulnerability detection with OpenAI GPT-4
for intelligent explanation, fix suggestions, and professional security reporting.

## Features

- **8 Vulnerability Detectors**: SQL Injection, XSS, Command Injection, Hardcoded Secrets,
  Weak Crypto, Insecure Deserialization, Unsafe Eval, Path Traversal
- **AI-Powered Analysis**: GPT-4 explanations and code fix generation
- **CVSS Scoring**: Professional severity scoring with project risk aggregation
- **PDF Reports**: Executive summaries with charts and remediation steps
- **Dashboard**: Real-time analytics with trend visualization
- **GitHub Integration**: OAuth, repo scanning, PR comments
- **Taint Analysis**: Data flow tracking from sources to sinks
- **CI/CD Integration**: GitHub Actions for automated PR scanning

## Quick Start

### Prerequisites
- Docker & Docker Compose
- OpenAI API key

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-username/major_project-2.git
cd major_project-2
```

2. Configure environment:
```bash
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

3. Start all services:
```bash
docker-compose up -d
```

4. Run database migrations:
```bash
docker-compose exec backend alembic upgrade head
```

5. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, SQLAlchemy, Celery |
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Database | PostgreSQL |
| Queue | Redis + Celery |
| AI | OpenAI GPT-4 |
| DevOps | Docker, GitHub Actions |

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v --cov=app
```

## Project Structure
├── backend/          # FastAPI application
│   ├── app/
│   │   ├── api/      # REST endpoints
│   │   ├── core/     # Scanning engine & detectors
│   │   ├── ai/       # OpenAI integration
│   │   ├── models/   # Database models
│   │   ├── services/ # Business logic
│   │   └── reporting/# PDF generation
│   └── tests/
├── frontend/         # Next.js application
│   └── src/
│       ├── app/      # Pages
│       ├── components/
│       └── lib/      # API client & utilities
└── docker-compose.yml

## License

MIT — Built as a final-year engineering project.

## Contributing