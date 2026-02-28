from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.api.v1 import auth, projects, scans, vulnerabilities, reports, github, analytics
from app.api.v1 import sandbox


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.report_path
    settings.scan_path
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Static Application Security Testing Tool",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_V1_PREFIX, tags=["Authentication"])
app.include_router(projects.router, prefix=settings.API_V1_PREFIX, tags=["Projects"])
app.include_router(scans.router, prefix=settings.API_V1_PREFIX, tags=["Scans"])
app.include_router(vulnerabilities.router, prefix=settings.API_V1_PREFIX, tags=["Vulnerabilities"])
app.include_router(reports.router, prefix=settings.API_V1_PREFIX, tags=["Reports"])
app.include_router(github.router, prefix=settings.API_V1_PREFIX, tags=["GitHub"])
app.include_router(analytics.router, prefix=settings.API_V1_PREFIX, tags=["Analytics"])
app.include_router(sandbox.router, prefix=settings.API_V1_PREFIX, tags=["Sandbox"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "app": settings.APP_NAME}
