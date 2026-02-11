import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

from app.config import Config
from app.services import email_validator
from app.services.rate_limiter import SlidingWindowRateLimiter

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

# ── Shared instances ─────────────────────────────────────────────
config = Config()
rate_limiter_instance = SlidingWindowRateLimiter(rate_limit=config.SMTP_RATE_LIMIT)
validator_instance = email_validator.EmailValidator(config)


# ── Request / response models ───────────────────────────────────
class SingleEmailRequest(BaseModel):
    email: EmailStr


class BulkEmailRequest(BaseModel):
    emails: List[EmailStr]


# ── App lifecycle ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Email Validator API starting up")
    yield
    logger.info("Email Validator API shutting down")


# ── FastAPI application ─────────────────────────────────────────
app = FastAPI(
    title="Email Validator API",
    description="Production-grade email validation service with SMTP verification, "
                "catch-all detection, DNSBL checks and more.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Liveness / readiness probe."""
    return {"status": "ok"}


@app.post("/validate")
async def validate_email_endpoint(body: SingleEmailRequest):
    """Validate a single email address.

    Returns format check, MX lookup, SMTP verification,
    catch-all detection, DNSBL status and a deliverability score.
    """
    try:
        await rate_limiter_instance.acquire()
        result = await validator_instance.validate_email_address(body.email)
        return result
    except Exception as exc:
        logger.exception("Validation failed for %s", body.email)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/validate/bulk")
async def validate_emails_endpoint(body: BulkEmailRequest):
    """Validate a list of email addresses concurrently.

    Maximum of ``MAX_BULK_EMAILS`` (default 100) per request.
    """
    if not body.emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    if len(body.emails) > config.MAX_BULK_EMAILS:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {config.MAX_BULK_EMAILS} emails per request",
        )
    try:
        await rate_limiter_instance.acquire()
        results = await validator_instance.validate_emails(body.emails)
        return results
    except Exception as exc:
        logger.exception("Bulk validation failed")
        raise HTTPException(status_code=500, detail=str(exc))
