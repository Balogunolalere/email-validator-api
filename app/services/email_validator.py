import asyncio
import aiodns
import aiosmtplib
import random
import string
import logging
from typing import Dict, List, Any, Optional
from email_validator import validate_email, EmailNotValidError
from aiocache import Cache
from aiocache.serializers import JsonSerializer
from .rate_limiter import SlidingWindowRateLimiter
from app.config import Config
from aiosmtplib import SMTPConnectError, SMTPResponseException

logger = logging.getLogger(__name__)


def _random_local_part(length: int = 16) -> str:
    """Generate a random local-part for catch-all probing."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class EmailValidator:
    """Production-grade async email validator.

    Validation pipeline:
        1. RFC format check
        2. Disposable-domain detection
        3. Free-provider detection
        4. MX record lookup (sorted by priority)
        5. Catch-all detection (random RCPT TO probe)
        6. SMTP mailbox verification with STARTTLS + greylisting retry
        7. DNSBL lookup against the primary MX IP
    """

    def __init__(self, config: Config):
        self.config = config
        self.dns_resolver = aiodns.DNSResolver()

        # Concurrency guards
        self.dns_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_DNS_QUERIES)
        self.smtp_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_SMTP_CHECKS)

        # Rate limiters
        self.dns_rate_limiter = SlidingWindowRateLimiter(config.DNS_RATE_LIMIT)
        self.smtp_rate_limiter = SlidingWindowRateLimiter(config.SMTP_RATE_LIMIT)

        # Caches — all async-safe, TTL-based, in-memory
        self.result_cache = Cache(
            Cache.MEMORY,
            serializer=JsonSerializer(),
            namespace="email_results",
            ttl=config.CACHE_TTL,
        )
        self.mx_cache = Cache(
            Cache.MEMORY,
            serializer=JsonSerializer(),
            namespace="mx_records",
            ttl=config.CACHE_TTL,
        )
        self.catchall_cache = Cache(
            Cache.MEMORY,
            serializer=JsonSerializer(),
            namespace="catchall",
            ttl=config.CACHE_TTL,
        )
        self.negative_mx_cache = Cache(
            Cache.MEMORY,
            serializer=JsonSerializer(),
            namespace="negative_mx",
            ttl=config.CACHE_TTL,
        )

        # Pre-compile immutable look-up sets
        self.free_email_providers = frozenset(config.FREE_EMAIL_PROVIDERS)
        self.disposable_email_domains = frozenset(config.DISPOSABLE_EMAIL_DOMAINS)

    # ── Result scaffold ──────────────────────────────────────────

    @staticmethod
    def _create_result(email: str, domain: str = "") -> Dict[str, Any]:
        return {
            "data": {
                "email": email,
                "domain": domain,
                "mx_records": [],
                "provider": "",
                "score": 0,
                "isv_format": False,
                "isv_domain": False,
                "isv_mx": False,
                "isv_noblock": True,
                "isv_nocatchall": True,
                "isv_nogeneric": True,
                "is_disposable": False,
                "is_free": False,
                "is_catchall": False,
                "dnsbl_listed": False,
                "result": "undeliverable",
                "reason": "",
            },
            "error": None,
        }

    # ── DNS helpers ──────────────────────────────────────────────

    async def _dns_query(self, name: str, query_type: str) -> list:
        """Run a rate-limited, concurrency-guarded DNS query."""
        async with self.dns_semaphore:
            await self.dns_rate_limiter.acquire()
            try:
                return await self.dns_resolver.query(name, query_type)
            except aiodns.error.DNSError:
                return []

    async def get_mx_records(self, domain: str) -> List[str]:
        """Return MX hostnames sorted by priority, with async caching."""
        cached = await self.mx_cache.get(domain)
        if cached is not None:
            return cached

        records = await self._dns_query(domain, "MX")
        if not records:
            await self.negative_mx_cache.set(domain, True)
            await self.mx_cache.set(domain, [])
            return []

        sorted_records = sorted(records, key=lambda r: r.priority)
        hosts = [str(r.host).rstrip(".") for r in sorted_records]

        await self.mx_cache.set(domain, hosts)
        return hosts

    async def _resolve_ip(self, hostname: str) -> Optional[str]:
        """Resolve a hostname to its first A-record IP."""
        records = await self._dns_query(hostname, "A")
        if records:
            # aiodns A-record results expose the IP via .host
            return str(records[0].host)
        return None

    # ── SMTP verification ────────────────────────────────────────

    async def _smtp_probe(self, mx_host: str, email: str) -> Dict[str, Any]:
        """Single SMTP RCPT TO probe with STARTTLS support.

        Tries port 25 first (standard MX relay port), then falls back
        to port 587 (submission) which is less commonly blocked by ISPs.
        """
        for port in self.config.SMTP_PORTS:
            result = await self._smtp_probe_port(mx_host, port, email)
            # If we got a definitive SMTP answer or a non-timeout error, return it
            if result["error"] is None or result["error"] != "SMTP timeout":
                return result
            logger.debug("Port %d timed out on %s, trying next port", port, mx_host)
        return result  # all ports timed out — return last result

    async def _smtp_probe_port(
        self, mx_host: str, port: int, email: str
    ) -> Dict[str, Any]:
        """SMTP RCPT TO probe on a specific port."""
        async with self.smtp_semaphore:
            await self.smtp_rate_limiter.acquire()

            use_tls = port == 465
            smtp = aiosmtplib.SMTP(
                hostname=mx_host,
                port=port,
                timeout=self.config.SMTP_TIMEOUT,
                use_tls=use_tls,
            )
            try:
                await asyncio.wait_for(
                    smtp.connect(), timeout=self.config.SMTP_TIMEOUT
                )
                await smtp.ehlo(self.config.EHLO_HOSTNAME)

                # Attempt STARTTLS on plaintext ports
                if not use_tls:
                    try:
                        await smtp.starttls()
                        await smtp.ehlo(self.config.EHLO_HOSTNAME)
                    except (aiosmtplib.SMTPException, ConnectionError, OSError):
                        pass  # Server doesn't support STARTTLS; continue plaintext

                await smtp.mail(self.config.SENDER_EMAIL)
                code, message = await smtp.rcpt(email)

                return {"code": code, "message": str(message), "error": None}

            except asyncio.TimeoutError:
                return {"code": None, "message": "", "error": "SMTP timeout"}
            except SMTPConnectError as exc:
                return {
                    "code": None,
                    "message": "",
                    "error": f"Connection refused: {exc}",
                }
            except SMTPResponseException as exc:
                return {
                    "code": exc.code,
                    "message": str(exc.message),
                    "error": str(exc),
                }
            except Exception as exc:
                return {"code": None, "message": "", "error": str(exc)}
            finally:
                try:
                    await smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:
                        pass

    async def _smtp_verify(
        self, mx_hosts: List[str], email: str
    ) -> Dict[str, Any]:
        """Try MX hosts in priority order; retry on transient 4xx (greylisting)."""
        last_result: Dict[str, Any] = {
            "code": None,
            "message": "",
            "error": "All MX hosts unreachable",
        }

        for mx_host in mx_hosts[: self.config.MAX_MX_HOSTS]:
            for attempt in range(self.config.SMTP_RETRIES):
                result = await self._smtp_probe(mx_host, email)

                # Definitive answer — return immediately
                if result["error"] is None:
                    return result

                # 4xx → transient / greylisting; wait and retry
                if result["code"] and 400 <= result["code"] < 500:
                    logger.info(
                        "Greylisting on %s for %s (attempt %d/%d)",
                        mx_host,
                        email,
                        attempt + 1,
                        self.config.SMTP_RETRIES,
                    )
                    await asyncio.sleep(
                        self.config.GREYLIST_DELAY * (attempt + 1)
                    )
                    continue

                # 5xx or connection error → move to next MX host
                last_result = result
                break
            else:
                # All retries exhausted for this host (greylisting persisted)
                last_result = result
                continue

            # If we got a definitive answer inside the retry loop, return it
            if result.get("error") is None:
                return result

        return last_result

    # ── Catch-all detection ──────────────────────────────────────

    async def _is_catchall(self, domain: str, mx_hosts: List[str]) -> bool:
        """Probe with a random address to detect catch-all / accept-all domains."""
        cached = await self.catchall_cache.get(domain)
        if cached is not None:
            return cached

        probe_email = f"{_random_local_part()}@{domain}"
        result = await self._smtp_verify(mx_hosts, probe_email)

        is_catchall = result.get("code") == 250
        await self.catchall_cache.set(domain, is_catchall)
        return is_catchall

    # ── DNSBL check ──────────────────────────────────────────────

    async def _check_dnsbl(self, mx_hosts: List[str]) -> bool:
        """Check the primary MX server's IP against DNS-based blocklists."""
        if not mx_hosts:
            return False

        ip = await self._resolve_ip(mx_hosts[0])
        if not ip:
            return False

        reversed_ip = ".".join(reversed(ip.split(".")))

        results = await asyncio.gather(
            *[
                self._dns_query(f"{reversed_ip}.{bl}", "A")
                for bl in self.config.DNSBL_LIST
            ]
        )

        return any(bool(r) for r in results)

    # ── Main validation pipeline ─────────────────────────────────

    async def validate_email_address(self, email: str) -> Dict[str, Any]:
        """Full validation pipeline for a single email address."""

        # ── Check result cache ──
        cached = await self.result_cache.get(email)
        if cached:
            return cached

        result = self._create_result(email)

        # ── Step 1: Format validation ──
        try:
            valid = validate_email(email, check_deliverability=False)
            result["data"]["email"] = valid.normalized
            result["data"]["domain"] = valid.domain
            result["data"]["isv_format"] = True
            result["data"]["score"] += self.config.FORMAT_SCORE
        except EmailNotValidError as exc:
            result["error"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"
            result["data"]["reason"] = str(exc)
            await self.result_cache.set(email, result)
            return result

        domain = valid.domain.lower()
        result["data"]["provider"] = domain

        # ── Step 2: Disposable-domain check ──
        result["data"]["is_disposable"] = domain in self.disposable_email_domains
        if result["data"]["is_disposable"]:
            result["data"]["reason"] = (
                f"{self.config.ERROR_DISPOSABLE_DOMAIN}: {domain}"
            )
            result["data"]["result"] = "risky"
            await self.result_cache.set(email, result)
            return result

        # ── Step 3: Free-provider flag ──
        result["data"]["is_free"] = domain in self.free_email_providers

        # ── Step 4: MX record lookup ──
        if await self.negative_mx_cache.get(domain):
            result["data"]["reason"] = (
                f"{self.config.ERROR_NO_MX_RECORD}: {domain}"
            )
            await self.result_cache.set(email, result)
            return result

        mx_hosts = await self.get_mx_records(domain)
        if not mx_hosts:
            result["data"]["reason"] = (
                f"{self.config.ERROR_NO_MX_RECORD}: {domain}"
            )
            await self.result_cache.set(email, result)
            return result

        result["data"]["mx_records"] = mx_hosts
        result["data"]["isv_domain"] = True
        result["data"]["isv_mx"] = True
        result["data"]["score"] += self.config.DOMAIN_SCORE

        # ── Step 5: Catch-all detection ──
        is_catchall = await self._is_catchall(domain, mx_hosts)
        result["data"]["is_catchall"] = is_catchall
        if is_catchall:
            result["data"]["isv_nocatchall"] = False

        # ── Step 6: SMTP mailbox verification ──
        smtp_result = await self._smtp_verify(mx_hosts, valid.normalized)

        if smtp_result["code"] == 250:
            if is_catchall:
                # Server accepts every address — mailbox existence is uncertain
                result["data"]["score"] += self.config.CATCHALL_SCORE
                result["data"]["result"] = "risky"
                result["data"]["reason"] = (
                    f"Domain {domain} is catch-all (accepts all addresses). "
                    "Individual mailbox existence cannot be confirmed."
                )
            else:
                result["data"]["score"] += self.config.SMTP_SCORE
                result["data"]["result"] = "deliverable"
                result["data"]["reason"] = "Accepted — mailbox exists"

        elif smtp_result["code"] and smtp_result["code"] >= 500:
            result["data"]["result"] = "undeliverable"
            result["data"]["reason"] = (
                f"{self.config.ERROR_SMTP_REJECTED} "
                f"(code {smtp_result['code']}): {smtp_result['message']}"
            )

        elif smtp_result["error"]:
            result["data"]["result"] = "unknown"
            result["data"]["reason"] = (
                f"{self.config.ERROR_SMTP_CONNECTION_FAILED}: "
                f"{smtp_result['error']}"
            )

        else:
            result["data"]["result"] = "unknown"
            result["data"]["reason"] = (
                f"Unexpected SMTP response "
                f"(code {smtp_result['code']}): {smtp_result['message']}"
            )

        # ── Step 7: DNSBL blocklist check ──
        is_listed = await self._check_dnsbl(mx_hosts)
        result["data"]["dnsbl_listed"] = is_listed
        if is_listed:
            result["data"]["score"] -= self.config.DNSBL_PENALTY
            result["data"]["isv_noblock"] = False
            result["data"]["reason"] += f" | {self.config.ERROR_DNSBL_LISTED}"
        else:
            result["data"]["score"] += self.config.DNSBL_SCORE

        # ── Step 8: Clamp score ──
        result["data"]["score"] = max(0, min(100, result["data"]["score"]))

        await self.result_cache.set(email, result)
        return result

    async def validate_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        """Validate a batch of emails concurrently."""
        tasks = [self.validate_email_address(email) for email in emails]
        return list(await asyncio.gather(*tasks))
