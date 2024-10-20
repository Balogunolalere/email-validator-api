import asyncio
import aiodns
import aiosmtplib
from typing import Dict, List, Any
from email_validator import validate_email, EmailNotValidError
from functools import lru_cache
from aiocache import Cache
from aiocache.serializers import JsonSerializer
from .rate_limiter import SlidingWindowRateLimiter
from ..config import Config
from aiosmtplib import SMTPConnectError, SMTPResponseException

class SMTPConnectionPool:
    def __init__(self, max_connections: int = 50):
        self.max_connections = max_connections
        self.connections = {}
        self.semaphore = asyncio.Semaphore(max_connections)

    async def get_connection(self, hostname: str) -> aiosmtplib.SMTP:
        async with self.semaphore:
            if hostname not in self.connections:
                self.connections[hostname] = aiosmtplib.SMTP(hostname=hostname, timeout=60)
                await self.connections[hostname].connect()
                await self.connections[hostname].ehlo()
            return self.connections[hostname]

    async def release_connection(self, hostname: str):
        if hostname in self.connections:
            try:
                await self.connections[hostname].quit()
            except Exception:
                pass
            del self.connections[hostname]

    async def close_all(self):
        for hostname in list(self.connections.keys()):
            await self.release_connection(hostname)

class EmailValidator:
    def __init__(self, config: Config):
        self.config = config
        self.dns_resolver = aiodns.DNSResolver()
        self.dns_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_DNS_QUERIES)
        self.smtp_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_SMTP_CHECKS)
        self.dns_rate_limiter = SlidingWindowRateLimiter(config.DNS_RATE_LIMIT)
        self.smtp_rate_limiter = SlidingWindowRateLimiter(config.SMTP_RATE_LIMIT)
        self.cache = Cache(Cache.MEMORY, serializer=JsonSerializer(), namespace="email_validator", ttl=3600)
        self.smtp_pool = SMTPConnectionPool(max_connections=config.MAX_CONCURRENT_SMTP_CHECKS)
        self.negative_cache = Cache(Cache.MEMORY, serializer=JsonSerializer(), namespace="negative_cache", ttl=3600)

    def create_result_dict(self, email: str, domain: str = "") -> Dict[str, Any]:
        return {
            "data": {
                "email": email,
                "domain": domain,
                "mx_record": "",
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
                "dnsbl_listed": False,
                "result": "undeliverable",
                "reason": ""
            },
            "error": None
        }

    @lru_cache(maxsize=10000)
    async def get_mx_record(self, domain: str) -> str:
        return await self._perform_dns_query(domain, 'MX')

    async def _perform_dns_query(self, domain: str, query_type: str) -> str:
        async with self.dns_semaphore:
            await self.dns_rate_limiter.acquire()
            try:
                records = await self.dns_resolver.query(domain, query_type)
                return str(records[0].host) if records else ""
            except aiodns.error.DNSError:
                return ""

    async def check_smtp(self, mx_record: str, email: str) -> Dict[str, Any]:
        async with self.smtp_semaphore:
            await self.smtp_rate_limiter.acquire()
            try:
                smtp = await asyncio.wait_for(self.smtp_pool.get_connection(mx_record), timeout=30)
                await asyncio.wait_for(smtp.mail(''), timeout=30)
                code, _ = await asyncio.wait_for(smtp.rcpt(str(email)), timeout=30)
                return {"code": code, "error": None}
            except asyncio.TimeoutError:
                return {"code": None, "error": "SMTP timeout"}
            except SMTPConnectError:
                return {"code": None, "error": "SMTP connection error"}
            except SMTPResponseException as e:
                return {"code": e.code, "error": str(e)}
            except Exception as e:
                return {"code": None, "error": str(e)}
            finally:
                await self.smtp_pool.release_connection(mx_record)

    async def validate_email_format(self, email: str) -> Dict[str, Any]:
        result = self.create_result_dict(email)
        try:
            valid = validate_email(email)
            result["data"]["email"] = valid.email
            result["data"]["domain"] = valid.domain
            result["data"]["isv_format"] = True
            result["data"]["score"] += self.config.FORMAT_SCORE
            return result
        except EmailNotValidError as e:
            result["error"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"
            result["data"]["reason"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"
            return result

    async def validate_email_domain(self, result: Dict[str, Any]) -> Dict[str, Any]:
        domain = result["data"]["domain"]

        if await self.negative_cache.get(domain):
            result["data"]["reason"] = f"{self.config.ERROR_NO_MX_RECORD}: {domain}"
            return result

        mx_record = await self.get_mx_record(domain)
        if mx_record:
            result["data"]["mx_record"] = mx_record
            result["data"]["isv_domain"] = True
            result["data"]["isv_mx"] = True
            result["data"]["score"] += self.config.DOMAIN_SCORE
        else:
            await self.negative_cache.set(domain, True)
            result["data"]["reason"] = f"{self.config.ERROR_NO_MX_RECORD}: {domain}"
            return result

        result["data"]["is_free"] = domain.lower() in self.config.FREE_EMAIL_PROVIDERS
        result["data"]["is_disposable"] = domain.lower() in self.config.DISPOSABLE_EMAIL_DOMAINS
        if not result["data"]["is_disposable"]:
            result["data"]["score"] += self.config.DISPOSABLE_SCORE
        else:
            result["data"]["reason"] = f"{self.config.ERROR_DISPOSABLE_DOMAIN}: {domain}"

        return result

    async def validate_email_smtp(self, result: Dict[str, Any]) -> Dict[str, Any]:
        email = result["data"]["email"]
        mx_record = result["data"]["mx_record"]

        smtp_result = await self.check_smtp(mx_record, email)
        if smtp_result["code"] == 250:
            result["data"]["score"] += self.config.SMTP_SCORE
            result["data"]["result"] = "deliverable"
            result["data"]["reason"] = "accepted email"
        elif smtp_result["error"]:
            result["data"]["result"] = "undeliverable"
            result["data"]["reason"] = f"{self.config.ERROR_SMTP_CONNECTION_FAILED}: {smtp_result['error']} (Email: {email})"
        else:
            result["data"]["result"] = "undeliverable"
            result["data"]["reason"] = f"{self.config.ERROR_SMTP_REJECTED}: {smtp_result['code']} (Email: {email})"

        result["data"]["provider"] = result["data"]["domain"]

        return result

    async def check_dnsbl(self, domain: str) -> bool:
        ip = await self._perform_dns_query(domain, 'A')
        if not ip:
            return False

        reversed_ip = '.'.join(reversed(ip.split('.')))

        dnsbl_results = await asyncio.gather(*[
            self._perform_dns_query(f"{reversed_ip}.{dnsbl}", 'A')
            for dnsbl in self.config.DNSBL_LIST
        ])

        return any(dnsbl_results)

    async def validate_email_address(self, email: str) -> Dict[str, Any]:
        cached_result = await self.cache.get(email)
        if cached_result:
            return cached_result

        result = await self.validate_email_format(email)
        if result["data"]["isv_format"]:
            result = await self.validate_email_domain(result)
            if result["data"]["isv_domain"]:
                result = await self.validate_email_smtp(result)

                # Check DNSBL
                is_listed = await self.check_dnsbl(result["data"]["domain"])
                result["data"]["dnsbl_listed"] = is_listed
                if is_listed:
                    result["data"]["score"] -= self.config.DNSBL_SCORE
                    result["data"]["reason"] += f" {self.config.ERROR_DNSBL_LISTED}"
                else:
                    result["data"]["score"] += self.config.DNSBL_SCORE

        # Update final score-based fields
        if result["data"]["score"] >= 90:
            result["data"]["isv_noblock"] = True
            result["data"]["isv_nocatchall"] = True
            result["data"]["isv_nogeneric"] = True

        await self.cache.set(email, result)
        return result

    async def validate_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        tasks = [self.validate_email_address(email) for email in emails]
        results = await asyncio.gather(*tasks)
        await self.smtp_pool.close_all()
        return results