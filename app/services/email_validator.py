import asyncio
import aiodns
import aiosmtplib
from typing import Dict, List, Any
from email_validator import validate_email, EmailNotValidError
from functools import lru_cache
from aiocache import Cache
from aiocache.serializers import JsonSerializer
from config import Config
from aiosmtplib import SMTPConnectError, SMTPResponseException
import re
import asyncio_pool

class SMTPConnectionPool:
    def __init__(self, max_connections: int = 50):
        self.max_connections = max_connections
        self.connections = {}
        self.semaphore = asyncio.Semaphore(max_connections)

    async def get_connection(self, hostname: str) -> aiosmtplib.SMTP:
        async with self.semaphore:
            if hostname not in self.connections:
                self.connections[hostname] = aiosmtplib.SMTP(hostname=hostname, timeout=5)
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
        self.dns_cache = Cache(Cache.MEMORY, ttl=86400)  # 24-hour TTL
        self.smtp_cache = Cache(Cache.MEMORY, ttl=3600)
        self.dnsbl_cache = Cache(Cache.MEMORY, ttl=86400)  # 24-hour TTL
        self.result_cache = Cache(Cache.MEMORY, serializer=JsonSerializer(), namespace="email_validator", ttl=3600)
        self.negative_cache = Cache(Cache.MEMORY, serializer=JsonSerializer(), namespace="negative_cache", ttl=86400)  # 24-hour TTL
        self.smtp_pool = SMTPConnectionPool(max_connections=config.MAX_CONCURRENT_SMTP_CHECKS)
        
        self.free_email_providers = set(config.FREE_EMAIL_PROVIDERS)
        self.disposable_email_domains = set(config.DISPOSABLE_EMAIL_DOMAINS)
        
        self.email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

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
        cached_result = await self.dns_cache.get(domain)
        if cached_result is not None:
            return cached_result

        try:
            records = await asyncio.wait_for(self.dns_resolver.query(domain, 'MX'), timeout=2)
            result = str(records[0].host) if records else ""
            await self.dns_cache.set(domain, result)
            return result
        except (aiodns.error.DNSError, asyncio.TimeoutError):
            await self.dns_cache.set(domain, "")
            return ""

    async def check_smtp(self, mx_record: str, email: str) -> Dict[str, Any]:
        cache_key = f"{mx_record}:{email}"
        cached_result = await self.smtp_cache.get(cache_key)
        if cached_result is not None:
            return cached_result

        try:
            smtp = await asyncio.wait_for(self.smtp_pool.get_connection(mx_record), timeout=5)
            await asyncio.wait_for(smtp.mail(''), timeout=5)
            code, _ = await asyncio.wait_for(smtp.rcpt(str(email)), timeout=5)
            result = {"code": code, "error": None}
        except asyncio.TimeoutError:
            result = {"code": None, "error": "SMTP timeout"}
        except SMTPConnectError:
            result = {"code": None, "error": "SMTP connection error"}
        except SMTPResponseException as e:
            result = {"code": e.code, "error": str(e)}
        except Exception as e:
            result = {"code": None, "error": str(e)}
        finally:
            await self.smtp_pool.release_connection(mx_record)

        await self.smtp_cache.set(cache_key, result)
        return result

    async def check_dnsbl(self, domain: str) -> bool:
        cached_result = await self.dnsbl_cache.get(domain)
        if cached_result is not None:
            return cached_result

        ip = await self._perform_dns_query(domain, 'A')
        if not ip:
            await self.dnsbl_cache.set(domain, False)
            return False

        reversed_ip = '.'.join(reversed(ip.split('.')))

        async def check_single_dnsbl(dnsbl):
            return await self._perform_dns_query(f"{reversed_ip}.{dnsbl}", 'A') != ""

        async with asyncio_pool.AioPool(size=10) as pool:
            dnsbl_results = await asyncio.wait_for(pool.map(check_single_dnsbl, self.config.DNSBL_LIST), timeout=2)

        result = any(dnsbl_results)
        await self.dnsbl_cache.set(domain, result)
        return result

    async def _perform_dns_query(self, domain: str, query_type: str) -> str:
        try:
            records = await asyncio.wait_for(self.dns_resolver.query(domain, query_type), timeout=1)
            return str(records[0].host) if records else ""
        except (aiodns.error.DNSError, asyncio.TimeoutError):
            return ""

    async def validate_email_address(self, email: str) -> Dict[str, Any]:
        cached_result = await self.result_cache.get(email)
        if cached_result:
            return cached_result

        result = self.create_result_dict(email)

        # Quick format check
        if not self.email_regex.match(email):
            result["error"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"
            result["data"]["reason"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"
            await self.result_cache.set(email, result)
            return result

        try:
            valid = validate_email(email)
            result["data"]["email"] = valid.email
            result["data"]["domain"] = valid.domain
            result["data"]["isv_format"] = True
            result["data"]["score"] += self.config.FORMAT_SCORE

            domain = valid.domain.lower()
            
            if await self.negative_cache.get(domain):
                result["data"]["reason"] = f"{self.config.ERROR_NO_MX_RECORD}: {domain}"
                await self.result_cache.set(email, result)
                return result

            result["data"]["is_free"] = domain in self.free_email_providers
            result["data"]["is_disposable"] = domain in self.disposable_email_domains

            if result["data"]["is_disposable"]:
                result["data"]["reason"] = f"{self.config.ERROR_DISPOSABLE_DOMAIN}: {domain}"
                await self.result_cache.set(email, result)
                return result

            mx_record = await self.get_mx_record(domain)
            if mx_record:
                result["data"]["mx_record"] = mx_record
                result["data"]["isv_domain"] = True
                result["data"]["isv_mx"] = True
                result["data"]["score"] += self.config.DOMAIN_SCORE
                result["data"]["score"] += self.config.DISPOSABLE_SCORE

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

                is_listed = await self.check_dnsbl(domain)
                result["data"]["dnsbl_listed"] = is_listed
                if is_listed:
                    result["data"]["score"] -= self.config.DNSBL_SCORE
                    result["data"]["reason"] += f" {self.config.ERROR_DNSBL_LISTED}"
                else:
                    result["data"]["score"] += self.config.DNSBL_SCORE
            else:
                await self.negative_cache.set(domain, True)
                result["data"]["reason"] = f"{self.config.ERROR_NO_MX_RECORD}: {domain}"

        except EmailNotValidError as e:
            result["error"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"
            result["data"]["reason"] = f"{self.config.ERROR_INVALID_FORMAT}: {email}"

        result["data"]["provider"] = result["data"]["domain"]

        if result["data"]["score"] >= 90:
            result["data"]["isv_noblock"] = True
            result["data"]["isv_nocatchall"] = True
            result["data"]["isv_nogeneric"] = True

        await self.result_cache.set(email, result)
        return result

    async def validate_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        async with asyncio_pool.AioPool(size=50) as pool:
            results = await pool.map(self.validate_email_address, emails)
        await self.smtp_pool.close_all()
        return results