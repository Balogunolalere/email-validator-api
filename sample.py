import re
import asyncio
import aiodns
import aiosmtplib
import json
from email_validator import validate_email, EmailNotValidError
from typing import Dict, Set, Any, List
from functools import lru_cache
import logging
import nest_asyncio
from collections import defaultdict, deque
from time import time
from aiocache import Cache
from aiocache.serializers import JsonSerializer
from idna import encode as idna_encode

nest_asyncio.apply()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Use sets for O(1) lookup time
FREE_EMAIL_PROVIDERS: Set[str] = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
    'yahoo.es', 'yahoo.it', 'yahoo.jp', 'yahoo.ca', 'yahoo.com.au', 'yahoo.co.in',
    'yahoo.com.br', 'yahoo.com.mx', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'passport.com', 'aol.com', 'aim.com', 'netscape.net', 'love.com', 'games.com',
    'wow.com', 'ygm.com', 'zoho.com', 'zohomail.com', 'mail.com', 'email.com', 'inbox.com',
    'mail.ru', 'protonmail.com', 'protonmail.ch', 'tutanota.com', 'tutanota.de',
    'tutamail.com', 'tuta.io', 'gmx.com', 'gmx.net', 'gmx.de', 'gmx.at', 'gmx.ch',
    'gmx.fr', 'gmx.es', 'gmx.it', 'gmx.co.uk', 'icloud.com', 'me.com', 'mac.com',
    'fastmail.com', 'fastmail.fm', 'fastmail.jp', 'fastmail.co.uk', 'fastmail.us',
    'fastmail.cn', 'fastmail.im', 'fastmail.tw', 'yandex.com', 'yandex.ru', 'yandex.ua',
    'yandex.kz', 'yandex.by', 'yandex.com.tr', 'mailfence.com', 'hushmail.com',
    'hush.com', 'hush.ai', 'hushmail.me', 'lavabit.com', 'runbox.com', 'startmail.com',
    'posteo.de', 'posteo.net', 'kolabnow.com'
}

DISPOSABLE_EMAIL_DOMAINS: Set[str] = {
    'temp-mail.org', 'temp-mail.ru', 'temp-mail.info', 'temp-mail.live',
    'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz',
    'guerrillamailblock.com', 'guerrillamail.de', '10minutemail.com', '10minutemail.net',
    '10minutemail.org', 'mailinator.com', 'sogetthis.com', 'mailin8r.com', 'mailinator2.com',
    'yopmail.com', 'yopmail.fr', 'yopmail.net', 'yopmail.gq', 'yopmail.info', 'yopmail.org',
    'yopmail.biz', 'yopmail.eu', 'yopmail.asia', 'yopmail.co.uk', 'yopmail.de', 'yopmail.es',
    'yopmail.it', 'yopmail.jp', 'yopmail.pl', 'yopmail.ru', 'yopmail.us', 'yopmail.ws',
    'trashmail.com', 'trashmail.net', 'trashmail.org', 'trashmail.me', 'trashmail.io',
    'fakemailgenerator.com', 'dispostable.com', 'mailcatch.com', 'tempmailaddress.com',
    'getnada.com', 'getairmail.com', 'getairmail.cf', 'getairmail.ga', 'getairmail.gq',
    'getairmail.ml', 'getairmail.tk', 'mailnesia.com', 'spamgourmet.com', 'spamgourmet.net',
    'spamgourmet.org', 'mohmal.com', 'mohmal.de', 'mohmal.ch', 'mohmal.at', 'mohmal.co.uk',
    'emailondeck.com', 'tempmail.io', 'mailinator2.com', 'mail.tm', 'tempmailo.com'
}

# Constants for scoring and error messages
FORMAT_SCORE = 15
DOMAIN_SCORE = 15
DISPOSABLE_SCORE = 15
SMTP_SCORE = 30
DNSBL_SCORE = 25

ERROR_INVALID_FORMAT = "Invalid email format"
ERROR_NO_MX_RECORD = "No MX record found for domain"
ERROR_DISPOSABLE_DOMAIN = "Disposable email domain"
ERROR_SMTP_CONNECTION_FAILED = "SMTP connection failed"
ERROR_SMTP_REJECTED = "Email rejected by SMTP server"
ERROR_DNSBL_LISTED = "Domain listed in DNSBL"

# Rate limiting constants
MAX_CONCURRENT_DNS_QUERIES = 100
MAX_CONCURRENT_SMTP_CHECKS = 50
DNS_RATE_LIMIT = 100  # queries per second
SMTP_RATE_LIMIT = 50  # checks per second

# DNSBL list
DNSBL_LIST = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
]

class Config:
    FREE_EMAIL_PROVIDERS = FREE_EMAIL_PROVIDERS
    DISPOSABLE_EMAIL_DOMAINS = DISPOSABLE_EMAIL_DOMAINS
    FORMAT_SCORE = FORMAT_SCORE
    DOMAIN_SCORE = DOMAIN_SCORE
    DISPOSABLE_SCORE = DISPOSABLE_SCORE
    SMTP_SCORE = SMTP_SCORE
    DNSBL_SCORE = DNSBL_SCORE
    ERROR_INVALID_FORMAT = ERROR_INVALID_FORMAT
    ERROR_NO_MX_RECORD = ERROR_NO_MX_RECORD
    ERROR_DISPOSABLE_DOMAIN = ERROR_DISPOSABLE_DOMAIN
    ERROR_SMTP_CONNECTION_FAILED = ERROR_SMTP_CONNECTION_FAILED
    ERROR_SMTP_REJECTED = ERROR_SMTP_REJECTED
    ERROR_DNSBL_LISTED = ERROR_DNSBL_LISTED
    MAX_CONCURRENT_DNS_QUERIES = MAX_CONCURRENT_DNS_QUERIES
    MAX_CONCURRENT_SMTP_CHECKS = MAX_CONCURRENT_SMTP_CHECKS
    DNS_RATE_LIMIT = DNS_RATE_LIMIT
    SMTP_RATE_LIMIT = SMTP_RATE_LIMIT
    DNSBL_LIST = DNSBL_LIST

class SlidingWindowRateLimiter:
    def __init__(self, rate_limit: int, window_size: int = 1):
        self.rate_limit = rate_limit
        self.window_size = window_size
        self.timestamps = deque()

    async def acquire(self):
        current_time = time()
        while self.timestamps and self.timestamps[0] <= current_time - self.window_size:
            self.timestamps.popleft()

        if len(self.timestamps) < self.rate_limit:
            self.timestamps.append(current_time)
            return
        else:
            await asyncio.sleep(0.01)
            await self.acquire()

class SMTPConnectionPool:
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self.connections = {}
        self.semaphore = asyncio.Semaphore(max_connections)

    async def get_connection(self, hostname: str) -> aiosmtplib.SMTP:
        async with self.semaphore:
            if hostname not in self.connections:
                self.connections[hostname] = aiosmtplib.SMTP(hostname=hostname, timeout=10)
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
        self.cache = Cache(Cache.MEMORY, serializer=JsonSerializer(), namespace="email_validator")
        self.smtp_pool = SMTPConnectionPool()
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

    @lru_cache(maxsize=1000)
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
                smtp = await self.smtp_pool.get_connection(mx_record)
                await smtp.mail('')
                code, _ = await smtp.rcpt(str(email))
                return {"code": code, "error": None}
            except aiosmtplib.SMTPTimeoutError:
                return {"code": None, "error": "SMTP timeout"}
            except aiosmtplib.SMTPConnectError:
                return {"code": None, "error": "SMTP connection error"}
            except aiosmtplib.SMTPResponseException as e:
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
        email = result["data"]["email"]
        domain = result["data"]["domain"]

        if await self.negative_cache.exists(domain):
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
            result["data"]["reason"] = f"{self.config.ERROR_SMTP_CONNECTION_FAILED}: {smtp_result['error']} (Email: {email})"
        else:
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

        logger.info(f"Validation result for {email}: {result['data']['result']} (Score: {result['data']['score']})")

        await self.cache.set(email, result)
        return result

    async def validate_emails(self, emails: List[str]) -> List[Dict[str, Any]]:
        tasks = [self.validate_email_address(email) for email in emails]
        results = await asyncio.gather(*tasks)
        await self.smtp_pool.close_all()
        return results

async def main():
    while True:
        email = input("Enter an email address to validate (or 'q' to quit): ")
        if email.lower() == 'q':
            break

        config = Config()
        validator = EmailValidator(config)
        result = await validator.validate_email_address(email)
        print(json.dumps(result, indent=2))
        await validator.smtp_pool.close_all()

if __name__ == "__main__":
    asyncio.run(main())