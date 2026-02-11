from pydantic_settings import BaseSettings


class Config(BaseSettings):
    """Centralised configuration for the email-validator API.

    Every value can be overridden via environment variables (case-insensitive)
    or a .env file thanks to pydantic-settings.
    """

    # ── SMTP verification ────────────────────────────────────────
    EHLO_HOSTNAME: str = "mail.emailvalidator.local"
    SENDER_EMAIL: str = "verify@emailvalidator.local"
    SMTP_TIMEOUT: int = 10
    SMTP_RETRIES: int = 2
    GREYLIST_DELAY: float = 2.0
    MAX_MX_HOSTS: int = 3  # try the top N MX hosts before giving up
    SMTP_PORTS: list[int] = [25, 587, 465]  # ports to try in order

    # ── Cache ────────────────────────────────────────────────────
    CACHE_TTL: int = 3600  # seconds

    # ── Concurrency & rate limits ────────────────────────────────
    MAX_CONCURRENT_DNS_QUERIES: int = 100
    MAX_CONCURRENT_SMTP_CHECKS: int = 20
    DNS_RATE_LIMIT: int = 100
    SMTP_RATE_LIMIT: int = 20

    # ── Scoring (total = 100 when everything passes) ─────────────
    FORMAT_SCORE: int = 15      # valid RFC format
    DOMAIN_SCORE: int = 15      # MX record found
    DISPOSABLE_SCORE: int = 15  # not disposable (unused penalty)
    SMTP_SCORE: int = 30        # RCPT TO accepted on non-catch-all domain
    CATCHALL_SCORE: int = 10    # RCPT TO accepted but domain is catch-all
    DNSBL_SCORE: int = 15       # primary MX not on any blocklist
    DNSBL_PENALTY: int = 25     # deducted when listed on a DNSBL

    # ── Error messages ───────────────────────────────────────────
    ERROR_INVALID_FORMAT: str = "Invalid email format"
    ERROR_NO_MX_RECORD: str = "No MX record found for domain"
    ERROR_DISPOSABLE_DOMAIN: str = "Disposable email domain"
    ERROR_SMTP_CONNECTION_FAILED: str = "SMTP connection failed"
    ERROR_SMTP_REJECTED: str = "Email rejected by SMTP server"
    ERROR_DNSBL_LISTED: str = "Domain listed in DNSBL"

    # ── Bulk validation ──────────────────────────────────────────
    MAX_BULK_EMAILS: int = 100

    # ── DNSBL servers ────────────────────────────────────────────
    DNSBL_LIST: list[str] = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
    ]

    # ── Free email providers ─────────────────────────────────────
    FREE_EMAIL_PROVIDERS: list[str] = [
        # Google
        "gmail.com", "googlemail.com",
        # Yahoo
        "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es",
        "yahoo.it", "yahoo.jp", "yahoo.ca", "yahoo.com.au", "yahoo.co.in",
        "yahoo.com.br", "yahoo.com.mx", "yahoo.co.jp", "yahoo.co.id",
        "myyahoo.com", "rocketmail.com",
        # Microsoft / Outlook
        "outlook.com", "hotmail.com", "live.com", "msn.com", "passport.com",
        "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it",
        "live.co.uk", "live.fr", "live.de", "live.nl", "outlook.fr",
        "outlook.de", "outlook.es", "outlook.it", "outlook.co.uk",
        # AOL
        "aol.com", "aim.com", "netscape.net", "love.com", "games.com",
        "wow.com", "ygm.com",
        # Zoho
        "zoho.com", "zohomail.com", "zohomail.in", "zohomail.eu",
        # Mail.com
        "mail.com", "email.com", "inbox.com",
        # Mail.ru
        "mail.ru", "inbox.ru", "list.ru", "bk.ru",
        # Proton
        "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
        # Tutanota / Tuta
        "tutanota.com", "tutanota.de", "tutamail.com", "tuta.io", "tuta.com",
        # GMX
        "gmx.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch", "gmx.fr",
        "gmx.es", "gmx.it", "gmx.co.uk",
        # Apple
        "icloud.com", "me.com", "mac.com",
        # Fastmail
        "fastmail.com", "fastmail.fm", "fastmail.jp", "fastmail.co.uk",
        "fastmail.us", "fastmail.cn", "fastmail.im", "fastmail.tw",
        # Yandex
        "yandex.com", "yandex.ru", "yandex.ua", "yandex.kz", "yandex.by",
        "yandex.com.tr", "ya.ru",
        # Others
        "mailfence.com", "hushmail.com", "hush.com", "hush.ai",
        "hushmail.me", "runbox.com", "startmail.com", "posteo.de",
        "posteo.net", "kolabnow.com", "disroot.org",
    ]

    # ── Disposable / throwaway email domains ─────────────────────
    # For production, augment with an external list such as
    # https://github.com/disposable-email-domains/disposable-email-domains
    DISPOSABLE_EMAIL_DOMAINS: list[str] = [
        # Temp-Mail
        "temp-mail.org", "temp-mail.ru", "temp-mail.info", "temp-mail.live",
        # Guerrilla Mail
        "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
        "guerrillamail.biz", "guerrillamailblock.com", "guerrillamail.de",
        "grr.la", "sharklasers.com", "guerrillamail.info",
        # 10 Minute Mail
        "10minutemail.com", "10minutemail.net", "10minutemail.org",
        "10minemail.com", "10minutemail.co.za",
        # Mailinator
        "mailinator.com", "sogetthis.com", "mailin8r.com", "mailinator2.com",
        "reallymymail.com", "tradermail.info", "chammy.info",
        # YOPmail
        "yopmail.com", "yopmail.fr", "yopmail.net", "yopmail.gq",
        "yopmail.info", "yopmail.org",
        # Trashmail
        "trashmail.com", "trashmail.net", "trashmail.org", "trashmail.me",
        "trashmail.io", "trash-mail.com",
        # Others
        "fakemailgenerator.com", "dispostable.com", "mailcatch.com",
        "tempmailaddress.com", "getnada.com", "getairmail.com",
        "mailnesia.com", "spamgourmet.com", "spamgourmet.net",
        "spamgourmet.org", "mohmal.com", "emailondeck.com", "tempmail.io",
        "mail.tm", "tempmailo.com", "throwaway.email", "maildrop.cc",
        "discard.email", "mailsac.com", "harakirimail.com", "33mail.com",
        "mytemp.email", "tempail.com", "burnermail.io", "inboxkitten.com",
        "mailnull.com", "spambox.us", "tempr.email", "dropmail.me",
        "mailhero.io", "crazymailing.com", "tmail.ws", "tmpmail.net",
        "tmpmail.org", "bupmail.com", "moakt.com", "tempinbox.com",
        "disposableemailaddresses.emailmiser.com", "mailtemp.info",
        "guerrillamail.de", "filzmail.com", "anonymbox.com",
        "emltmp.com", "ephemail.net", "jetable.org", "meltmail.com",
        "mintemail.com", "nospamfor.us", "safetymail.info",
        "tempomail.fr", "thankyou2010.com", "trash-mail.at",
        "yopmail.biz", "yopmail.eu", "yopmail.asia",
    ]
