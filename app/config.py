from pydantic_settings import BaseSettings

class Config(BaseSettings):
    FREE_EMAIL_PROVIDERS: list[str] = [
        'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
        'yahoo.es', 'yahoo.it', 'yahoo.jp', 'yahoo.ca', 'yahoo.com.au', 'yahoo.co.in',
        'yahoo.com.br', 'yahoo.com.mx', 'outlook.com', 'hotmail.com', 'live.com','msn.com',
        'passport.com', 'aol.com', 'aim.com', 'netscape.net', 'love.com', 'games.com',
        'wow.com', 'ygm.com', 'zoho.com', 'zohomail.com','mail.com', 'email.com', 'inbox.com',
       'mail.ru', 'protonmail.com', 'protonmail.ch', 'tutanota.com', 'tutanota.de',
        'tutamail.com', 'tuta.io', 'gmx.com', 'gmx.net', 'gmx.de', 'gmx.at', 'gmx.ch',
        'gmx.fr', 'gmx.es', 'gmx.it', 'gmx.co.uk', 'icloud.com','me.com','mac.com',
        'fastmail.com', 'fastmail.fm', 'fastmail.jp', 'fastmail.co.uk', 'fastmail.us',
        'fastmail.cn', 'fastmail.im', 'fastmail.tw', 'yandex.com', 'yandex.ru', 'yandex.ua',
        'yandex.kz', 'yandex.by', 'yandex.com.tr','mailfence.com', 'hushmail.com',
        'hush.com', 'hush.ai', 'hushmail.me', 'lavabit.com', 'runbox.com','startmail.com',
        'posteo.de', 'posteo.net', 'kolabnow.com'
    ]

    DISPOSABLE_EMAIL_DOMAINS: list[str] = [
        'temp-mail.org', 'temp-mail.ru', 'temp-mail.info', 'temp-mail.live',
        'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz',
        'guerrillamailblock.com', 'guerrillamail.de', '10minutemail.com', '10minutemail.net',
        '10minutemail.org','mailinator.com','sogetthis.com','mailin8r.com','mailinator2.com',
        'yopmail.com', 'yopmail.fr', 'yopmail.net', 'yopmail.gq', 'yopmail.info', 'yopmail.org',
        'yopmail.biz', 'yopmail.eu', 'yopmail.asia', 'yopmail.co.uk', 'yopmail.de', 'yopmail.es',
        'yopmail.it', 'yopmail.jp', 'yopmail.pl', 'yopmail.ru', 'yopmail.us', 'yopmail.ws',
        'trashmail.com', 'trashmail.net', 'trashmail.org', 'trashmail.me', 'trashmail.io',
        'fakemailgenerator.com', 'dispostable.com','mailcatch.com', 'tempmailaddress.com',
        'getnada.com', 'getairmail.com', 'getairmail.cf', 'getairmail.ga', 'getairmail.gq',
        'getairmail.ml', 'getairmail.tk','mailnesia.com','spamgourmet.com','spamgourmet.net',
       'spamgourmet.org','mohmal.com','mohmal.de','mohmal.ch','mohmal.at','mohmal.co.uk',
        'emailondeck.com', 'tempmail.io','mailinator2.com','mail.tm', 'tempmailo.com'
    ]

    FORMAT_SCORE: int = 15
    DOMAIN_SCORE: int = 15
    DISPOSABLE_SCORE: int = 15
    SMTP_SCORE: int = 30
    DNSBL_SCORE: int = 25

    ERROR_INVALID_FORMAT: str = "Invalid email format"
    ERROR_NO_MX_RECORD: str = "No MX record found for domain"
    ERROR_DISPOSABLE_DOMAIN: str = "Disposable email domain"
    ERROR_SMTP_CONNECTION_FAILED: str = "SMTP connection failed"
    ERROR_SMTP_REJECTED: str = "Email rejected by SMTP server"
    ERROR_DNSBL_LISTED: str = "Domain listed in DNSBL"

    MAX_CONCURRENT_DNS_QUERIES: int = 100
    MAX_CONCURRENT_SMTP_CHECKS: int = 50
    DNS_RATE_LIMIT: int = 100
    SMTP_RATE_LIMIT: int = 50

    DNSBL_LIST: list[str] = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'dnsbl.sorbs.net',
    ]
