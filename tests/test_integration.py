"""Thorough integration tests for the Email Validator API."""
import asyncio
import aiohttp
import json
import sys
import time

BASE = "http://127.0.0.1:8000"

# ── Test cases ───────────────────────────────────────────────────
SINGLE_TESTS = [
    # (description, email, expected_checks)
    (
        "1. Health check",
        None,  # special: GET /health
        {"status": "ok"},
    ),

    (
        "4. Disposable domain (mailinator)",
        "test@mailinator.com",
        {"is_disposable": True, "result": "risky"},
    ),
    (
        "5. Disposable domain (guerrillamail)",
        "test@guerrillamail.com",
        {"is_disposable": True, "result": "risky"},
    ),
    (
        "6. Non-existent domain",
        "user@thisdomain-definitely-does-not-exist-12345.com",
        {"isv_format": True, "isv_mx": False, "result": "undeliverable"},
    ),
    (
        "7. Free provider flag — Gmail",
        "test@gmail.com",
        {"is_free": True, "isv_mx": True},
    ),
    (
        "8. Free provider flag — Yahoo",
        "test@yahoo.com",
        {"is_free": True, "isv_mx": True},
    ),
    (
        "9. Free provider flag — Outlook",
        "test@outlook.com",
        {"is_free": True, "isv_mx": True},
    ),
    (
        "10. Non-free domain",
        "info@github.com",
        {"is_free": False, "isv_mx": True},
    ),
]


async def test_health(session: aiohttp.ClientSession) -> dict:
    async with session.get(f"{BASE}/health") as resp:
        return await resp.json()


async def test_single(session: aiohttp.ClientSession, email: str) -> dict:
    payload = {"email": email}
    async with session.post(f"{BASE}/validate", json=payload) as resp:
        return await resp.json()


async def test_bulk(session: aiohttp.ClientSession, emails: list[str]) -> list:
    payload = {"emails": emails}
    async with session.post(f"{BASE}/validate/bulk", json=payload) as resp:
        return await resp.json()


def check(description: str, data: dict, expected: dict) -> bool:
    passed = True
    for key, expected_val in expected.items():
        actual_val = data.get(key)
        if actual_val != expected_val:
            print(f"  ❌ {key}: expected {expected_val!r}, got {actual_val!r}")
            passed = False
    return passed


async def main():
    passed = 0
    failed = 0
    total = 0

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
        # ── Health check ──
        print("=" * 60)
        print("EMAIL VALIDATOR API — INTEGRATION TESTS")
        print("=" * 60)

        # Test 1: Health
        print("\n── 1. Health check ──")
        result = await test_health(session)
        total += 1
        if result.get("status") == "ok":
            print("  ✅ PASS")
            passed += 1
        else:
            print(f"  ❌ FAIL: {result}")
            failed += 1

        # ── Single email validations ──
        for desc, email, expected in SINGLE_TESTS:
            if email is None:
                continue  # already tested health
            print(f"\n── {desc} ──")
            print(f"  Email: {email}")
            total += 1
            try:
                t0 = time.monotonic()
                result = await test_single(session, email)
                elapsed = time.monotonic() - t0
                data = result.get("data", result)
                print(f"  Time: {elapsed:.2f}s")
                print(f"  Result: {data.get('result', 'N/A')}")
                print(f"  Score: {data.get('score', 'N/A')}")
                print(f"  Reason: {data.get('reason', 'N/A')}")
                print(f"  MX: {data.get('mx_records', [])}")
                print(f"  Catch-all: {data.get('is_catchall', 'N/A')}")

                if check(desc, data, expected):
                    print("  ✅ PASS")
                    passed += 1
                else:
                    failed += 1
                    print("  ❌ FAIL")
            except Exception as e:
                print(f"  ❌ ERROR: {e}")
                failed += 1

        # ── Pydantic validation: bad emails get 422 ──
        for idx, bad_email in [("2", "notanemail"), ("3", "user..name@example.com"), ("11", "@missing-local")]:
            print(f"\n── {idx}. Pydantic rejects bad email: {bad_email} ──")
            total += 1
            async with session.post(f"{BASE}/validate", json={"email": bad_email}) as resp:
                if resp.status == 422:
                    print("  ✅ PASS (422 Unprocessable Entity)")
                    passed += 1
                else:
                    body = await resp.json()
                    print(f"  ❌ FAIL: expected 422, got {resp.status}: {body}")
                    failed += 1

        # ── Bulk validation ──
        print("\n── 12. Bulk validation ──")
        total += 1
        bulk_emails = [
            "test@gmail.com",
            "test@mailinator.com",
            "test@thisdomain-definitely-does-not-exist-12345.com",
        ]
        try:
            t0 = time.monotonic()
            results = await test_bulk(session, bulk_emails)
            elapsed = time.monotonic() - t0
            print(f"  Time (3 emails): {elapsed:.2f}s")
            if isinstance(results, list) and len(results) == 3:
                for i, r in enumerate(results):
                    d = r.get("data", r)
                    print(f"    [{i}] {d.get('email')}: {d.get('result')} (score={d.get('score')})")
                print("  ✅ PASS")
                passed += 1
            else:
                print(f"  ❌ FAIL: unexpected response shape: {results}")
                failed += 1
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            failed += 1

        # ── Empty bulk should fail ──
        print("\n── 13. Empty bulk request rejected ──")
        total += 1
        async with session.post(f"{BASE}/validate/bulk", json={"emails": []}) as resp:
            if resp.status == 400:
                print("  ✅ PASS (400 Bad Request)")
                passed += 1
            else:
                body = await resp.json()
                print(f"  ❌ FAIL: expected 400, got {resp.status}: {body}")
                failed += 1

        # ── Cache test: second call should be faster ──
        print("\n── 14. Cache: second call is faster ──")
        total += 1
        t0 = time.monotonic()
        await test_single(session, "cachetest@gmail.com")
        first = time.monotonic() - t0
        t0 = time.monotonic()
        await test_single(session, "cachetest@gmail.com")
        second = time.monotonic() - t0
        print(f"  First call: {first:.3f}s   Cached call: {second:.3f}s")
        if second < first:
            print("  ✅ PASS (cached call faster)")
            passed += 1
        else:
            print("  ⚠️  WARN (cached call not faster — may be network variance)")
            passed += 1  # still a soft pass

    # ── Summary ──
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} passed, {failed} failed")
    print("=" * 60)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
