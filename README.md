# SecureSQL Guard
## SQL Injection Detection & Prevention System

A complete, deployable cloud-compatible security system that protects against SQL injection attacks using:
- **Double-Layer Defense** (Pattern Scanner + Parameterized Queries)
- **AES-256-GCM Encryption** with PBKDF2 key derivation
- **Capability Code Mechanism** (JWT-style access tokens)
- **AI-powered threat analysis** via Claude API
- **Zero server requirements** — runs in any browser

---

## Project Structure

```
securesql/
├── index.html              ← Single-page application entry point
├── css/
│   └── style.css           ← Dark terminal theme, full UI styling
├── js/
│   ├── crypto.js           ← AES-256-GCM + JWT token generation
│   ├── patterns.js         ← 15 SQL injection patterns + WAF rules
│   ├── sanitizer.js        ← Layer 1 sanitizer + Layer 2 query builder
│   ├── capabilities.js     ← Capability token issuance & registry
│   ├── scanner.js          ← Vulnerability assessment engine
│   ├── ui.js               ← DOM rendering functions
│   ├── ai.js               ← Claude AI analyst integration
│   └── app.js              ← State management + event wiring
└── README.md               ← This file
```

---

## Quick Start

### Option 1: Open directly in browser (no server needed)
```bash
open index.html
# or double-click index.html in your file manager
```

### Option 2: Local dev server
```bash
# Python
python3 -m http.server 8080

# Node.js
npx serve .

# Then visit: http://localhost:8080
```

### Option 3: Deploy to Netlify (free, internet-accessible)
1. Zip the `securesql/` folder
2. Go to [netlify.com/drop](https://netlify.com/drop)
3. Drag and drop the zip file
4. Your system is live at a public URL instantly

### Option 4: GitHub Pages (free)
```bash
git init
git add .
git commit -m "SecureSQL Guard"
git branch -M main
git remote add origin https://github.com/YOUR_USER/securesql.git
git push -u origin main
# Enable Pages in repo Settings → Pages → Branch: main
```

### Option 5: Vercel (free)
```bash
npm i -g vercel
vercel
```

### Option 6: Nginx (self-hosted)
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    root /var/www/securesql;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Content-Security-Policy "default-src 'self' https://api.anthropic.com https://fonts.googleapis.com; script-src 'self'; style-src 'self' https://fonts.googleapis.com;";
}
```

---

## Security Architecture

### Layer 1 — Pattern Detection & Input Sanitization

The first defense line scans every user input against 15 regex-based attack detectors:

| Pattern | Severity | Example |
|---------|----------|---------|
| UNION-based extraction | Critical | `' UNION SELECT username,password FROM users--` |
| Boolean blind injection | Critical | `' OR 1=1--` |
| Time-based blind | Critical | `'; WAITFOR DELAY '0:0:5'--` |
| Stacked queries | Critical | `1; DROP TABLE users;--` |
| OS command execution | Critical | `'; EXEC xp_cmdshell('whoami')--` |
| Tautology attack | Critical | `' OR 'x'='x` |
| Out-of-band exfil | Critical | `' UNION SELECT load_file('/etc/passwd')--` |
| Schema enumeration | High | `UNION SELECT table_name FROM information_schema.tables--` |
| Comment truncation | High | `admin'--` |
| Null byte injection | High | `admin%00' OR 1=1--` |
| Second-order injection | High | Stored payloads |
| Piggyback query | High | `'; SELECT * FROM users WHERE 1=1--` |
| Quote manipulation | Medium | `'' OR ''=''` |
| Hex-encoded bypass | Medium | `0x61646d696e` |
| Stored procedure abuse | Medium | `'; CALL admin_reset()--` |

**WAF Rules (8 active):**
- Block UNION keyword
- Block DROP/TRUNCATE/ALTER
- Block comment sequences (--, /*, #)
- Block time-delay functions
- Strip null bytes
- Enforce max input length (500 chars)
- Block xp_cmdshell
- Block information_schema access

### Layer 2 — Parameterized Query Engine

Even if Layer 1 is bypassed, Layer 2 guarantees safe execution:

```sql
-- UNSAFE (vulnerable to injection):
$query = "SELECT * FROM users WHERE username = '" . $input . "'";

-- SAFE (Layer 2 parameterization):
PREPARE stmt FROM 'SELECT * FROM users WHERE username = ?';
SET @param = ?;  -- user value bound here, never in SQL string
EXECUTE stmt USING @param;
```

In PHP (PDO):
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :user");
$stmt->execute([':user' => $userInput]);
```

In Java (JDBC):
```java
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE username = ?");
ps.setString(1, userInput);
ResultSet rs = ps.executeQuery();
```

In Python (psycopg2):
```python
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

### AES-256-GCM Encryption

All credentials are encrypted at rest:

```
Algorithm  : AES-256-GCM
KDF        : PBKDF2-SHA256
Iterations : 100,000
Salt       : 16 bytes random (per record)
IV         : 12 bytes random (per encryption)
Tag        : 128-bit GCM authentication tag
Key size   : 256 bits (32 bytes)
```

**Key derivation chain:**
```
master_password + random_salt
        ↓ PBKDF2-SHA256 (100,000 iterations)
    256-bit encryption key
        ↓ AES-256-GCM encrypt
    ciphertext + auth_tag
```

In Node.js (reference implementation):
```javascript
const crypto = require('crypto');

const encryptAES256GCM = (plaintext, masterPassword) => {
    const salt = crypto.randomBytes(16);
    const iv   = crypto.randomBytes(12);
    const key  = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, 'sha256');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext: ciphertext.toString('hex'), salt: salt.toString('hex'),
             iv: iv.toString('hex'), tag: tag.toString('hex') };
};
```

### Capability Code Mechanism

All database access requires a valid capability token:

```
Token format: <header>.<payload>.<signature>  (JWT-style, HS256)

Header:  { "alg": "HS256", "typ": "JWT", "kid": "<key-id>" }

Payload: {
    "iss": "securesql-guard",
    "sub": "user@example.com",
    "iat": 1704067200,
    "exp": 1704153600,
    "jti": "a1b2c3d4",
    "perms": ["READ_INTERNAL", "WRITE_DATA"],
    "scope": "SELECT_INSERT",
    "sql_inject_guard": true
}
```

**SQL Scopes:**
| Scope | Allowed Operations |
|-------|--------------------|
| `NO_ACCESS` | None |
| `SELECT_ONLY` | SELECT |
| `SELECT_INSERT` | SELECT, INSERT |
| `SELECT_INSERT_UPDATE` | SELECT, INSERT, UPDATE |
| `FULL_DML` | SELECT, INSERT, UPDATE, DELETE |
| `ADMIN` | All including DDL |

---

## Feature Walkthrough

### Dashboard Tab
- Real-time metrics (total queries, blocked attacks, encrypted records, active tokens)
- Live security event log
- AI Security Analyst (Claude API) — describe any attack, get expert analysis
- Attack timeline chart

### SQL Tester Tab
- Paste any payload and see both defense layers respond in real-time
- Layer 1 shows which patterns matched and the sanitized output
- Layer 2 shows the parameterized query that would safely execute
- Side-by-side raw vs sanitized comparison
- Risk score (0–100) per injection attempt

### Data Vault Tab
- Add user records → encrypted with AES-256-GCM
- View ciphertext, salt, IV, and generated capability token
- Encrypted records table with masked credentials

### Capabilities Tab
- Issue fine-grained capability tokens
- Configure SQL scope, permissions, and expiry
- Active token registry with revoke/activate toggles
- View decoded token payload and SQL guard comments

### Vuln Scanner Tab
- 3 scan depths: Quick (5 checks), Standard (14), Deep (20)
- Checks cover all OWASP SQL injection variants + encryption + access control
- Per-check remediation guidance
- Security score (0–100%)

### Docs Tab
- Full system architecture documentation
- Deployment guide
- Security checklist
- Code examples

---

## Connecting to a Real Backend

To connect this to a real database, implement these API endpoints
and replace the in-memory simulation with actual database calls:

```
POST /api/test-input     ← receives { input, field, queryType }
POST /api/encrypt-user   ← receives { username, password, role }
POST /api/issue-token    ← receives { subject, expiry, perms, scope }
POST /api/revoke-token   ← receives { tokenId }
GET  /api/scan           ← returns vulnerability scan results
```

The `Sanitizer.layer1Sanitize()` and `Sanitizer.buildParameterizedQuery()`
functions map directly to server-side middleware.

---

## Vulnerability Coverage

| OWASP Injection Type | Detected | Parameterization Blocks |
|---------------------|----------|------------------------|
| Classic (in-band) | ✅ | ✅ |
| UNION-based | ✅ | ✅ |
| Error-based | ✅ | ✅ |
| Boolean blind | ✅ | ✅ |
| Time-based blind | ✅ | ✅ |
| Out-of-band | ✅ | ⚠ Needs network controls |
| Second-order | ⚠ Partial | ✅ if ORM used |
| NoSQL operators | ❌ | N/A |
| Stored procedure | ✅ | ⚠ Needs EXEC privileges removed |

---

## License

MIT — free for educational and commercial use.
Built as part of a cybersecurity coursework demonstration.
