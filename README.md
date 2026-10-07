# 🛡️ CyberMiniKit

> A Python-based cybersecurity mini toolkit containing five practical security utilities in one interactive terminal application.

CyberMiniKit is a lightweight cybersecurity toolkit designed to demonstrate practical security concepts through simple, modular Python utilities.

The project provides an interactive Rich-powered terminal interface and organizes multiple security checks into a single command-line application.

---

## 🚀 Features

### 1. 🔐 Password Strength Checker

Analyzes passwords using multiple security characteristics.

**Checks include:**

- Password length
- Uppercase characters
- Lowercase characters
- Numbers
- Special characters
- Common passwords
- Repeated characters
- Predictable sequences
- Overall strength score
- Security recommendations

---

### 2. 🌐 URL / Domain Security Checker

Performs basic security analysis of URLs and domains.

**Checks include:**

- HTTPS usage
- Direct IP-based URLs
- Non-standard ports
- URL length
- Suspicious URL characters
- Multiple subdomains
- Hyphen-heavy hostnames
- Security score
- Security recommendations

---

### 3. #️⃣ Hash Identifier

Identifies common hash formats based on their structure.

**Currently recognizes:**

- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- bcrypt
- Argon2

The tool analyzes hash length and format to determine the most likely algorithm.

> Note: Hash identification based on format is heuristic and does not guarantee the exact algorithm.

---

### 4. 📁 File Integrity Checker

Uses cryptographic hashes to detect file modifications.

**Supported algorithms:**

- SHA-256
- SHA-512
- MD5

**Capabilities:**

- Calculate file hashes
- Generate trusted reference hashes
- Compare current and reference hashes
- Detect file modifications
- Display file size and hash information

Example workflow:

```text
Trusted Hash
     ↓
Current File
     ↓
Calculate Hash
     ↓
Compare
     ↓
INTEGRITY OK / FILE MODIFIED
