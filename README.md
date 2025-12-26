# SecureShield 🛡️

**SecureShield** is a single-file, interactive Streamlit app designed for university cybersecurity labs.
It demonstrates:

- **Hashing vs. Encryption** (one-way vs two-way)
- The **Avalanche Effect** (small input changes → completely different digest)
- A **Breach Simulator** (plaintext DB vs salted+hashed DB)
- A simple **Register/Login** flow using **salt + hash**

> Note: This project intentionally uses `hashlib` (SHA-256) for visibility and teaching.
> Real production systems should use dedicated password hash algorithms like **Argon2**, **bcrypt**, or **scrypt**.

---

## Tech Stack

- Python 3.9+
- [Streamlit](https://streamlit.io)
- `hashlib` + `secrets` (Python standard library)
- Pandas

---

## Project Structure

```text
.
├── app.py
├── requirements.txt
└── README.md
```

---

## Setup

### 1) Create/activate a virtual environment (recommended)

**macOS / zsh**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

---

## Run the app

```bash
python3 -m streamlit run app.py
```

Streamlit will print a local URL (usually `http://localhost:8501`).

---

## App Pages

### 1) Mission Control
A short intro and quick conceptual definitions.

### 2) The Hash Lab
Type any message and see live:
- MD5
- SHA-256
- SHA-512

The output highlights differences between the previous and current digest to visualize the **avalanche effect**.

### 3) Breach Simulator
Shows two mock databases:
- `Insecure_DB` (plaintext passwords)
- `Secure_DB` (salt + hashed passwords)

Press **SIMULATE HACK** to see what an attacker would steal.

### 4) Login System
A demo authentication flow:
- **Register** creates a per-user salt and stores only `salt + hash`
- **Login** recomputes the salted hash and compares using `secrets.compare_digest`

---

## Security Notes (Teaching Highlights)

- Hashing is **one-way**; encryption is **two-way**.
- Salting prevents two identical passwords from producing the same stored hash.
- Timing-safe comparison (`secrets.compare_digest`) is used when verifying hashes.

---

## License

Educational use only (feel free to adapt for your lab).
