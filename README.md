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

## Requirements (Beginner-friendly)

1. **Install Python (3.9 or newer)**

   - Download: https://www.python.org/downloads/
   - During installation on Windows, **enable**: ✅ _“Add Python to PATH”_

2. **Download / open this project folder**

   - If you downloaded a ZIP: extract it first.
   - You should see `app.py`, `requirements.txt`, and `README.md` in the same folder.

3. **Open a terminal in the project folder**
   - **Windows:** open _PowerShell_ or _Command Prompt_ in the folder.
   - **macOS:** open _Terminal_ and `cd` into the folder.

---

## Setup (macOS / Linux)

### 1) Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

---

## Setup (Windows)

### 1) Verify Python is available

In **PowerShell** (recommended):

```powershell
python --version
```

If that fails, try:

```powershell
py --version
```

### 2) Create and activate a virtual environment

**PowerShell**:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Command Prompt (cmd)**:

```bat
python -m venv .venv
.venv\Scripts\activate.bat
```

> If PowerShell blocks activation, run PowerShell as Administrator and execute:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### 3) Install dependencies

```powershell
python -m pip install -r requirements.txt
```

---

## Run the app

### macOS / Linux

```bash
python3 -m streamlit run app.py
```

### Windows

```powershell
python -m streamlit run app.py
```

---

## Open in your browser

After running, Streamlit prints something like:

- `Local URL: http://localhost:8501`

Open your browser and go to:

- **http://localhost:8501**

If port **8501** is busy, Streamlit will choose another port and print it in the terminal.

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
