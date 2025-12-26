import time
import hashlib
import secrets
from typing import Dict, Optional, Tuple

import pandas as pd
import streamlit as st


# -----------------------------
# SecureShield: educational app
# -----------------------------

st.set_page_config(
    page_title="SecureShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def local_css() -> None:
    """Inject custom CSS for the 'Black Box' theme."""

    st.markdown(
        """
<style>
/* --- Global ultra-dark theme --- */
html, body, [class*="stApp"] {
  background: #000000 !important;
  color: #d7ffd9 !important;
  font-family: "Fira Code", "Courier New", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
}

/* Reduce top padding a bit */
.main .block-container { padding-top: 1.0rem; padding-bottom: 2.0rem; }

/* --- Hide the sidebar entirely --- */
section[data-testid="stSidebar"],
div[data-testid="stSidebar"],
button[kind="header"] {
  display: none !important;
}
button[title="View sidebar"], button[title="Hide sidebar"] { display: none !important; }

/* Subtle scanline effect */
.stApp:before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    to bottom,
    rgba(0,255,65,0.030),
    rgba(0,255,65,0.030) 1px,
    rgba(0,0,0,0.0) 2px,
    rgba(0,0,0,0.0) 6px
  );
  opacity: 0.55;
  mix-blend-mode: overlay;
  z-index: 0;
}

/* --- Cards --- */
.secureshield-card {
  position: relative;
  z-index: 1;
  background: radial-gradient(1200px 180px at 15% 0%, rgba(0,255,65,0.10), transparent 60%),
              linear-gradient(180deg, rgba(11,15,12,0.96), rgba(7,10,8,0.92));
  border: 1px solid rgba(0, 255, 65, 0.24);
  box-shadow:
    0 0 0 1px rgba(0, 255, 65, 0.06) inset,
    0 10px 28px rgba(0,0,0,0.55);
  border-radius: 16px;
  padding: 16px 18px;
}

.hr-glow {
  border: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(0,255,65,0.65), transparent);
  margin: 10px 0 14px 0;
}

.badge-green, .badge-red {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  letter-spacing: 0.10em;
  text-transform: uppercase;
}

.badge-green {
  border: 1px solid rgba(0,255,65,0.6);
  color: #00ff41;
  background: rgba(0,255,65,0.06);
}

.badge-red {
  border: 1px solid rgba(255,0,85,0.6);
  color: #ff0055;
  background: rgba(255,0,85,0.06);
}

/* --- Buttons --- */
.stButton > button {
  border: 1px solid rgba(0, 255, 65, 0.75) !important;
  background: rgba(0, 0, 0, 0.35) !important;
  color: #00ff41 !important;
  border-radius: 12px !important;
  padding: 0.62rem 0.95rem !important;
  font-weight: 800 !important;
  letter-spacing: 0.10em !important;
  text-transform: uppercase !important;
  box-shadow: 0 0 0 1px rgba(0,255,65,0.10) inset;
  transition: transform 120ms ease, box-shadow 180ms ease, border-color 180ms ease;
}

.stButton > button:hover {
  transform: translateY(-1px);
  border-color: rgba(0, 255, 65, 1.0) !important;
  box-shadow: 0 0 18px rgba(0,255,65,0.22), 0 0 0 1px rgba(0,255,65,0.18) inset;
}

.danger-btn .stButton > button {
  border-color: rgba(255, 0, 85, 0.85) !important;
  color: #ff0055 !important;
}
.danger-btn .stButton > button:hover {
  border-color: rgba(255, 0, 85, 1.0) !important;
  box-shadow: 0 0 18px rgba(255,0,85,0.26), 0 0 0 1px rgba(255,0,85,0.16) inset;
}

/* --- Terminal-style inputs --- */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea,
[data-testid="stNumberInput"] input {
  background: #000000 !important;
  color: #00ff41 !important;
  border: 1px solid rgba(0,255,65,0.35) !important;
  border-radius: 12px !important;
}

[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus,
[data-testid="stNumberInput"] input:focus {
  box-shadow: 0 0 0 1px rgba(0,255,65,0.35) inset, 0 0 16px rgba(0,255,65,0.16) !important;
  border-color: rgba(0,255,65,0.75) !important;
}

/* --- Horizontal navigation (radio-as-tabs) --- */
.navbar {
  position: sticky;
  top: 0;
  z-index: 999;
  backdrop-filter: blur(8px);
  background: rgba(0,0,0,0.78);
  border-bottom: 1px solid rgba(0,255,65,0.14);
  padding: 10px 0 10px 0;
  margin-bottom: 16px;
}

.navbar div[role="radiogroup"] {
  display: flex !important;
  flex-direction: row !important;
  flex-wrap: wrap !important;
  gap: 10px !important;
}

.navbar [data-testid="stRadio"] svg,
.navbar [data-testid="stRadio"] input {
  display: none !important;
}

.navbar [data-testid="stRadio"] label {
  background: linear-gradient(180deg, rgba(7,10,8,0.95), rgba(0,0,0,0.55)) !important;
  border: 1px solid rgba(0,255,65,0.22) !important;
  border-radius: 14px !important;
  padding: 10px 14px !important;
  color: #b9ffbe !important;
  cursor: pointer !important;
  user-select: none !important;
  transition: all 160ms ease;
  margin: 0 !important;
}

.navbar [data-testid="stRadio"] label:hover {
  border-color: rgba(0,255,65,0.65) !important;
  box-shadow: 0 0 16px rgba(0,255,65,0.18);
}

.navbar [data-testid="stRadio"] div[role="radio"][aria-checked="true"] label {
  border-color: rgba(0,255,65,0.95) !important;
  color: #00ff41 !important;
  box-shadow: 0 0 18px rgba(0,255,65,0.22);
}

/* DataFrames */
[data-testid="stDataFrame"] {
  border: 1px solid rgba(0,255,65,0.14);
  border-radius: 14px;
  overflow: hidden;
}

</style>
        """,
        unsafe_allow_html=True,
    )


local_css()


# -----------------------------
# Helpers (hashing, rendering)
# -----------------------------

def to_bytes(s: str) -> bytes:
    return s.encode("utf-8", errors="replace")


def compute_hashes(message: str) -> Dict[str, str]:
    """Compute common hashes for demonstration.

    Instructor note:
    Hash functions are one-way: you can verify integrity by re-hashing an input,
    but you cannot recover the original message from the digest.

    We intentionally include MD5 here only as a *teaching artifact* because it is
    cryptographically broken for collision resistance.
    """

    data = to_bytes(message)
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }


def diff_highlight(old: str, new: str) -> str:
    """Return an HTML string where characters that differ are highlighted.

    Useful to visualize the avalanche effect: a tiny input change causes a
    large apparent change across the entire hash.
    """

    if not old:
        # First render: show as normal (no diff yet)
        safe = new
        return f"<span style='color:#b9ffbe;'>{safe}</span>"

    out = []
    # Same length for hexdigests, but keep it generic.
    max_len = max(len(old), len(new))
    old_padded = old.ljust(max_len)
    new_padded = new.ljust(max_len)

    for oc, nc in zip(old_padded, new_padded):
        if oc == nc:
            out.append(f"<span style='color:#9deaa4;'>{nc}</span>")
        else:
            out.append(
                "<span style='color:#000;background:#ff0055;padding:1px 2px;border-radius:4px;'>"
                + nc
                + "</span>"
            )

    return "".join(out)


def salted_password_hash(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Create a per-user salt and salted hash.

    Instructor note:
    - Salt defeats precomputed rainbow tables and ensures identical passwords
      produce different hashes.
    - For real systems you'd use a *slow* password hashing algorithm (bcrypt,
      scrypt, Argon2). For this lab, we use SHA-256 to keep the math visible.
    """

    if salt is None:
        # 16 bytes -> 32 hex chars
        salt = secrets.token_hex(16)

    # Salted hash: SHA256(salt || password)
    digest = hashlib.sha256(to_bytes(salt + password)).hexdigest()
    return salt, digest


def card(title: str, body: str, *, badge: Optional[str] = None) -> None:
    """Render a styled card with the body INSIDE the same box.

    We avoid user-visible raw HTML tags by:
    - Keeping the outer box as HTML (for styling)
    - Rendering the body as Markdown text inside the box using a safe wrapper

    Note: `body` should be plain text/Markdown (not HTML).
    """

    header_right = f"<span class='badge-green'>{badge}</span>" if badge else ""

    # Put the body inside the same card container. We use a <div> wrapper and
    # rely on Markdown for formatting (Streamlit will render Markdown, not show tags).
    st.markdown(
        f"""
<div class="secureshield-card">
  <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
    <div style="font-size:17px;font-weight:900;letter-spacing:0.10em;color:#00ff41;">{title}</div>
    {header_right}
  </div>
  <hr class="hr-glow"/>
  <div style="color:#d7ffd9; line-height:1.7; font-size: 0.98rem;">
    {body}
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------
# Session state initialization
# -----------------------------

if "users" not in st.session_state:
    # Users are stored in-memory for demo:
    # { username: {"salt": ..., "hash": ...} }
    st.session_state.users = {}

if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

if "prev_hashes" not in st.session_state:
    # Remember previous hashes to highlight avalanche effect on change.
    st.session_state.prev_hashes = {"MD5": "", "SHA-256": "", "SHA-512": ""}


# -----------------------------
# Top Navigation (NO SIDEBAR)
# -----------------------------

st.markdown('<div class="navbar">', unsafe_allow_html=True)
nav = st.radio(
    "",
    ["Mission Control", "The Hash Lab", "Breach Simulator", "Login System"],
    horizontal=True,
    label_visibility="collapsed",
)
st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------
# Page: Mission Control
# -----------------------------

def render_mission_control() -> None:
    # Title card: keep HTML here for typing effect only (doesn't expose raw tags)
    st.markdown(
        """
<div class="secureshield-card">
  <div id="typing" style="font-size:30px;font-weight:950;letter-spacing:0.12em;color:#00ff41;">
    SECURE_SHIELD // SYSTEM_ONLINE
  </div>
  <div style="margin-top:10px;color:#b9ffbe;line-height:1.7;">
    <span class="badge-green">LAB MODE</span>
    &nbsp;Interactive demonstrations of: <b>Hashing vs. Encryption</b>, the <b>Avalanche Effect</b>, and <b>Secure Authentication</b>.
    <br/><br/>
    <b>Use cases:</b>
    <ul>
      <li><b>Hashing</b>: one-way, integrity + password verification</li>
      <li><b>Encryption</b>: two-way, confidentiality (needs a key)</li>
      <li><b>Authentication</b>: verify without storing passwords</li>
    </ul>
  </div>
</div>

<script>
(() => {
  const el = window.parent.document.getElementById('typing');
  if (!el) return;
  const full = 'SECURE_SHIELD // SYSTEM_ONLINE';
  if (el.getAttribute('data-typed') === '1') return;
  el.setAttribute('data-typed','1');
  el.textContent = '';
  let i = 0;
  const tick = () => {
    el.textContent = full.slice(0, i);
    i++;
    if (i <= full.length) window.parent.requestAnimationFrame(tick);
  };
  tick();
})();
</script>
        """,
        unsafe_allow_html=True,
    )

    cols = st.columns(3)
    with cols[0]:
        card(
            "HASHING // ONE-WAY",
            """
**Hashing is one-way.**

- Input → digest (fingerprint)
- Used for integrity checks and verifying passwords
- You *can't* reverse a secure hash to get the original input
            """.strip(),
            badge="SAFE",
        )

    with cols[1]:
        card(
            "ENCRYPTION // TWO-WAY",
            """
**Encryption is two-way.**

- Plaintext ↔ ciphertext with a key
- Used for confidentiality (protecting data)
- If the key is compromised, encrypted data can be decrypted
            """.strip(),
            badge="KEYED",
        )

    with cols[2]:
        card(
            "AUTH // VERIFY",
            """
**Authentication should verify, not reveal.**

- Store `salt + hash`, never plaintext
- Login = recompute hash from supplied password and compare
- Salts ensure identical passwords don’t share the same hash
            """.strip(),
            badge="VERIFY",
        )


# -----------------------------
# Page: The Hash Lab
# -----------------------------

def render_hash_lab() -> None:
    st.markdown(
        """
<div class="secureshield-card">
  <div style="font-size:18px;font-weight:900;letter-spacing:0.08em;color:#00ff41;">THE_HASH_LAB</div>
  <div style="margin-top:6px;color:#b9ffbe;line-height:1.65;">
    Type any message and observe how different hash algorithms produce different fingerprints.
    Change <b>one character</b> to trigger the <b>Avalanche Effect</b> highlighting.
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )

    msg = st.text_area(
        "Input message",
        value="",
        height=150,
        placeholder="Enter text here...",
        help="Hash outputs update instantly. Try tiny edits (e.g., change one letter).",
    )

    try:
        hashes = compute_hashes(msg)
    except Exception as e:
        st.error(f"Hash computation failed: {e}")
        return

    # Render with avalanche diff: compare current to previous render.
    prev = st.session_state.prev_hashes

    st.markdown("<hr class='hr-glow'/>", unsafe_allow_html=True)

    cols = st.columns(3)
    for i, algo in enumerate(["MD5", "SHA-256", "SHA-512"]):
        with cols[i]:
            st.markdown(
                f"""
<div class="secureshield-card">
  <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
    <div style="font-weight:900;letter-spacing:0.08em;color:#d7ffd9;">{algo}</div>
    <div class="badge-green">DIGEST</div>
  </div>
  <hr class="hr-glow"/>
  <div style="font-size:13px;word-break:break-all;line-height:1.6;">
    {diff_highlight(prev.get(algo, ""), hashes[algo])}
  </div>
</div>
                """,
                unsafe_allow_html=True,
            )

    # Update prev hashes after rendering
    st.session_state.prev_hashes = hashes

    st.caption(
        "Instructor note: Avalanche effect is a required property for cryptographic hashes: small input changes yield unpredictable output changes."
    )


# -----------------------------
# Page: Breach Simulator
# -----------------------------

def render_breach_simulator() -> None:
    st.markdown(
        """
<div class="secureshield-card">
  <div style="font-size:18px;font-weight:950;letter-spacing:0.10em;color:#00ff41;">BREACH_SIMULATOR</div>
  <div style="margin-top:6px;color:#b9ffbe;line-height:1.7;">
    Compare an <b>insecure</b> plaintext password database with a <b>secure</b> salted-hash database.
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )

    insecure_rows = [
        {"username": "alice", "password": "Password123"},
        {"username": "bob", "password": "qwerty"},
        {"username": "charlie", "password": "letmein"},
        {"username": "diana", "password": "Uni2025!"},
    ]

    secure_rows = []
    for r in insecure_rows:
        salt, h = salted_password_hash(r["password"])
        secure_rows.append({"username": r["username"], "salt": salt, "password_hash": h})

    insecure_df = pd.DataFrame(insecure_rows)
    secure_df = pd.DataFrame(secure_rows)

    left, right = st.columns(2)

    with left:
        card(
            "Insecure_DB",
            """
Stores passwords in **plaintext**.

If a breach happens, attackers instantly learn everyone’s password.
            """.strip(),
            badge="DANGER",
        )

    with right:
        card(
            "Secure_DB",
            """
Stores **salt + hash**.

A database dump does **not** reveal passwords directly.
(Attackers may still attempt offline guessing; real systems use slow hashing.)
            """.strip(),
            badge="PROTECTED",
        )

    st.markdown("<hr class='hr-glow'/>", unsafe_allow_html=True)

    st.session_state.setdefault("breach_ran", False)

    st.markdown('<div class="danger-btn">', unsafe_allow_html=True)
    clicked = st.button("💥 SIMULATE HACK", type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

    if clicked:
        st.session_state.breach_ran = True

        progress = st.progress(0, text="Hacking... establishing foothold")
        for i in range(1, 101):
            time.sleep(0.012)
            if i < 35:
                txt = "Hacking... escalating privileges"
            elif i < 70:
                txt = "Hacking... dumping tables"
            else:
                txt = "Hacking... exfiltration complete"
            progress.progress(i, text=txt)
        time.sleep(0.15)

    if st.session_state.breach_ran:
        a, b = st.columns(2)
        with a:
            st.markdown("<div class='badge-red'>COMPROMISED</div>", unsafe_allow_html=True)
            st.dataframe(insecure_df, use_container_width=True, hide_index=True)

        with b:
            st.markdown("<div class='badge-green'>RESISTANT</div>", unsafe_allow_html=True)
            st.dataframe(secure_df, use_container_width=True, hide_index=True)

        st.caption(
            "Plaintext dumps are immediately usable. Salted hashes prevent instant password disclosure."
        )
    else:
        st.info("Click **SIMULATE HACK** to reveal what an attacker sees after a database breach.")


# -----------------------------
# Page: Login System
# -----------------------------

def render_login_system() -> None:
    st.markdown(
        """
<div class="secureshield-card">
  <div style="font-size:18px;font-weight:900;letter-spacing:0.08em;color:#00ff41;">LOGIN_SYSTEM</div>
  <div style="margin-top:6px;color:#b9ffbe;line-height:1.65;">
    This is a working demo of secure authentication:
    <b>register</b> stores <i>salt + hash</i>, and <b>login</b> verifies by recomputing the salted hash.
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )

    users: Dict[str, Dict[str, str]] = st.session_state.users

    top = st.columns([1, 1, 1])
    with top[0]:
        if st.session_state.logged_in_user:
            st.markdown(
                f"<div class='badge-green'>AUTHENTICATED: {st.session_state.logged_in_user}</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown("<div class='badge-red'>NOT_AUTHENTICATED</div>", unsafe_allow_html=True)

    with top[2]:
        if st.session_state.logged_in_user:
            if st.button("LOG OUT"):
                st.session_state.logged_in_user = None
                st.success("Logged out.")

    st.markdown("<hr class='hr-glow'/>", unsafe_allow_html=True)

    register_col, login_col = st.columns(2)

    with register_col:
        card(
            "REGISTER",
            """
            Create a new account. We will display the generated **salt** and **hash** to show what is stored.
            """.strip(),
        )

        with st.form("register_form", clear_on_submit=False):
            r_user = st.text_input("Username", key="reg_user")
            r_pass = st.text_input("Password", type="password", key="reg_pass")
            r_pass2 = st.text_input("Confirm Password", type="password", key="reg_pass2")
            submitted = st.form_submit_button("REGISTER")

        if submitted:
            try:
                if not r_user or not r_pass:
                    st.warning("Username and password are required.")
                elif r_pass != r_pass2:
                    st.warning("Passwords do not match.")
                elif r_user in users:
                    st.warning("Username already exists. Choose another.")
                else:
                    salt, h = salted_password_hash(r_pass)
                    users[r_user] = {"salt": salt, "hash": h}
                    st.session_state.users = users

                    st.success("User registered. Stored values shown below (educational).")
                    st.code(
                        f"username: {r_user}\n"
                        f"salt: {salt}\n"
                        f"sha256(salt+password): {h}",
                        language="text",
                    )
            except Exception as e:
                st.error(f"Registration failed: {e}")

    with login_col:
        card(
            "LOGIN",
            """
            Login verifies by recomputing SHA-256(**salt + provided_password**) and comparing to the stored hash.
            """.strip(),
        )

        with st.form("login_form", clear_on_submit=False):
            l_user = st.text_input("Username", key="log_user")
            l_pass = st.text_input("Password", type="password", key="log_pass")
            l_submitted = st.form_submit_button("LOGIN")

        if l_submitted:
            try:
                if not l_user or not l_pass:
                    st.warning("Username and password are required.")
                elif l_user not in users:
                    st.error("No such user.")
                else:
                    salt = users[l_user]["salt"]
                    expected = users[l_user]["hash"]
                    _, candidate = salted_password_hash(l_pass, salt=salt)

                    if secrets.compare_digest(candidate, expected):
                        st.session_state.logged_in_user = l_user
                        st.success("Access granted.")
                    else:
                        st.error("Access denied. Incorrect password.")

                    with st.expander("Show verification math (educational)"):
                        st.code(
                            f"stored_salt: {salt}\n"
                            f"stored_hash: {expected}\n"
                            f"candidate_hash: {candidate}",
                            language="text",
                        )
            except Exception as e:
                st.error(f"Login failed: {e}")

    st.markdown("<hr class='hr-glow'/>", unsafe_allow_html=True)
    st.caption(
        "Production note: Use a dedicated password hash function (Argon2/bcrypt/scrypt) and a real database. This app uses SHA-256 strictly for clarity in a lab setting."
    )


# -----------------------------
# Router
# -----------------------------

if nav == "Mission Control":
    render_mission_control()
elif nav == "The Hash Lab":
    render_hash_lab()
elif nav == "Breach Simulator":
    render_breach_simulator()
elif nav == "Login System":
    render_login_system()
else:
    st.error("Unknown navigation state.")
