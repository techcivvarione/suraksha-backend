"""
cyber_card_scorer.py — Real-time Cyber Score calculation engine.

Score = 1000 (base)
  − Exposure Risk    (0–400)  email breaches, compromised passwords
  − Behavior Risk    (0–250)  high/medium risk scans, risky QR codes
  + Protection       (0–200)  verified phone, trusted contacts, active alerts
  + Activity         (0–100)  scan-type coverage breadth
  + Consistency      (0–50)   recent activity streak
Clamp final result: 0–1000.

Returns a dict — does NOT write to the database.  The caller
(cyber_card.py route) is responsible for persisting the result.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ── Risk-level thresholds (V2 — 0-1000 scale) ─────────────────────────────────

def _level(score: int) -> str:
    if score >= 850: return "EXCELLENT"
    if score >= 700: return "MOSTLY_SAFE"
    if score >= 550: return "MODERATE_RISK"
    if score >= 400: return "HIGH_RISK"
    return "CRITICAL"


# ── UTC-aware datetime helper ────────────────────────────────────────────────

def _to_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── Main scoring function ────────────────────────────────────────────────────

def calculate_cyber_score(db: Session, user_id: str) -> dict[str, Any]:
    """Compute a Cyber Score for *user_id* and return the full payload.

    Return shape:
        {
            "score":       int,          # 0–1000
            "level":       str,          # EXCELLENT / MOSTLY_SAFE / …
            "factors":     dict,         # per-component breakdown
            "insights":    list[str],    # human-readable findings
            "actions":     list[dict],   # suggested next steps
            "computed_at": str,          # ISO-8601 UTC timestamp
        }
    """
    now    = datetime.now(timezone.utc)
    ago_30 = now - timedelta(days=30)
    ago_7  = now - timedelta(days=7)
    ago_14 = now - timedelta(days=14)

    insights: list[str]       = []
    actions:  list[dict]      = []
    factors:  dict[str, Any]  = {}

    # ── 1. Load scan history (last 30 days) ──────────────────────────────────
    #    Normalize scan_type to UPPER so both "email" (new) and "EMAIL" (legacy)
    #    are handled identically without needing a data migration.

    try:
        scan_rows = db.execute(
            text(
                """
                SELECT UPPER(scan_type) AS scan_type, risk, score AS scan_score, created_at
                FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND created_at >= :since
                ORDER BY created_at DESC
                """
            ),
            {"uid": user_id, "since": ago_30},
        ).mappings().all()
    except Exception:
        logger.exception("cyber_scorer_scan_history_failed", extra={"user_id": user_id})
        scan_rows = []

    def _risk(row) -> str:
        return str(row.get("risk") or "").lower()

    # Type buckets (case-normalised via UPPER() in the query above)
    email_scans    = [r for r in scan_rows if r["scan_type"] == "EMAIL"]
    password_scans = [r for r in scan_rows if r["scan_type"] == "PASSWORD"]
    threat_scans   = [r for r in scan_rows if r["scan_type"] in ("THREAT", "TEXT")]
    qr_scans       = [r for r in scan_rows if r["scan_type"] == "QR"]
    image_scans    = [r for r in scan_rows if r["scan_type"] in ("REALITY_IMAGE", "IMAGE", "OCR")]

    # ── 2. User profile ───────────────────────────────────────────────────────

    try:
        user_row = db.execute(
            text("SELECT phone_verified FROM users WHERE id = CAST(:uid AS uuid)"),
            {"uid": user_id},
        ).mappings().first()
        phone_verified = bool(user_row["phone_verified"]) if user_row else False
    except Exception:
        logger.exception("cyber_scorer_user_fetch_failed", extra={"user_id": user_id})
        phone_verified = False

    # ── 3. Trusted contacts ───────────────────────────────────────────────────

    try:
        trusted_count: int = db.execute(
            text(
                """
                SELECT COUNT(*) FROM trusted_contacts
                WHERE owner_user_id = CAST(:uid AS uuid) AND status = 'ACTIVE'
                """
            ),
            {"uid": user_id},
        ).scalar() or 0
    except Exception:
        trusted_count = 0

    # ── 4. Recent alert events (proxy for monitoring being active) ────────────

    try:
        alert_count: int = db.execute(
            text(
                """
                SELECT COUNT(*) FROM alert_events
                WHERE user_id = CAST(:uid AS uuid)
                  AND created_at >= :since
                """
            ),
            {"uid": user_id, "since": ago_30},
        ).scalar() or 0
    except Exception:
        alert_count = 0

    # =========================================================================
    # COMPONENT A — EXPOSURE RISK  (deduction 0–400)
    # =========================================================================

    exp_deduction = 0

    # Email breaches
    high_email = [r for r in email_scans if _risk(r) == "high"]
    med_email  = [r for r in email_scans if _risk(r) == "medium"]
    email_exp  = min(len(high_email) * 50 + len(med_email) * 20, 200)
    exp_deduction += email_exp

    if high_email:
        count = len(high_email)
        insights.append(
            f"Your email was found in {count} data breach{'es' if count > 1 else ''} — "
            "change your linked account passwords now"
        )
    elif med_email:
        insights.append(
            "Your email appeared in a minor breach — monitor your accounts for unusual activity"
        )

    # Password strength
    high_pw = [r for r in password_scans if _risk(r) == "high"]
    med_pw  = [r for r in password_scans if _risk(r) == "medium"]
    pw_exp  = min(len(high_pw) * 80 + len(med_pw) * 30, 160)
    exp_deduction += pw_exp

    if high_pw:
        insights.append(
            "A weak or compromised password was detected — update it immediately"
        )
        actions.append({
            "id": "scan_password",
            "title": "Scan your password again",
            "subtitle": "Confirm your password is now secure",
            "icon": "lock",
            "priority": 0,
        })
    elif med_pw:
        insights.append("Your password strength could be improved — consider using a stronger one")

    exp_deduction = min(exp_deduction, 400)
    factors["exposure"] = {
        "deduction": exp_deduction,
        "email_breaches_high": len(high_email),
        "email_breaches_medium": len(med_email),
        "weak_passwords": len(high_pw),
        "medium_passwords": len(med_pw),
    }

    # =========================================================================
    # COMPONENT B — BEHAVIOR RISK  (deduction 0–250)
    # =========================================================================

    beh_deduction = 0

    high_threats = [r for r in threat_scans if _risk(r) == "high"]
    med_threats  = [r for r in threat_scans if _risk(r) == "medium"]
    threat_ded   = len(high_threats) * 70 + len(med_threats) * 30
    if len(high_threats) >= 3:
        threat_ded += 50  # repeated risky-scan pattern penalty
    beh_deduction += min(threat_ded, 200)

    high_qr  = [r for r in qr_scans if _risk(r) == "high"]
    beh_deduction += min(len(high_qr) * 40, 50)
    beh_deduction = min(beh_deduction, 250)

    if high_threats:
        c = len(high_threats)
        insights.append(
            f"{c} high-risk link{'s' if c > 1 else ''} detected in your recent scans — "
            "avoid clicking unknown links"
        )
    elif med_threats:
        c = len(med_threats)
        insights.append(
            f"{c} suspicious message{'s' if c > 1 else ''} found — stay cautious and verify before trusting"
        )

    if high_qr:
        c = len(high_qr)
        insights.append(
            f"{c} risky QR code{'s' if c > 1 else ''} detected — always verify QR codes before scanning"
        )

    factors["behavior"] = {
        "deduction": beh_deduction,
        "high_risk_scans": len(high_threats),
        "medium_risk_scans": len(med_threats),
        "risky_qr_codes": len(high_qr),
    }

    # =========================================================================
    # COMPONENT C — PROTECTION STRENGTH  (bonus 0–200)
    # =========================================================================

    prot_bonus = 0

    # Phone verified = 2FA proxy (+80)
    if phone_verified:
        prot_bonus += 80
    else:
        insights.append(
            "Phone verification not enabled — add phone verification to strengthen your account"
        )
        actions.append({
            "id": "verify_phone",
            "title": "Verify your phone number",
            "subtitle": "Adds an extra layer of protection to your account",
            "icon": "phone",
            "priority": 1,
        })

    # Trusted contacts (+40 for ≥2, +20 for 1)
    if trusted_count >= 2:
        prot_bonus += 40
    elif trusted_count == 1:
        prot_bonus += 20
        actions.append({
            "id": "add_trusted_contact",
            "title": "Add another trusted contact",
            "subtitle": "2 or more contacts keeps your family safer",
            "icon": "people",
            "priority": 2,
        })
    else:
        insights.append(
            "No trusted contacts added — your account has no safety net in an emergency"
        )
        actions.append({
            "id": "add_trusted_contact",
            "title": "Add a trusted contact",
            "subtitle": "Someone you trust who can help if you're targeted",
            "icon": "people",
            "priority": 1,
        })

    # Alerts received this month (+40 if active, +20 otherwise)
    prot_bonus += 40 if alert_count > 0 else 20

    # Active monitoring: has any scans (+40)
    if scan_rows:
        prot_bonus += 40

    prot_bonus = min(prot_bonus, 200)
    factors["protection"] = {
        "bonus": prot_bonus,
        "phone_verified": phone_verified,
        "trusted_contacts": int(trusted_count),
        "alerts_received": alert_count,
    }

    # =========================================================================
    # COMPONENT D — ACTIVITY COVERAGE  (bonus 0–100)
    #   Eligibility: COUNT(DISTINCT scan_type) >= 2
    # =========================================================================

    covered: set[str] = set()
    if email_scans:    covered.add("email")
    if password_scans: covered.add("password")
    if qr_scans:       covered.add("qr")
    if threat_scans:   covered.add("threat")
    if image_scans:    covered.add("image")

    coverage_n = len(covered)
    act_bonus = (
        100 if coverage_n >= 4 else
         70 if coverage_n == 3 else
         40 if coverage_n == 2 else
         20 if coverage_n == 1 else 0
    )

    if coverage_n == 0:
        insights.append(
            "No scans completed yet — run your first scan to start building your safety score"
        )
        actions.append({
            "id": "scan_now",
            "title": "Run your first scan",
            "subtitle": "Scan a message, link, or QR code to get started",
            "icon": "qr_code_scanner",
            "priority": 0,
        })
    else:
        if "email" not in covered:
            actions.append({
                "id": "scan_email",
                "title": "Check your email for breaches",
                "subtitle": "See if your data was exposed in a leak",
                "icon": "email",
                "priority": 1,
            })
        if "password" not in covered:
            actions.append({
                "id": "scan_password",
                "title": "Scan your password",
                "subtitle": "Check if your password has been compromised",
                "icon": "lock",
                "priority": 1,
            })

    factors["activity"] = {
        "bonus": act_bonus,
        "scan_types_covered": sorted(covered),
        "coverage_count": coverage_n,
        # Eligibility signal: distinct scan types >= 2
        "eligible": coverage_n >= 2,
    }

    # =========================================================================
    # COMPONENT E — CONSISTENCY BONUS  (0–50)
    # =========================================================================

    recent_7  = [r for r in scan_rows if _to_aware(r["created_at"]) and _to_aware(r["created_at"]) >= ago_7]
    recent_14 = [r for r in scan_rows if _to_aware(r["created_at"]) and _to_aware(r["created_at"]) >= ago_14]

    if recent_7:
        con_bonus = 50
        insights.append("You've been scanning regularly this week — keep it up!")
    elif recent_14:
        con_bonus = 20
    else:
        con_bonus = 0
        if scan_rows:
            insights.append(
                "You haven't scanned anything in 2 weeks — run a quick check to stay protected"
            )
            actions.append({
                "id": "resume_scanning",
                "title": "Resume scanning",
                "subtitle": "Stay protected with regular security checks",
                "icon": "refresh",
                "priority": 2,
            })

    factors["consistency"] = {
        "bonus": con_bonus,
        "active_last_7_days": bool(recent_7),
        "active_last_14_days": bool(recent_14),
    }

    # =========================================================================
    # FINAL SCORE
    # =========================================================================

    raw = (
        1000
        - exp_deduction
        - beh_deduction
        + prot_bonus
        + act_bonus
        + con_bonus
    )
    score = max(0, min(1000, raw))
    level = _level(score)

    # Positive insight if everything looks clean
    if not insights:
        insights.append("Your account looks clean — no significant threats detected this month")

    # Deduplicate + sort actions by priority (cap at 4)
    seen: set[str] = set()
    deduped: list[dict] = []
    for a in sorted(actions, key=lambda x: x.get("priority", 9)):
        if a["id"] not in seen:
            seen.add(a["id"])
            deduped.append(a)
    actions = deduped[:4]

    return {
        "score":       score,
        "level":       level,
        "factors":     factors,
        "insights":    insights,
        "actions":     actions,
        "computed_at": now.isoformat(),
    }
