"""PhishShield X - Message Detection Engine

Performs comprehensive heuristic and pattern-matching analysis on suspicious communications
(SMS, WhatsApp, Email, social engineering messages).
Detects:
1. Fake KYC / PAN / Aadhaar threats
2. Account suspension / blocking urgency
3. OTP / Password / PIN theft requests
4. Payment pressure & fraudulent transaction claims
5. Fake rewards, lotteries, and cashback lures
6. Fake job offers requiring upfront registration fees
7. Authority impersonation
"""

import re
from typing import List, Tuple
from app.schemas.findings import FindingCategory, FindingSeverity, ScanFindingResponse

# Pattern matching definitions: (regex, points, category, severity, title, explanation)
MESSAGE_PATTERNS: List[Tuple[re.Pattern, int, str, str, str, str]] = [
    # 1. Fake KYC / Document Verification Scams
    (
        re.compile(r"\b(?:kyc\s*(?:expired|suspended|pending|incomplete|update|verification)|complete\s*kyc|verify\s*(?:your\s*)?kyc|update\s*pan|link\s*aadhaar)\b", re.I),
        20,
        FindingCategory.SEMANTIC.value,
        FindingSeverity.CRITICAL.value,
        "Fake KYC / Document Update Demand",
        "Legitimate banks never mandate urgent KYC verification via SMS or unofficial third-party links. This is a common tactic to hijack banking profiles.",
    ),
    # 2. Account Suspension & Immediate Blocking Urgency
    (
        re.compile(r"\b(?:account\s*(?:will\s*be|is)\s*(?:blocked|suspended|terminated|deactivated)|freeze\s*your\s*account|within\s*(?:24|12|2|1)\s*hours?|immediately\s*(?:to\s*avoid|or))\b", re.I),
        18,
        FindingCategory.BEHAVIOR.value,
        FindingSeverity.HIGH.value,
        "Coercive Account Suspension Threat",
        "Threatening immediate account deactivation creates panic to compel victims into clicking malicious links without verifying authenticity.",
    ),
    # 3. OTP / PIN / Credential Theft
    (
        re.compile(r"\b(?:share\s*(?:your\s*)?(?:otp|one\s*time\s*password|pin|upi\s*pin|password|cvv)|enter\s*(?:your\s*)?(?:otp|pin|upi\s*pin|credentials)|send\s*(?:the\s*)?(?:6|4)[-\s]*digit\s*code)\b", re.I),
        25,
        FindingCategory.SEMANTIC.value,
        FindingSeverity.CRITICAL.value,
        "Direct OTP / Security PIN Theft Solicitation",
        "Official financial institutions strictly prohibit staff from asking for OTPs or PINs. Disclosing a PIN or OTP authorizes irreversible transactions or complete account takeover.",
    ),
    # 4. UPI / Payment Reversal & Unauthorized Charges
    (
        re.compile(r"\b(?:unauthorized\s*(?:transaction|debit|payment)|debited\s*by\s*(?:rs|inr|\$)|call\s*customer\s*care\s*to\s*cancel|refund\s*(?:pending|credited))\b", re.I),
        15,
        FindingCategory.BEHAVIOR.value,
        FindingSeverity.HIGH.value,
        "False Transaction / Refund Baiting",
        "Simulating unauthorized charges provokes fear, driving recipients to contact fake support helplines or enter credentials into phishing portals.",
    ),
    # 5. Fake Rewards, Lottery & Cashback Lures
    (
        re.compile(r"\b(?:congratulations|you\s*(?:have\s*)?won|cashback\s*of\s*(?:rs|inr|\$|\d+)|lottery|scratch\s*card|claim\s*your\s*(?:prize|reward|gift\s*voucher)|free\s*(?:recharge|iphone))\b", re.I),
        15,
        FindingCategory.SEMANTIC.value,
        FindingSeverity.MEDIUM.value,
        "Unsolicited Reward or Cashback Lure",
        "Promises of unearned cash rewards or prizes are used to entice victims into initiating payment requests or surrendering personal details.",
    ),
    # 6. UPI PIN to Receive Money Deception
    (
        re.compile(r"\b(?:enter\s*(?:your\s*)?upi\s*pin\s*to\s*(?:receive|claim|accept)|scan\s*qr\s*to\s*receive\s*money)\b", re.I),
        25,
        FindingCategory.BEHAVIOR.value,
        FindingSeverity.CRITICAL.value,
        "Reverse UPI Scam (PIN Required to Receive)",
        "Under the UPI protocol, entering a PIN is ONLY required to deduct money from your account, NEVER to receive funds. This is a predatory fraud.",
    ),
    # 7. Payment Platform / UPI Exploitation Indicator
    (
        re.compile(r"\b(?:phonepe|paytm|gpay|google\s*pay|bhim|upi)\b", re.I),
        15,
        FindingCategory.IDENTITY.value,
        FindingSeverity.MEDIUM.value,
        "Payment Platform Identity Context",
        "The message invokes digital payment platforms (UPI/Wallets) to lend credibility to an unsolicited financial transaction or reward claim.",
    ),
    # 8. Advance Fee / Registration Fee Fraud (Employment & Task Scams)
    (
        re.compile(r"\b(?:registration\s*fee|processing\s*fee|security\s*deposit|pay\s*(?:rs|inr|\$)?\s*\d+\s*(?:only|to\s*(?:join|start|register|apply))|upfront\s*(?:fee|payment|charge)|pay\s*fee\s*to\s*receive)\b", re.I),
        20,
        FindingCategory.BEHAVIOR.value,
        FindingSeverity.HIGH.value,
        "Advance Fee / Registration Payment Demand",
        "Legitimate employers never demand registration fees or security deposits to start work. Upfront fee demands are a classic hallmark of employment advance-fee fraud.",
    ),
    # 9. Fake Part-time / Remote Job Offer
    (
        re.compile(r"\b(?:part[-\s]*time\s*job|work\s*from\s*home|earn\s*(?:rs|inr|\$)?\s*\d{3,5}\s*(?:daily|per\s*day)|telegram\s*task|youtube\s*like\s*(?:and|&)\s*subscribe)\b", re.I),
        20,
        FindingCategory.SEMANTIC.value,
        FindingSeverity.HIGH.value,
        "Predatory Task / Part-Time Job Scam",
        "Unrealistic daily earnings for simple online tasks typically lead to investment or deposit fraud where victims are asked to pay registration fees.",
    ),
    # 10. Unofficial / Shortened Links embedded in message
    (
        re.compile(r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|wa\.me|t\.me)\b|https?://[^\s]+", re.I),
        12,
        FindingCategory.URL.value,
        FindingSeverity.MEDIUM.value,
        "Embedded Link / URL Shortener in Message",
        "URL shorteners and untrusted links in unsolicited messages are utilized to hide the actual malicious landing destination.",
    ),
    # 11. Institutional Impersonation (RBI, Income Tax, Electricity Board, Police)
    (
        re.compile(r"\b(?:reserve\s*bank\s*of\s*india|rbi\s*alert|income\s*tax\s*department|electricity\s*(?:will\s*be\s*disconnected|bill\s*unpaid)|police\s*notice|cyber\s*crime\s*cell)\b", re.I),
        15,
        FindingCategory.IDENTITY.value,
        FindingSeverity.HIGH.value,
        "Public Authority / Utility Impersonation",
        "Posing as utility providers or government law enforcement exploits institutional authority to coerce compliance.",
    ),
]


def analyze_message_rules(text: str) -> List[ScanFindingResponse]:
    """Execute rule-based pattern matching on message content.
    
    Returns structured findings with concrete evidence snippets.
    """
    findings: List[ScanFindingResponse] = []
    finding_counter = 1

    def make_id(prefix: str = "msg") -> str:
        nonlocal finding_counter
        fid = f"{prefix}_{finding_counter:03d}"
        finding_counter += 1
        return fid

    for pattern, pts, category, severity, title, explanation in MESSAGE_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_phrase = match.group(0)
            # Find snippet context around match
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 20)
            evidence_snippet = f"...{text[start:end].strip()}..."

            findings.append(
                ScanFindingResponse(
                    id=make_id("msg"),
                    category=category,
                    severity=severity,
                    points=pts,
                    title=title,
                    evidence=f"Matched trigger '{matched_phrase}': {evidence_snippet}",
                    explanation=explanation,
                )
            )

    return findings
