"""PhishShield X - Central Risk Scoring Engine

The SOLE authoritative risk-scoring engine in the platform.
Enforces strict mathematical bounds, category caps, finding deduplication,
and deterministic risk level mapping.
"""

from typing import Dict, List, Set, Tuple
from app.schemas.findings import FindingCategory, FindingSeverity, ScanFindingResponse
from app.schemas.scan import RiskLevel

# Strict category scoring caps (Sum = 100 maximum)
CATEGORY_CAPS: Dict[str, int] = {
    FindingCategory.URL.value: 25,
    FindingCategory.IDENTITY.value: 20,
    FindingCategory.SEMANTIC.value: 25,
    FindingCategory.BEHAVIOR.value: 20,
    FindingCategory.REPUTATION.value: 10,
}

VALID_CATEGORIES: Set[str] = set(CATEGORY_CAPS.keys())
VALID_SEVERITIES: Set[str] = {
    FindingSeverity.LOW.value,
    FindingSeverity.MEDIUM.value,
    FindingSeverity.HIGH.value,
    FindingSeverity.CRITICAL.value,
}


def compute_risk_level(score: int) -> str:
    """Map deterministic integer score (0-100) to agreed standard risk level.
    
    0–19: LOW
    20–39: MODERATE
    40–59: SUSPICIOUS
    60–79: HIGH
    80–100: CRITICAL
    """
    if score >= 80:
        return RiskLevel.CRITICAL.value
    if score >= 60:
        return RiskLevel.HIGH.value
    if score >= 40:
        return RiskLevel.SUSPICIOUS.value
    if score >= 20:
        return RiskLevel.MODERATE.value
    return RiskLevel.LOW.value


def deduplicate_findings(findings: List[ScanFindingResponse]) -> List[ScanFindingResponse]:
    """Deduplicate findings based on normalized category and title.
    
    Retains the finding with higher points if duplicates exist.
    """
    unique_map: Dict[Tuple[str, str], ScanFindingResponse] = {}
    for f in findings:
        cat = f.category.lower().strip()
        title_key = f.title.lower().strip()
        key = (cat, title_key)
        if key in unique_map:
            if f.points > unique_map[key].points:
                unique_map[key] = f
        else:
            unique_map[key] = f
    return list(unique_map.values())


def generate_threat_summary(risk_level: str, findings: List[ScanFindingResponse], target_type: str) -> str:
    """Generate concise, professional summary for the scan."""
    if not findings or risk_level == RiskLevel.LOW.value:
        if target_type == "url":
            return "No prominent phishing or impersonation indicators were detected on this website."
        return "No coercive social-engineering or phishing triggers were detected in this message."

    critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL.value)
    high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH.value)

    if risk_level == RiskLevel.CRITICAL.value:
        top_finding = findings[0].title if findings else "Critical threats detected"
        return f"CRITICAL THREAT: Severe phishing indicators detected. Key risk: {top_finding}."

    if risk_level == RiskLevel.HIGH.value:
        return f"HIGH RISK: Detected {len(findings)} suspicious indicator(s) including {critical_count + high_count} severe signals."

    if risk_level == RiskLevel.SUSPICIOUS.value:
        return f"SUSPICIOUS: Identified potential threat signals ({len(findings)} finding(s)). Exercise elevated caution."

    return f"MODERATE RISK: Minor anomalous indicators observed ({len(findings)} finding(s)). Proceed with awareness."


def generate_recommended_action(risk_level: str, target_type: str) -> str:
    """Generate clear, non-jargon safety advice based on authoritative risk level."""
    if risk_level == RiskLevel.CRITICAL.value:
        if target_type == "url":
            return "DO NOT interact with this website. Do not enter credentials, OTPs, or payment details. Close the browser tab immediately."
        return "DO NOT reply, click links, or share any OTP or financial information. Block the sender immediately."

    if risk_level == RiskLevel.HIGH.value:
        if target_type == "url":
            return "Avoid providing personal data or payment credentials. Verify the official web address through an independent search."
        return "Do not click any embedded links or follow payment instructions. Contact the institution via verified official numbers."

    if risk_level == RiskLevel.SUSPICIOUS.value:
        if target_type == "url":
            return "Verify the SSL certificate and domain authenticity before entering login details or sensitive records."
        return "Treat this message with caution. Verify the sender's identity through official channels before taking action."

    if risk_level == RiskLevel.MODERATE.value:
        return "Review the website or message carefully. Ensure URL matches the expected organization domain."

    return "Safe to browse. Continue adhering to standard security best practices."


def calculate_risk_assessment(
    raw_findings: List[ScanFindingResponse],
    target_type: str,
) -> Tuple[int, str, List[ScanFindingResponse], str, str]:
    """Execute authoritative risk scoring on raw findings.
    
    Returns:
        (risk_score, risk_level, validated_findings, summary, recommended_action)
    """
    # 1. Validate category and severity, reject invalid/unsupported entries
    sanitized_findings: List[ScanFindingResponse] = []
    for f in raw_findings:
        cat = f.category.lower().strip()
        sev = f.severity.lower().strip()

        # Reject unsupported or blank evidence
        if not f.evidence or not f.evidence.strip():
            continue

        if cat not in VALID_CATEGORIES:
            cat = FindingCategory.SEMANTIC.value

        if sev not in VALID_SEVERITIES:
            sev = FindingSeverity.MEDIUM.value

        # Ensure points are non-negative
        pts = max(0, int(f.points))

        sanitized_findings.append(
            ScanFindingResponse(
                id=f.id,
                category=cat,
                severity=sev,
                points=pts,
                title=f.title.strip(),
                evidence=f.evidence.strip(),
                explanation=f.explanation.strip(),
            )
        )

    # 2. Deduplicate overlapping findings
    deduped = deduplicate_findings(sanitized_findings)

    # 3. Enforce category caps
    category_totals: Dict[str, int] = {cat: 0 for cat in VALID_CATEGORIES}
    for f in deduped:
        category_totals[f.category] += f.points

    # Cap points per category
    capped_category_scores: Dict[str, int] = {}
    for cat, total in category_totals.items():
        cap = CATEGORY_CAPS[cat]
        capped_category_scores[cat] = min(total, cap)

    # 4. Total aggregate score (Max 100)
    raw_total_score = sum(capped_category_scores.values())
    final_score = min(max(0, raw_total_score), 100)

    # 5. Determine Risk Level
    final_risk_level = compute_risk_level(final_score)

    # Sort findings by points descending
    sorted_findings = sorted(deduped, key=lambda x: x.points, reverse=True)

    # 6. Generate Contextual Threat Summary & Recommendations
    summary = generate_threat_summary(final_risk_level, sorted_findings, target_type)
    action = generate_recommended_action(final_risk_level, target_type)

    return final_score, final_risk_level, sorted_findings, summary, action
