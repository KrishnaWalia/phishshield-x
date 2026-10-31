"""Tests for central risk engine, category caps, deduplication, and thresholds."""

from app.schemas.findings import ScanFindingResponse
from app.detection.risk_engine import (
    calculate_risk_assessment,
    compute_risk_level,
    deduplicate_findings,
    CATEGORY_CAPS,
)


def test_compute_risk_level_thresholds():
    """Verify strict mapping of scores to risk levels."""
    assert compute_risk_level(0) == "LOW"
    assert compute_risk_level(19) == "LOW"
    assert compute_risk_level(20) == "MODERATE"
    assert compute_risk_level(39) == "MODERATE"
    assert compute_risk_level(40) == "SUSPICIOUS"
    assert compute_risk_level(59) == "SUSPICIOUS"
    assert compute_risk_level(60) == "HIGH"
    assert compute_risk_level(79) == "HIGH"
    assert compute_risk_level(80) == "CRITICAL"
    assert compute_risk_level(100) == "CRITICAL"


def test_deduplicate_duplicate_findings():
    """Findings with same category and title should be deduplicated."""
    findings = [
        ScanFindingResponse(
            id="f1",
            category="url",
            severity="medium",
            points=10,
            title="Suspicious domain structure",
            evidence="Observed hyphenated domain",
            explanation="Domain contains confusing hyphens",
        ),
        ScanFindingResponse(
            id="f2",
            category="url",
            severity="high",
            points=15,
            title="Suspicious domain structure",
            evidence="Observed multiple hyphens",
            explanation="Domain contains confusing hyphens",
        ),
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    # Retains higher points
    assert deduped[0].points == 15


def test_category_scoring_caps():
    """Points in a single category must not exceed its cap."""
    # Add url findings that total 50 points (cap is 25)
    findings = [
        ScanFindingResponse(
            id=f"url_{i}",
            category="url",
            severity="high",
            points=15,
            title=f"URL Issue {i}",
            evidence=f"Evidence {i}",
            explanation=f"Explanation {i}",
        )
        for i in range(4)
    ]
    score, level, final_findings, summary, action = calculate_risk_assessment(findings, "url")
    assert score == CATEGORY_CAPS["url"]  # Must be strictly 25, not 60
    assert score == 25
    assert level == "MODERATE"


def test_total_score_cap_at_100():
    """Even if all categories exceed their caps, total score must cap at 100."""
    findings = []
    # Fill each category to exceed cap
    for cat in ["url", "identity", "semantic", "behavior", "reputation"]:
        for i in range(3):
            findings.append(
                ScanFindingResponse(
                    id=f"{cat}_{i}",
                    category=cat,
                    severity="critical",
                    points=30,
                    title=f"Critical {cat} signal {i}",
                    evidence=f"Evidence for {cat} {i}",
                    explanation=f"Explanation for {cat} {i}",
                )
            )

    score, level, final_findings, summary, action = calculate_risk_assessment(findings, "message")
    assert score == 100
    assert level == "CRITICAL"
