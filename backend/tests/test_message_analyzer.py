"""Tests for message detection rules."""

from app.detection.message_analyzer import analyze_message_rules


def test_fake_banking_kyc_message():
    """Urgent fake KYC messages should be flagged with high severity."""
    msg = "Dear customer, your bank account will be blocked. Complete KYC immediately to avoid suspension."
    findings = analyze_message_rules(msg)
    titles = [f.title for f in findings]
    assert any("KYC" in t for t in titles)
    assert any("Suspension" in t or "Blocking" in t for t in titles)


def test_fake_upi_reward_message():
    """Fake cashback and lottery lures must be detected."""
    msg = "Congratulations! You have won cashback of Rs 5000 in lucky draw. Enter your UPI PIN to claim."
    findings = analyze_message_rules(msg)
    titles = [f.title for f in findings]
    assert any("Reward" in t or "Cashback" in t for t in titles)
    assert any("UPI" in t for t in titles)


def test_fake_job_offer():
    """High-paying remote job with registration fee lure must be detected."""
    msg = "Part time job work from home. Earn Rs 4000 daily by watching videos. Pay registration fee Rs 299."
    findings = analyze_message_rules(msg)
    assert any("Job" in f.title for f in findings)


def test_otp_theft_message():
    """Requests to disclose OTP must be flagged as critical."""
    msg = "Share your OTP with our verification executive to unblock your card."
    findings = analyze_message_rules(msg)
    assert any("OTP" in f.title for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_benign_payment_message():
    """Legitimate receipts/transaction alerts should not trigger scam findings."""
    msg = "Your salary for October has been credited. Current account balance is Rs 55,000. HDFC Bank."
    findings = analyze_message_rules(msg)
    assert len(findings) == 0
