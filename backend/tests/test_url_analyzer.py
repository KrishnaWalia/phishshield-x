"""Tests for URL detection engine."""

from app.detection.url_analyzer import analyze_url


def test_legitimate_website():
    """Legitimate well-known domains should trigger zero or low findings."""
    url = "https://www.google.com"
    findings = analyze_url(url=url)
    assert len(findings) == 0


def test_ip_based_url():
    """Direct IP address hosts must trigger high severity finding."""
    url = "http://192.168.1.100/login"
    findings = analyze_url(url=url)
    ip_findings = [f for f in findings if "IP address" in f.title]
    assert len(ip_findings) == 1
    assert ip_findings[0].category == "url"
    assert ip_findings[0].severity == "high"


def test_brand_impersonation_in_subdomain():
    """Brand in subdomain of unauthorized domain must trigger identity finding."""
    url = "https://paypal.com.account-verification-portal.xyz/signin"
    findings = analyze_url(url=url)
    identity_findings = [f for f in findings if f.category == "identity"]
    assert len(identity_findings) >= 1
    assert "PAYPAL" in identity_findings[0].title.upper()


def test_punycode_homograph():
    """Punycode domains must trigger homograph finding."""
    url = "https://xn--pple-43d.com/login"
    findings = analyze_url(url=url)
    puny_findings = [f for f in findings if "Punycode" in f.title]
    assert len(puny_findings) == 1


def test_excessive_subdomains():
    """Three or more subdomain levels should be flagged."""
    url = "https://secure.login.portal.verify.banking.attacker.net/auth"
    findings = analyze_url(url=url)
    sub_findings = [f for f in findings if "subdomain" in f.title.lower()]
    assert len(sub_findings) >= 1


def test_suspicious_tld():
    """High-abuse TLDs like .xyz should be flagged."""
    url = "https://fast-rewards-claim.xyz/bonus"
    findings = analyze_url(url=url)
    tld_findings = [f for f in findings if "TLD" in f.title]
    assert len(tld_findings) == 1
