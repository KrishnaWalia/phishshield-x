"""PhishShield X - URL Detection Engine

Analyzes URLs, domain anatomy, page titles, and anchor links for phishing indicators.
Strictly local analysis — NEVER performs outbound HTTP requests or SSRF browsing.
"""

from typing import List, Optional
from urllib.parse import urlparse, parse_qs
from app.schemas.findings import FindingCategory, FindingSeverity, ScanFindingResponse
from app.core.security import clean_invisible_characters, scrub_sensitive_content
from app.detection.feature_extractor import (
    extract_domain_components,
    is_ip_address,
    calculate_entropy,
    check_brand_impersonation,
    has_unicode_homoglyphs,
    normalize_homoglyphs_and_leetspeak,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
    HIGH_PROFILE_BRANDS,
)


def analyze_url(
    url: str,
    page_title: Optional[str] = None,
    page_text: Optional[str] = None,
    links: Optional[List[str]] = None,
) -> List[ScanFindingResponse]:
    """Execute rule-based and structural heuristic checks on a given URL.
    
    Returns a list of structured findings conforming to ScanFindingResponse.
    """
    findings: List[ScanFindingResponse] = []
    finding_counter = 1

    def make_id(prefix: str = "url") -> str:
        nonlocal finding_counter
        fid = f"{prefix}_{finding_counter:03d}"
        finding_counter += 1
        return fid

    parsed = urlparse(url)
    # Strip userinfo (e.g. user:pass@host) to extract true host
    host = parsed.netloc.split("@")[-1].split(":")[0].strip()
    path = parsed.path
    query = parsed.query
    domain_info = extract_domain_components(url)

    # 1. IP Address as Host Check (including integer/decimal, hex, octal)
    if is_ip_address(host):
        is_obfuscated_ip = host.isdigit() or host.lower().startswith("0x") or (host.count(".") != 3 and ":" not in host)
        pts = 25 if is_obfuscated_ip else 20
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.CRITICAL.value if is_obfuscated_ip else FindingSeverity.HIGH.value,
                points=pts,
                title="IP address used as hostname" if not is_obfuscated_ip else "Obfuscated decimal/hex IP address host",
                evidence=f"Hostname is a direct or obfuscated numeric IP address: '{host}'",
                explanation=(
                    "Legitimate commercial websites almost always use named domain names. "
                    "Decimal/integer and hex IP representations are used by phishing kits "
                    "to circumvent domain reputation filters."
                ),
            )
        )
        if is_obfuscated_ip:
            findings.append(
                ScanFindingResponse(
                    id=make_id("behavior"),
                    category=FindingCategory.BEHAVIOR.value,
                    severity=FindingSeverity.HIGH.value,
                    points=18,
                    title="Obfuscated integer/hex IP evasion",
                    evidence=f"Host '{host}' bypasses standard DNS using raw numeric IP encoding",
                    explanation="Encoding IP addresses as 32-bit integers or hexadecimal values is an evasive obfuscation technique.",
                )
            )

    # 2. Punycode / Cyrillic / Internationalized Homograph Attack
    is_punycode = "xn--" in host.lower()
    is_unicode_homoglyph = has_unicode_homoglyphs(host)
    if is_punycode or is_unicode_homoglyph:
        findings.append(
            ScanFindingResponse(
                id=make_id("identity"),
                category=FindingCategory.IDENTITY.value,
                severity=FindingSeverity.CRITICAL.value,
                points=20,
                title="Punycode/Cyrillic homoglyph domain spoofing",
                evidence=f"Host uses internationalized/Cyrillic lookalike characters: '{host}'",
                explanation=(
                    "The domain uses lookalike characters from Cyrillic or non-Latin alphabets "
                    "(homoglyph attack) that appear visually identical to standard brand names to deceive users."
                ),
            )
        )
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.HIGH.value,
                points=18,
                title="Internationalized domain (IDN) deceptive encoding",
                evidence=f"Host contains internationalized characters: '{host}'",
                explanation="Internationalized domains are used in visual impersonation attacks.",
            )
        )

    # 3. Userinfo '@' Symbol Deception (e.g. paypal.com@evil.xyz)
    if "@" in parsed.netloc:
        userinfo_part = parsed.netloc.split("@")[0]
        actual_host = parsed.netloc.split("@")[-1]
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.CRITICAL.value,
                points=22,
                title="Deceptive userinfo '@' symbol used to spoof destination",
                evidence=f"URL uses userinfo prefix '{userinfo_part}@' to deceive users into trusting fake host '{actual_host}'",
                explanation=(
                    "The '@' character in a URL treats everything before it as login credentials, "
                    "tricking users into believing they are visiting the brand displayed before the '@'."
                ),
            )
        )

    # 3. Excessive URL Length
    url_len = len(url)
    if url_len > 120:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.MEDIUM.value,
                points=10,
                title="Excessive URL length",
                evidence=f"URL length is {url_len} characters (threshold: 120)",
                explanation=(
                    "Phishing URLs often pack lengthy obfuscated tokens, redirects, and padding "
                    "to obscure the real destination in browser address bars."
                ),
            )
        )
    elif url_len > 80:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.LOW.value,
                points=5,
                title="Elevated URL length",
                evidence=f"URL length is {url_len} characters",
                explanation="Lengthy URLs can be used to hide suspicious path and query segments.",
            )
        )

    # 4. Excessive Subdomains (Domain hierarchy confusion)
    subdomain = domain_info.get("subdomain", "")
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    if len(subdomain_parts) >= 3:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.HIGH.value,
                points=16,
                title="Excessive subdomain nesting",
                evidence=f"Observed {len(subdomain_parts)} subdomains: '{subdomain}'",
                explanation=(
                    "Attackers often stack multiple subdomains (e.g., login.chase.com.security.site.xyz) "
                    "to trick users into seeing trusted brand names on small screen displays."
                ),
            )
        )
    elif len(subdomain_parts) == 2:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.LOW.value,
                points=5,
                title="Multiple subdomain levels",
                evidence=f"Observed 2 subdomain levels: '{subdomain}'",
                explanation="Multiple subdomains can sometimes be used to obscure the primary registered domain.",
            )
        )

    # 5. Suspicious Top-Level Domain (TLD)
    suffix = domain_info.get("suffix", "")
    if suffix in SUSPICIOUS_TLDS:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.MEDIUM.value,
                points=12,
                title="High-risk TLD detected",
                evidence=f"Domain uses high-abuse top-level domain '.{suffix}'",
                explanation=(
                    f"The '.{suffix}' extension is frequently abused in automated disposable phishing "
                    "campaigns due to negligible registration costs."
                ),
            )
        )

    # 6. Brand Impersonation (Identity Spoofing)
    impersonation = check_brand_impersonation(url, domain_info)
    if impersonation:
        findings.append(
            ScanFindingResponse(
                id=make_id("identity"),
                category=FindingCategory.IDENTITY.value,
                severity=FindingSeverity.CRITICAL.value,
                points=20,
                title=f"Brand impersonation detected ({impersonation['brand'].upper()})",
                evidence=impersonation["evidence"],
                explanation=(
                    f"The URL references the brand '{impersonation['brand'].capitalize()}' while hosted on "
                    f"an unauthorized domain. This is a primary indicator of a credential-harvesting phishing site."
                ),
            )
        )

    # 7. Suspicious Characters (@ symbol, double slashes in path, hyphens in domain)
    if "@" in parsed.netloc:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.HIGH.value,
                points=18,
                title="URL contains userinfo '@' symbol",
                evidence=f"Host component contains '@': '{parsed.netloc}'",
                explanation=(
                    "The '@' character in a URL treats everything before it as login credentials, "
                    "obscuring the actual destination host that follows."
                ),
            )
        )

    registered_domain = domain_info.get("domain", "")
    if registered_domain.count("-") >= 2:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.MEDIUM.value,
                points=10,
                title="Multiple hyphens in domain name",
                evidence=f"Domain '{registered_domain}' contains {registered_domain.count('-')} hyphens",
                explanation=(
                    "Typosquatting and fake portal websites frequently use hyphenated keywords "
                    "(e.g., sbi-online-portal-kyc) to simulate official service names."
                ),
            )
        )

    # 8. High Entropy in Host / Subdomain
    host_entropy = calculate_entropy(host)
    if host_entropy > 3.8 and len(host) > 15:
        findings.append(
            ScanFindingResponse(
                id=make_id("url"),
                category=FindingCategory.URL.value,
                severity=FindingSeverity.LOW.value,
                points=6,
                title="High lexical randomness in hostname",
                evidence=f"Hostname entropy is {host_entropy} bits",
                explanation="High entropy suggests algorithmically generated domains (DGA) or disposable hosts.",
            )
        )

    # 9. Suspicious Path & Query Keywords (Credential / Action harvesting)
    combined_path_query = (path + " " + query).lower()
    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined_path_query]
    if len(detected_keywords) >= 3:
        findings.append(
            ScanFindingResponse(
                id=make_id("behavior"),
                category=FindingCategory.BEHAVIOR.value,
                severity=FindingSeverity.HIGH.value,
                points=15,
                title="Multiple auth/financial action keywords in path",
                evidence=f"Detected keywords: {', '.join(detected_keywords[:5])}",
                explanation=(
                    "The URL path contains multiple high-value targets such as login, KYC, and verification, "
                    "typical of phishing lures designed to steal account credentials."
                ),
            )
        )
    elif len(detected_keywords) >= 1:
        findings.append(
            ScanFindingResponse(
                id=make_id("behavior"),
                category=FindingCategory.BEHAVIOR.value,
                severity=FindingSeverity.LOW.value,
                points=5,
                title="Auth/verification keyword in URL",
                evidence=f"Detected keyword: '{detected_keywords[0]}'",
                explanation="The URL points to an authentication or verification workflow.",
            )
        )

    # 10. Open Redirect / External Target Query Parameters
    parsed_query = parse_qs(query)
    suspicious_params = {"redirect", "url", "next", "dest", "destination", "target", "link", "out"}
    for param in suspicious_params:
        if param in parsed_query:
            val = parsed_query[param][0]
            if val.startswith("http://") or val.startswith("https://") or "//" in val:
                findings.append(
                    ScanFindingResponse(
                        id=make_id("behavior"),
                        category=FindingCategory.BEHAVIOR.value,
                        severity=FindingSeverity.MEDIUM.value,
                        points=12,
                        title="Potential open redirect parameter",
                        evidence=f"Parameter '{param}' contains target: '{val[:60]}'",
                        explanation=(
                            "Open redirects permit attackers to exploit legitimate domain trust "
                            "to forward unsuspecting victims to malicious phishing pages."
                        ),
                    )
                )
                break

    # 11. Insecure Protocol Context (HTTP with sensitive keywords)
    is_https = parsed.scheme.lower() == "https"
    if not is_https:
        if any(kw in combined_path_query for kw in ["login", "signin", "bank", "account", "kyc", "otp"]):
            findings.append(
                ScanFindingResponse(
                    id=make_id("url"),
                    category=FindingCategory.URL.value,
                    severity=FindingSeverity.HIGH.value,
                    points=15,
                    title="Insecure HTTP used on sensitive auth/banking endpoint",
                    evidence=f"URL uses unencrypted 'http://' with authentication keyword in path",
                    explanation=(
                        "Legitimate banking and login portals enforce HTTPS. Submitting credentials over "
                        "plain HTTP exposes sensitive passwords and tokens in cleartext to interceptors."
                    ),
                )
            )
        else:
            findings.append(
                ScanFindingResponse(
                    id=make_id("url"),
                    category=FindingCategory.URL.value,
                    severity=FindingSeverity.LOW.value,
                    points=5,
                    title="Unencrypted HTTP protocol",
                    evidence="Connection uses plain http:// without TLS encryption",
                    explanation="Modern reputable web services mandate HTTPS encryption by default.",
                )
            )

    # 12. Page Title & Page Text Heuristic Correlation (if supplied by extension)
    if page_title:
        title_lower = page_title.lower()
        for brand, legit_domains in HIGH_PROFILE_BRANDS.items():
            if brand in title_lower and domain_info.get("registered_domain") not in legit_domains:
                findings.append(
                    ScanFindingResponse(
                        id=make_id("identity"),
                        category=FindingCategory.IDENTITY.value,
                        severity=FindingSeverity.HIGH.value,
                        points=18,
                        title=f"Page title claims '{brand.capitalize()}' identity on mismatched domain",
                        evidence=f"Page title is '{page_title}' on host '{host}'",
                        explanation=(
                            f"The webpage title claims to belong to '{brand.capitalize()}', "
                            f"yet it is hosted on an unverified domain ('{domain_info.get('registered_domain')}')."
                        ),
                    )
                )
                break

    # 13. Page Text Urgent / Verification Check (if visible text supplied)
    if page_text and len(page_text.strip()) > 10:
        # Import and run message pattern analyzer on webpage text
        from app.detection.message_analyzer import analyze_message_rules
        msg_findings = analyze_message_rules(page_text)
        for mf in msg_findings:
            findings.append(
                ScanFindingResponse(
                    id=make_id("semantic"),
                    category=mf.category,
                    severity=mf.severity,
                    points=mf.points,
                    title=f"{mf.title} (Page Content)",
                    evidence=mf.evidence,
                    explanation=mf.explanation,
                )
            )

    # 14. Anchor Link Analysis (Outbound disparity and sensitive action harvesting)
    if links and len(links) > 0:
        # Check for credential / OTP harvesting links in the page
        for link in links:
            if not link or not isinstance(link, str):
                continue
            l_lower = link.lower()
            if any(term in l_lower for term in ["otp", "submit-otp", "pin", "verify-account", "pan-update", "kyc-update"]):
                findings.append(
                    ScanFindingResponse(
                        id=make_id("behavior"),
                        category=FindingCategory.BEHAVIOR.value,
                        severity=FindingSeverity.HIGH.value,
                        points=18,
                        title="Credential / OTP harvesting link observed",
                        evidence=f"Observed sensitive action link: '{link[:60]}'",
                        explanation="The webpage contains links pointing directly to OTP or credential interception endpoints.",
                    )
                )
                break

        external_mismatched = 0
        total_valid_links = 0
        current_reg_domain = domain_info.get("registered_domain", "")
        for link in links:
            if not link or not isinstance(link, str):
                continue
            l_parsed = urlparse(link.strip())
            if l_parsed.netloc:
                total_valid_links += 1
                link_domain = extract_domain_components(link).get("registered_domain", "")
                if link_domain and link_domain != current_reg_domain:
                    external_mismatched += 1

        if total_valid_links > 5 and (external_mismatched / total_valid_links) > 0.8:
            findings.append(
                ScanFindingResponse(
                    id=make_id("behavior"),
                    category=FindingCategory.BEHAVIOR.value,
                    severity=FindingSeverity.MEDIUM.value,
                    points=10,
                    title="Abnormal outbound link disparity",
                    evidence=f"{external_mismatched}/{total_valid_links} links point to external domains",
                    explanation=(
                        "Phishing templates frequently clone assets or link back to official sites "
                        "while trapping user credentials within the single spoofed login form."
                    ),
                )
            )

    return findings
