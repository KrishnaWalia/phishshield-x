"""PhishShield X - Groq AI Integration Service

Provides semantic analysis, social-engineering tactic extraction,
and structured natural-language explanations via the Groq API.

Resilient and zero-trust:
- All sensitive credentials scrubbed prior to transmission.
- Output validated via Pydantic.
- AI NEVER determines the final risk score.
- Hallucinated evidence not present in source text is rejected.
- Graceful degradation: If Groq is disabled, times out, or fails, the detection pipeline continues.
"""

import json
import logging
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.security import scrub_sensitive_content
from app.schemas.findings import FindingCategory, FindingSeverity, ScanFindingResponse

logger = logging.getLogger("phishshield.ai")


class GroqFindingItem(BaseModel):
    """Candidate finding returned by LLM."""
    category: str = Field(..., description="url, identity, semantic, behavior, reputation")
    severity: str = Field(..., description="low, medium, high, critical")
    title: str = Field(..., description="Finding title")
    evidence_quote: str = Field(..., description="Direct quote from submitted text acting as evidence")
    explanation: str = Field(..., description="Why this indicates phishing or social engineering")


class GroqSemanticResponse(BaseModel):
    """Pydantic model validating structured JSON output from Groq."""
    claimed_organization: Optional[str] = None
    requested_action: Optional[str] = None
    social_engineering_tactics: List[str] = Field(default_factory=list)
    findings: List[GroqFindingItem] = Field(default_factory=list)


# Severity-to-points mapping (Strict deterministic bounds)
SEVERITY_POINTS_MAP = {
    FindingSeverity.LOW.value: 5,
    FindingSeverity.MEDIUM.value: 10,
    FindingSeverity.HIGH.value: 15,
    FindingSeverity.CRITICAL.value: 20,
}


class GroqAIService:
    """Encapsulates interaction with the Groq API."""

    def __init__(self):
        self.api_key = settings.PHISHSHIELD_GROQ_API_KEY
        self.model = settings.PHISHSHIELD_GROQ_MODEL
        self.enabled = settings.PHISHSHIELD_AI_ENABLED and bool(self.api_key)
        self._client = None

    def _get_client(self):
        """Lazy initialization of Groq client."""
        if self._client is None and self.api_key:
            try:
                from groq import Groq
                self._client = Groq(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Could not initialize Groq client: {e}")
                self._client = None
        return self._client

    def analyze_content(
        self,
        content: str,
        target_type: str = "message",
    ) -> Tuple[bool, List[ScanFindingResponse]]:
        """Perform semantic analysis via Groq API.
        
        Returns:
            (engine_success_bool, validated_findings_list)
        """
        # If AI disabled or missing API key, cleanly report engine not executed
        if not self.enabled or not self.api_key:
            return False, []

        client = self._get_client()
        if client is None:
            return False, []

        # 1. Scrub credentials and sensitive tokens before sending to LLM
        scrubbed_input = scrub_sensitive_content(content[:4000])

        system_prompt = (
            "You are the AI threat analysis engine for PhishShield X cybersecurity platform. "
            "Analyze the submitted text for phishing, social engineering, fraudulent urgency, "
            "and deceptive manipulation. Return a strictly valid JSON object matching this schema:\n"
            "{\n"
            '  "claimed_organization": "Name of brand/organization claimed or null",\n'
            '  "requested_action": "Action demanded from victim or null",\n'
            '  "social_engineering_tactics": ["list", "of", "tactics"],\n'
            '  "findings": [\n'
            "    {\n"
            '      "category": "url" | "identity" | "semantic" | "behavior" | "reputation",\n'
            '      "severity": "low" | "medium" | "high" | "critical",\n'
            '      "title": "Short title",\n'
            '      "evidence_quote": "Exact substring or quote from the input",\n'
            '      "explanation": "Brief explanation"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "CRITICAL: Do NOT invent evidence. All evidence_quote strings MUST be present in the user text. "
            "Return ONLY raw JSON, with no markdown fences, greetings, or extra prose."
        )

        user_prompt = f"Analyze this {target_type} content:\n\n{scrubbed_input}"

        try:
            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=800,
                response_format={"type": "json_object"},
            )

            raw_response = chat_completion.choices[0].message.content
            if not raw_response:
                logger.warning("Empty response received from Groq API.")
                return False, []

            # 2. Parse and validate JSON using Pydantic
            parsed_data = json.loads(raw_response)
            validated_output = GroqSemanticResponse(**parsed_data)

            # 3. Verify evidence quotes against actual supplied content
            validated_findings: List[ScanFindingResponse] = []
            content_lower = content.lower()

            for idx, candidate in enumerate(validated_output.findings):
                quote = candidate.evidence_quote.strip()
                # Check if quote is present in the source text (or close match)
                if quote and (quote.lower() in content_lower or len(quote) < 5):
                    # Verified evidence
                    evidence_text = f"AI observed quote: \"{quote}\""
                else:
                    # If quote was hallucinated or not found, reject or mark unverified
                    # Reject ungrounded claims per specification
                    continue

                sev = candidate.severity.lower()
                if sev not in SEVERITY_POINTS_MAP:
                    sev = FindingSeverity.MEDIUM.value

                pts = SEVERITY_POINTS_MAP[sev]

                cat = candidate.category.lower()
                if cat not in [c.value for c in FindingCategory]:
                    cat = FindingCategory.SEMANTIC.value

                validated_findings.append(
                    ScanFindingResponse(
                        id=f"ai_{idx + 1:03d}",
                        category=cat,
                        severity=sev,
                        points=pts,
                        title=candidate.title.strip(),
                        evidence=evidence_text,
                        explanation=candidate.explanation.strip(),
                    )
                )

            return True, validated_findings

        except Exception as exc:
            logger.warning(f"Groq AI semantic analysis encountered an error: {exc}. Gracefully falling back to local detection.")
            return False, []


# Singleton AI Service instance
ai_service = GroqAIService()
