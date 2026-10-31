"""Tests for Groq AI integration, resilience, and hallucination rejection."""

from unittest.mock import MagicMock, patch
from app.services.ai_analyzer import GroqAIService


def test_ai_unavailable_graceful_fallback():
    """When AI is disabled or API key missing, it cleanly returns False with no findings."""
    service = GroqAIService()
    service.enabled = False
    service.api_key = None
    success, findings = service.analyze_content("Some sample message text")
    assert success is False
    assert findings == []


def test_ai_invalid_json_handling():
    """If Groq returns malformed JSON, service must handle safely without crashing."""
    service = GroqAIService()
    service.enabled = True
    service.api_key = "mock_key"

    mock_client = MagicMock()
    mock_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "INVALID_NON_JSON_STRING"
    mock_completion.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_completion
    service._client = mock_client

    success, findings = service.analyze_content("Some suspicious text")
    assert success is False
    assert findings == []


def test_ai_hallucinated_evidence_rejection():
    """Findings with quotes hallucinated by the model must be rejected."""
    service = GroqAIService()
    service.enabled = True
    service.api_key = "mock_key"

    fake_json_response = """
    {
        "claimed_organization": "FakeBank",
        "requested_action": "Click link",
        "social_engineering_tactics": ["fear"],
        "findings": [
            {
                "category": "semantic",
                "severity": "critical",
                "title": "Fabricated Claim",
                "evidence_quote": "THIS TEXT DOES NOT EXIST IN THE INPUT AT ALL 987654321",
                "explanation": "Made up by LLM"
            }
        ]
    }
    """

    mock_client = MagicMock()
    mock_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = fake_json_response
    mock_completion.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_completion
    service._client = mock_client

    success, findings = service.analyze_content("Please check your email for the code.")
    # Success should be True because API returned, but findings with hallucinated evidence must be filtered out
    assert success is True
    assert len(findings) == 0
