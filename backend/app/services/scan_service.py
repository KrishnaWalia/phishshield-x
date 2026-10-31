"""PhishShield X - Scan Orchestration Service

Orchestrates the detection pipeline:
1. Heuristic & rule-based engines (URL and Message).
2. Machine learning classification (TF-IDF + Logistic Regression).
3. Groq AI semantic analysis (optional, resilient).
4. Central Risk Scoring Engine (authoritative scoring).
5. Neon PostgreSQL persistence (scans & scan_findings).
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc

from app.schemas.scan import (
    UrlScanRequest,
    MessageScanRequest,
    ScanResponse,
    EngineStatus,
    ScanHistoryResponse,
    ScanHistoryItem,
)
from app.schemas.findings import ScanFindingResponse
from app.core.security import (
    validate_and_sanitize_url,
    create_safe_target_descriptor,
)
from app.detection.url_analyzer import analyze_url
from app.detection.message_analyzer import analyze_message_rules
from app.detection.risk_engine import calculate_risk_assessment
from app.services.ml_service import ml_service
from app.services.ai_analyzer import ai_service
from app.database.models import Scan, ScanFinding

logger = logging.getLogger("phishshield.scan_service")


def generate_public_scan_id() -> str:
    """Generate unique public scan ID in standard psx_ format."""
    random_hex = uuid.uuid4().hex[:12]
    return f"psx_{random_hex}"


class ScanService:
    """Core coordinator for URL and Message threat evaluations."""

    # Active session cache (guarantees history availability during offline demos / sandboxes without DB)
    _session_cache: List[Tuple[ScanResponse, str]] = []

    @staticmethod
    def scan_url(request: UrlScanRequest, db: Optional[Session] = None) -> ScanResponse:
        """Execute full detection pipeline for a submitted URL."""
        # 1. Validate & sanitize URL
        sanitized_url = validate_and_sanitize_url(request.url)
        safe_target = create_safe_target_descriptor("url", sanitized_url)

        engines_status = EngineStatus(rules=True, ml=False, ai=False)
        collected_findings: List[ScanFindingResponse] = []

        # 2. Rule-based URL Heuristics
        url_findings = analyze_url(
            url=sanitized_url,
            page_title=request.page_title,
            page_text=request.page_text,
            links=request.links or [],
        )
        collected_findings.extend(url_findings)

        # 3. Optional ML on visible page text if available
        if request.page_text and len(request.page_text.strip()) > 30:
            if ml_service.is_available:
                engines_status.ml = True
                ml_findings = ml_service.analyze_message_ml(request.page_text)
                collected_findings.extend(ml_findings)

        # 4. Optional Groq AI semantic analysis on page text/title
        content_to_analyze = ""
        if request.page_title:
            content_to_analyze += f"Title: {request.page_title}\n"
        if request.page_text:
            content_to_analyze += f"Body: {request.page_text}\n"

        if content_to_analyze and ai_service.enabled:
            ai_success, ai_findings = ai_service.analyze_content(content_to_analyze, target_type="url")
            engines_status.ai = ai_success
            if ai_success:
                collected_findings.extend(ai_findings)

        # 5. Authoritative Central Risk Scoring
        risk_score, risk_level, final_findings, summary, rec_action = calculate_risk_assessment(
            raw_findings=collected_findings,
            target_type="url",
        )

        scan_id = generate_public_scan_id()
        analyzed_at_dt = datetime.now(timezone.utc)
        analyzed_at_str = analyzed_at_dt.isoformat()

        response = ScanResponse(
            scan_id=scan_id,
            target_type="url",
            target=safe_target,
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
            findings=final_findings,
            recommended_action=rec_action,
            analyzed_at=analyzed_at_str,
            engines=engines_status,
        )

        # 6. Store in active session cache
        ScanService._session_cache.append((response, request.source.value))
        if len(ScanService._session_cache) > 100:
            ScanService._session_cache.pop(0)

        # 7. Persist to Neon PostgreSQL
        if db is not None:
            ScanService._persist_scan(db, response, request.source.value, analyzed_at_dt)

        return response

    @staticmethod
    def scan_message(request: MessageScanRequest, db: Optional[Session] = None) -> ScanResponse:
        """Execute full detection pipeline for a submitted message."""
        raw_text = request.text.strip()
        safe_target = create_safe_target_descriptor("message", raw_text)

        engines_status = EngineStatus(rules=True, ml=False, ai=False)
        collected_findings: List[ScanFindingResponse] = []

        # 1. Rule-based Message Analysis
        rule_findings = analyze_message_rules(raw_text)
        collected_findings.extend(rule_findings)

        # 2. Machine Learning Classification
        if ml_service.is_available:
            engines_status.ml = True
            ml_findings = ml_service.analyze_message_ml(raw_text)
            collected_findings.extend(ml_findings)

        # 3. Groq AI Semantic Analysis
        if ai_service.enabled:
            ai_success, ai_findings = ai_service.analyze_content(raw_text, target_type="message")
            engines_status.ai = ai_success
            if ai_success:
                collected_findings.extend(ai_findings)

        # 4. Authoritative Central Risk Scoring
        risk_score, risk_level, final_findings, summary, rec_action = calculate_risk_assessment(
            raw_findings=collected_findings,
            target_type="message",
        )

        scan_id = generate_public_scan_id()
        analyzed_at_dt = datetime.now(timezone.utc)
        analyzed_at_str = analyzed_at_dt.isoformat()

        response = ScanResponse(
            scan_id=scan_id,
            target_type="message",
            target=safe_target,
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
            findings=final_findings,
            recommended_action=rec_action,
            analyzed_at=analyzed_at_str,
            engines=engines_status,
        )

        # 5. Store in active session cache
        ScanService._session_cache.append((response, request.source.value))
        if len(ScanService._session_cache) > 100:
            ScanService._session_cache.pop(0)

        # 6. Persist to Neon PostgreSQL
        if db is not None:
            ScanService._persist_scan(db, response, request.source.value, analyzed_at_dt)

        return response

    @staticmethod
    def _persist_scan(
        db: Session,
        response: ScanResponse,
        source: str,
        analyzed_at_dt: datetime,
    ) -> None:
        """Persist Scan and associated ScanFindings to Neon PostgreSQL."""
        try:
            db_scan = Scan(
                scan_id=response.scan_id,
                target_type=response.target_type,
                target=response.target,
                risk_score=response.risk_score,
                risk_level=response.risk_level,
                summary=response.summary,
                recommended_action=response.recommended_action,
                engines=response.engines.model_dump(),
                source=source,
                analyzed_at=analyzed_at_dt,
            )
            db.add(db_scan)
            db.flush()

            # Add findings
            for f in response.findings:
                finding_db = ScanFinding(
                    id=f"{response.scan_id}_{f.id}",
                    scan_id=response.scan_id,
                    category=f.category,
                    severity=f.severity,
                    points=f.points,
                    title=f.title,
                    evidence=f.evidence,
                    explanation=f.explanation,
                )
                db.add(finding_db)

            db.commit()
            logger.info(f"Persisted scan {response.scan_id} successfully in Neon DB.")
        except Exception as exc:
            db.rollback()
            logger.error(f"Failed to persist scan {response.scan_id} to database: {exc}")
            # Note: We do not crash the API if DB write fails, but log the failure

    @staticmethod
    def get_history(db: Optional[Session] = None, limit: int = 20, offset: int = 0) -> ScanHistoryResponse:
        """Retrieve paginated scan history from Neon PostgreSQL with active session cache fallback."""
        if db is not None:
            try:
                total = db.scalar(select(func.count()).select_from(Scan)) or 0
                stmt = select(Scan).order_by(desc(Scan.analyzed_at)).limit(limit).offset(offset)
                scans = db.scalars(stmt).all()

                items: List[ScanHistoryItem] = []
                for s in scans:
                    items.append(
                        ScanHistoryItem(
                            scan_id=s.scan_id,
                            target_type=s.target_type,
                            target=s.target,
                            risk_score=s.risk_score,
                            risk_level=s.risk_level,
                            summary=s.summary,
                            recommended_action=s.recommended_action,
                            source=s.source,
                            analyzed_at=s.analyzed_at.isoformat() if s.analyzed_at else "",
                            findings_count=len(s.findings),
                        )
                    )

                return ScanHistoryResponse(total=total, limit=limit, offset=offset, scans=items)
            except Exception as exc:
                logger.warning(
                    f"Neon database connection unavailable during history retrieval: {exc}. "
                    "Serving from active in-memory session cache."
                )

        # Fallback to in-memory session cache (guarantees history for sandbox testing / offline demos)
        cached = list(reversed(ScanService._session_cache))
        total_cached = len(cached)
        paged = cached[offset : offset + limit]
        items = [
            ScanHistoryItem(
                scan_id=resp.scan_id,
                target_type=resp.target_type,
                target=resp.target,
                risk_score=resp.risk_score,
                risk_level=resp.risk_level,
                summary=resp.summary,
                recommended_action=resp.recommended_action,
                source=src,
                analyzed_at=resp.analyzed_at,
                findings_count=len(resp.findings),
            )
            for resp, src in paged
        ]
        return ScanHistoryResponse(total=total_cached, limit=limit, offset=offset, scans=items)

    @staticmethod
    def get_scan_by_id(db: Optional[Session] = None, scan_id: str = "") -> Optional[ScanResponse]:
        """Retrieve single scan and its findings by public scan_id."""
        if db is not None:
            try:
                stmt = select(Scan).where(Scan.scan_id == scan_id)
                scan = db.scalars(stmt).first()
                if scan:
                    findings_resp = [
                        ScanFindingResponse(
                            id=f.id.split("_", 2)[-1] if "_" in f.id else f.id,
                            category=f.category,
                            severity=f.severity,
                            points=f.points,
                            title=f.title,
                            evidence=f.evidence,
                            explanation=f.explanation,
                        )
                        for f in scan.findings
                    ]

                    return ScanResponse(
                        scan_id=scan.scan_id,
                        target_type=scan.target_type,
                        target=scan.target,
                        risk_score=scan.risk_score,
                        risk_level=scan.risk_level,
                        summary=scan.summary,
                        findings=findings_resp,
                        recommended_action=scan.recommended_action,
                        analyzed_at=scan.analyzed_at.isoformat() if scan.analyzed_at else "",
                        engines=EngineStatus(**scan.engines) if scan.engines else EngineStatus(),
                    )
            except Exception as exc:
                logger.warning(f"Database query failed for scan {scan_id}: {exc}. Checking active session cache...")

        # Fallback to session cache
        for resp, _ in ScanService._session_cache:
            if resp.scan_id == scan_id:
                return resp

        return None
