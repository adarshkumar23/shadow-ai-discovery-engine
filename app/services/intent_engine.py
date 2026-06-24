"""
PATENT NOTICE
Module: services/intent_engine
Implements Dependent Patent Claim 7:
Intent Classification from Linguistic Context.

This engine extracts a structured intent tuple
(action, data_subject, business_context) from
the text surrounding an AI tool mention and
maps the tuple to regulatory risk classifications.

CRITICAL DESIGN INVARIANTS:
1. This engine runs LOCALLY. No external service
   calls. No HTTP requests. No API calls.
2. This engine is DETERMINISTIC. Same input text
   always produces identical output. No randomness.
3. This engine uses a RULE-BASED approach only.
   No neural networks. No probabilistic models.
   No embeddings. No LLM inference.
4. All rules are human-authored mappings from
   linguistic patterns to regulatory concepts.
5. Classification confidence is always one of:
   'high', 'medium', 'low' — never a probability.

These invariants are patent-specified and must
never be changed.
"""

from __future__ import annotations

from datetime import datetime, timezone

CLASSIFIER_VERSION = "1.0.0"


ACTION_PATTERNS: dict[str, list[str]] = {
    "evaluating": [
        "evaluat", "assess", "screen", "review",
        "score", "rank", "shortlist", "filter",
        "select candidates", "hiring decision",
        "performance review", "appraise",
    ],
    "processing_personal_data": [
        "process personal", "handle personal",
        "customer data", "user data", "personal information",
        "process data about", "data subject",
        "patient data", "health data", "medical record",
    ],
    "automated_decision": [
        "automat", "automatic decision", "auto-approv",
        "auto-reject", "without human review",
        "autonomous", "auto-generat", "bot decision",
    ],
    "content_generation": [
        "draft", "generat", "writ", "creat",
        "compil", "summar", "translat", "produc content",
    ],
    "surveillance": [
        "monitor employee", "track employee",
        "monitor worker", "employee monitoring",
        "workplace surveillance", "track productivity",
    ],
    "financial_decision": [
        "credit decision", "loan", "underwrite",
        "insurance decision", "financial assessment",
        "fraud detect", "credit score", "creditworthiness",
    ],
    "legal_analysis": [
        "legal document", "contract review",
        "compliance check", "legal analysis",
        "case analysis", "court", "litigation",
        "legal advice",
    ],
    "healthcare": [
        "diagnosis", "medical decision", "patient",
        "clinical", "treatment", "health record",
        "medical imaging", "symptom",
    ],
}


DATA_SUBJECT_PATTERNS: dict[str, list[str]] = {
    "job_candidates": [
        "candidat", "applicant", "job seeker",
        "resume", "cv", "hiring", "recruitment",
        "job application",
    ],
    "employees": [
        "employee", "worker", "staff", "workforce",
        "team member", "personnel",
    ],
    "customers": [
        "customer", "client", "consumer",
        "end user", "user data", "buyer",
    ],
    "patients": [
        "patient", "clinical", "medical",
        "healthcare", "health record",
    ],
    "financial_subjects": [
        "borrower", "loan applicant", "credit",
        "insurance holder", "policyholder",
    ],
    "general_public": [
        "citizen", "public", "people", "person",
        "individual", "natural person",
    ],
    "internal_data": [
        "internal document", "company document",
        "business data", "corporate data",
    ],
}


BUSINESS_CONTEXT_PATTERNS: dict[str, list[str]] = {
    "hr": [
        "hr", "human resource", "recruiting",
        "talent", "hiring", "onboarding",
        "performance management", "payroll",
    ],
    "legal": [
        "legal", "compliance", "regulatory",
        "contract", "litigation", "counsel",
    ],
    "finance": [
        "finance", "financial", "accounting",
        "credit", "loan", "underwriting",
        "insurance", "treasury",
    ],
    "healthcare": [
        "health", "medical", "clinical",
        "hospital", "patient care", "pharma",
    ],
    "customer_support": [
        "customer support", "customer service",
        "help desk", "support ticket",
        "customer success",
    ],
    "engineering": [
        "engineering", "development", "coding",
        "software", "devops", "infrastructure",
    ],
    "marketing": [
        "marketing", "content", "campaign",
        "advertising", "brand", "social media",
    ],
    "education": [
        "education", "student", "learning",
        "training", "academic",
    ],
}


REGULATORY_RISK_MAP: list[dict] = [
    {
        "name": "Rule 1 — HR Automated Decision",
        "condition": lambda a, s, c: a in ("evaluating", "automated_decision") and s == "job_candidates",
        "obligations": [
            {
                "code": "EU_AI_ACT_ART6",
                "name": "EU AI Act Article 6",
                "articles": ["Article 6(2)(a)"],
                "reason": "High-risk AI: employment decisions",
            },
            {
                "code": "EU_AI_ACT_ART13",
                "name": "EU AI Act Article 13",
                "articles": ["Article 13"],
                "reason": "Transparency obligation required",
            },
            {
                "code": "GDPR_ART22",
                "name": "GDPR Article 22",
                "articles": ["Article 22"],
                "reason": "Automated individual decision-making",
            },
        ],
        "use_case": "Automated evaluation of job candidates",
        "risk_level": "high",
    },
    {
        "name": "Rule 2 — Employee Monitoring",
        "condition": lambda a, s, c: a == "surveillance" and s == "employees",
        "obligations": [
            {
                "code": "GDPR_ART6",
                "name": "GDPR Article 6",
                "articles": ["Article 6(1)"],
                "reason": "Lawful basis for processing required",
            },
            {
                "code": "EU_AI_ACT_ART6",
                "name": "EU AI Act Article 6",
                "articles": ["Article 6(2)(b)"],
                "reason": "High-risk: worker management",
            },
        ],
        "use_case": "Employee monitoring and surveillance",
        "risk_level": "high",
    },
    {
        "name": "Rule 3 — Financial Decision",
        "condition": lambda a, s, c: a == "financial_decision" or s == "financial_subjects",
        "obligations": [
            {
                "code": "EU_AI_ACT_ART6",
                "name": "EU AI Act Article 6",
                "articles": ["Article 6(2)(b)"],
                "reason": "High-risk: creditworthiness assessment",
            },
            {
                "code": "GDPR_ART22",
                "name": "GDPR Article 22",
                "articles": ["Article 22"],
                "reason": "Automated credit decision",
            },
        ],
        "use_case": "Automated financial decision-making",
        "risk_level": "high",
    },
    {
        "name": "Rule 4 — Healthcare AI",
        "condition": lambda a, s, c: c == "healthcare" or s == "patients",
        "obligations": [
            {
                "code": "EU_AI_ACT_ART6",
                "name": "EU AI Act Article 6",
                "articles": ["Article 6(1)"],
                "reason": "High-risk: medical device AI",
            },
            {
                "code": "HIPAA_MINIMUM_NECESSARY",
                "name": "HIPAA Minimum Necessary",
                "articles": ["45 CFR 164.502(b)"],
                "reason": "PHI processing requires minimum necessary standard",
            },
        ],
        "use_case": "Healthcare AI processing patient data",
        "risk_level": "critical",
    },
    {
        "name": "Rule 5 — Personal Data Processing",
        "condition": lambda a, s, c: a == "processing_personal_data" and s in ("customers", "general_public", "employees", "job_candidates"),
        "obligations": [
            {
                "code": "GDPR_ART5",
                "name": "GDPR Article 5",
                "articles": ["Article 5(1)(a)", "Article 5(1)(b)"],
                "reason": "Lawfulness, fairness, purpose limitation",
            },
            {
                "code": "INDIA_DPDP_S4",
                "name": "India DPDP Act Section 4",
                "articles": ["Section 4"],
                "reason": "Lawful processing of personal data",
            },
        ],
        "use_case": "AI processing of personal data",
        "risk_level": "medium",
    },
    {
        "name": "Rule 6 — Content Generation (low risk)",
        "condition": lambda a, s, c: a == "content_generation" and s == "internal_data" and c in ("engineering", "marketing"),
        "obligations": [],
        "use_case": "Internal content generation",
        "risk_level": "low",
    },
    {
        "name": "Rule 7 — Legal Analysis",
        "condition": lambda a, s, c: a == "legal_analysis" or c == "legal",
        "obligations": [
            {
                "code": "GDPR_ART9",
                "name": "GDPR Article 9",
                "articles": ["Article 9"],
                "reason": "Possible special category data",
            },
        ],
        "use_case": "AI-assisted legal analysis",
        "risk_level": "medium",
    },
]

_DEFAULT_RULE: dict = {
    "obligations": [],
    "use_case": "General AI tool usage",
    "risk_level": "low",
}


class IntentEngine:
    """Deterministic rule-based intent classification engine.

    Implements Dependent Patent Claim 7.
    This engine is fully deterministic: same input text always
    produces identical output. No external calls. No probabilistic
    models. No randomness.
    """

    CLASSIFIER_VERSION = CLASSIFIER_VERSION

    @staticmethod
    def classify(
        text: str,
        tool_name: str,
    ) -> dict | None:
        """Main entry point. Extracts intent tuple from
        text surrounding a detected AI tool mention
        and maps to regulatory risk classification.

        Returns None if no meaningful intent can
        be extracted from the text.

        Returns dict matching use_case_risk_json
        schema when classification succeeds.

        This method is fully deterministic.
        Same inputs -> always same output.
        """
        action = IntentEngine._extract_action(text)
        data_subject = IntentEngine._extract_data_subject(text)
        business_context = IntentEngine._extract_business_context(text)

        if action is None and data_subject is None and business_context is None:
            return None

        rule = IntentEngine._match_rule(action, data_subject, business_context)

        return IntentEngine._build_output(
            action, data_subject, business_context, rule
        )

    @staticmethod
    def _extract_action(text: str) -> str | None:
        lower_text = text.lower()
        for action, triggers in ACTION_PATTERNS.items():
            for trigger in triggers:
                if trigger in lower_text:
                    return action
        return None

    @staticmethod
    def _extract_data_subject(text: str) -> str | None:
        lower_text = text.lower()
        for subject, triggers in DATA_SUBJECT_PATTERNS.items():
            for trigger in triggers:
                if trigger in lower_text:
                    return subject
        return None

    @staticmethod
    def _extract_business_context(text: str) -> str | None:
        lower_text = text.lower()
        for context, triggers in BUSINESS_CONTEXT_PATTERNS.items():
            for trigger in triggers:
                if trigger in lower_text:
                    return context
        return None

    @staticmethod
    def _match_rule(
        action: str | None,
        data_subject: str | None,
        business_context: str | None,
    ) -> dict:
        for rule in REGULATORY_RISK_MAP:
            if rule["condition"](action, data_subject, business_context):
                return rule
        return _DEFAULT_RULE

    @staticmethod
    def _build_output(
        action: str | None,
        data_subject: str | None,
        business_context: str | None,
        rule: dict,
    ) -> dict:
        extracted_count = sum(1 for v in (action, data_subject, business_context) if v is not None)
        if extracted_count >= 3:
            confidence = "high"
        elif extracted_count >= 2:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "use_case": rule["use_case"],
            "risk_level": rule["risk_level"],
            "applicable_regulations": rule["obligations"],
            "intent_tuple": {
                "action": action,
                "data_subject": data_subject,
                "business_context": business_context,
            },
            "classification_confidence": confidence,
            "classified_at": datetime.now(timezone.utc).isoformat(),
            "classifier_version": CLASSIFIER_VERSION,
        }
