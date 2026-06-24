"""
PATENT NOTICE
Module: services/regulatory_graph
Implements Dependent Patent Claim 9:
Regulatory Jurisdiction Graph Traversal.

GRAPH SCHEMA SPECIFICATION (patent claim):

NODE TYPES:
  RegulationNode — a specific regulation law
    Fields: id, short_name, jurisdiction, regulation_type, risk_categories
  ArticleNode — a specific article/section
    Fields: id, regulation_id, article_number, obligation_type,
            trigger_conditions, plain_english

EDGE TYPES:
  CONTAINS — RegulationNode → ArticleNode
    (a regulation contains articles)
  TRIGGERED_BY — ArticleNode → DetectionAttribute
    (an article is triggered by a detection attribute value)

PREDICATE FUNCTIONS:
  Each edge from ArticleNode to DetectionAttribute carries a predicate
  function that evaluates to True/False given a detection's attribute
  values. True means the article applies.

TRAVERSAL ALGORITHM:
  Input: DetectionAttributeSet
  Output: list[ApplicableArticle]

  For each ArticleNode:
    Evaluate all its TRIGGERED_BY predicates against the
    DetectionAttributeSet. If any predicate returns True:
      Include this article in output.

  This is O(n) where n = number of articles. No recursion. No cycles.
  DAG guaranteed.

CRITICAL INVARIANTS:
  1. All predicate functions are pure functions. No side effects.
     No external calls.
  2. Same DetectionAttributeSet always produces same output. Fully
     deterministic.
  3. Graph version is incremented when any regulation definition changes.
  4. No LLM inference anywhere in this module.
  5. Output includes specific article references, never just regulation
     names.
"""

GRAPH_VERSION = "1.0.0"

REGULATION_DEFINITIONS = [
    {
        "id": "EU_AI_ACT",
        "short_name": "EU AI Act",
        "full_name": "EU Artificial Intelligence Act 2024",
        "jurisdiction": "European Union",
        "effective_date": "2024-08-01",
        "regulation_type": "ai_specific",
        "risk_categories": [
            "prohibited_ai",
            "high_risk_ai",
            "general_purpose_ai",
            "limited_risk_ai",
        ],
        "base_url": "https://artificialintelligenceact.eu",
    },
    {
        "id": "GDPR",
        "short_name": "GDPR",
        "full_name": "General Data Protection Regulation",
        "jurisdiction": "European Union",
        "effective_date": "2018-05-25",
        "regulation_type": "data_protection",
        "risk_categories": [
            "personal_data",
            "automated_decision",
            "profiling",
        ],
        "base_url": "https://gdpr-info.eu",
    },
    {
        "id": "INDIA_DPDP",
        "short_name": "India DPDP Act",
        "full_name": "Digital Personal Data Protection Act 2023",
        "jurisdiction": "India",
        "effective_date": "2023-08-11",
        "regulation_type": "data_protection",
        "risk_categories": [
            "personal_data",
            "data_fiduciary",
            "consent",
        ],
        "base_url": "https://prsindia.org/billtrack/digital-personal-data-protection-bill-2023",
    },
    {
        "id": "HIPAA",
        "short_name": "HIPAA",
        "full_name": "Health Insurance Portability and Accountability Act",
        "jurisdiction": "USA",
        "effective_date": "1996-08-21",
        "regulation_type": "sector_specific",
        "risk_categories": [
            "health_data",
            "phi",
            "healthcare_ai",
        ],
        "base_url": "https://www.hhs.gov/hipaa",
    },
    {
        "id": "CCPA",
        "short_name": "CCPA",
        "full_name": "California Consumer Privacy Act",
        "jurisdiction": "USA-California",
        "effective_date": "2020-01-01",
        "regulation_type": "data_protection",
        "risk_categories": [
            "personal_data",
            "consumer_rights",
            "automated_decision",
        ],
        "base_url": "https://oag.ca.gov/privacy/ccpa",
    },
    {
        "id": "ISO_42001",
        "short_name": "ISO 42001",
        "full_name": "ISO/IEC 42001 AI Management System Standard",
        "jurisdiction": "Global",
        "effective_date": "2023-12-18",
        "regulation_type": "voluntary_framework",
        "risk_categories": [
            "ai_management",
            "risk_assessment",
            "ai_governance",
        ],
        "base_url": "https://www.iso.org/standard/81230.html",
    },
    {
        "id": "NIST_AI_RMF",
        "short_name": "NIST AI RMF",
        "full_name": "NIST Artificial Intelligence Risk Management Framework",
        "jurisdiction": "USA",
        "effective_date": "2023-01-26",
        "regulation_type": "voluntary_framework",
        "risk_categories": [
            "ai_risk",
            "trustworthy_ai",
            "ai_governance",
        ],
        "base_url": "https://airc.nist.gov/RMF",
    },
]

ARTICLE_DEFINITIONS = [
    # EU AI Act Articles
    {
        "id": "EU_AI_ACT_ART5",
        "regulation_id": "EU_AI_ACT",
        "article_number": "Article 5",
        "article_title": "Prohibited AI Practices",
        "obligation_type": "prohibition",
        "applies_to_risk": ["critical"],
        "trigger_conditions": {
            "use_cases": [
                "surveillance",
                "social_scoring",
                "subliminal_manipulation",
            ],
            "contexts": ["law_enforcement", "government"],
        },
        "plain_english": (
            "Certain AI practices are completely prohibited including subliminal "
            "manipulation and real-time biometric identification in public spaces."
        ),
    },
    {
        "id": "EU_AI_ACT_ART6",
        "regulation_id": "EU_AI_ACT",
        "article_number": "Article 6",
        "article_title": "Classification Rules for High-Risk AI",
        "obligation_type": "requirement",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "categories": ["llm", "agent", "code_assistant"],
            "data_subjects": [
                "job_candidates",
                "employees",
                "patients",
                "financial_subjects",
                "general_public",
            ],
            "contexts": [
                "hr",
                "finance",
                "healthcare",
                "legal",
                "law_enforcement",
                "education",
            ],
        },
        "plain_english": (
            "AI systems used in high-risk applications must comply with requirements "
            "for data governance, transparency, human oversight, and accuracy."
        ),
    },
    {
        "id": "EU_AI_ACT_ART9",
        "regulation_id": "EU_AI_ACT",
        "article_number": "Article 9",
        "article_title": "Risk Management System",
        "obligation_type": "requirement",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "categories": ["llm", "agent"],
            "contexts": ["hr", "finance", "healthcare", "legal"],
        },
        "plain_english": (
            "High-risk AI systems must have a documented risk management system "
            "established and maintained throughout the lifecycle."
        ),
    },
    {
        "id": "EU_AI_ACT_ART13",
        "regulation_id": "EU_AI_ACT",
        "article_number": "Article 13",
        "article_title": "Transparency and Information",
        "obligation_type": "transparency",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "data_subjects": [
                "job_candidates",
                "employees",
                "patients",
                "general_public",
                "customers",
            ],
        },
        "plain_english": (
            "High-risk AI systems must be transparent enough for users to interpret "
            "outputs, with instructions for use provided."
        ),
    },
    {
        "id": "EU_AI_ACT_ART14",
        "regulation_id": "EU_AI_ACT",
        "article_number": "Article 14",
        "article_title": "Human Oversight",
        "obligation_type": "requirement",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "use_cases": [
                "automated_decision",
                "evaluating",
                "financial_decision",
                "healthcare",
            ],
            "contexts": ["hr", "finance", "healthcare", "legal"],
        },
        "plain_english": (
            "High-risk AI systems must be designed to allow human oversight including "
            "the ability to override, interrupt, or correct AI outputs."
        ),
    },
    # GDPR Articles
    {
        "id": "GDPR_ART5",
        "regulation_id": "GDPR",
        "article_number": "Article 5",
        "article_title": "Principles of Processing",
        "obligation_type": "requirement",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "use_cases": ["processing_personal_data"],
            "data_subjects": [
                "customers",
                "employees",
                "job_candidates",
                "general_public",
                "patients",
            ],
        },
        "plain_english": (
            "Personal data must be processed lawfully, fairly, transparently, and "
            "limited to specified purposes."
        ),
    },
    {
        "id": "GDPR_ART22",
        "regulation_id": "GDPR",
        "article_number": "Article 22",
        "article_title": "Automated Decision-Making",
        "obligation_type": "requirement",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "use_cases": ["automated_decision", "evaluating", "financial_decision"],
            "data_subjects": [
                "job_candidates",
                "employees",
                "customers",
                "financial_subjects",
                "general_public",
            ],
        },
        "plain_english": (
            "Individuals have the right not to be subject to solely automated "
            "decisions that produce significant effects, with required safeguards "
            "and human review rights."
        ),
    },
    {
        "id": "GDPR_ART35",
        "regulation_id": "GDPR",
        "article_number": "Article 35",
        "article_title": "Data Protection Impact Assessment",
        "obligation_type": "assessment",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "use_cases": [
                "automated_decision",
                "processing_personal_data",
                "surveillance",
            ],
            "data_subjects": [
                "employees",
                "general_public",
                "customers",
                "job_candidates",
            ],
        },
        "plain_english": (
            "A DPIA must be conducted before processing that is likely to result in "
            "high risk to individuals, especially when using automated decision-making."
        ),
    },
    # India DPDP Articles
    {
        "id": "INDIA_DPDP_S4",
        "regulation_id": "INDIA_DPDP",
        "article_number": "Section 4",
        "article_title": "Grounds for Processing",
        "obligation_type": "requirement",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "use_cases": ["processing_personal_data"],
            "data_subjects": [
                "customers",
                "employees",
                "general_public",
                "job_candidates",
            ],
        },
        "plain_english": (
            "Personal data of Indian residents may only be processed for a lawful "
            "purpose with consent or other specified grounds."
        ),
    },
    {
        "id": "INDIA_DPDP_S8",
        "regulation_id": "INDIA_DPDP",
        "article_number": "Section 8",
        "article_title": "Obligations of Data Fiduciary",
        "obligation_type": "requirement",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "categories": ["llm", "agent", "data_ai", "embedding"],
            "data_subjects": [
                "customers",
                "employees",
                "general_public",
                "job_candidates",
            ],
        },
        "plain_english": (
            "Data fiduciaries must ensure completeness, accuracy of personal data, "
            "implement technical safeguards, and address data principal grievances."
        ),
    },
    # HIPAA Articles
    {
        "id": "HIPAA_MINIMUM_NECESSARY",
        "regulation_id": "HIPAA",
        "article_number": "45 CFR 164.502(b)",
        "article_title": "Minimum Necessary Standard",
        "obligation_type": "requirement",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "contexts": ["healthcare"],
            "data_subjects": ["patients"],
        },
        "plain_english": (
            "Protected health information must only be used or disclosed to the "
            "minimum extent necessary to accomplish the intended purpose."
        ),
    },
    {
        "id": "HIPAA_SAFEGUARDS",
        "regulation_id": "HIPAA",
        "article_number": "45 CFR 164.312",
        "article_title": "Technical Safeguards",
        "obligation_type": "requirement",
        "applies_to_risk": ["high", "critical"],
        "trigger_conditions": {
            "contexts": ["healthcare"],
            "categories": ["llm", "data_ai", "agent"],
        },
        "plain_english": (
            "Covered entities must implement technical policies and procedures to "
            "protect electronic protected health information processed by AI systems."
        ),
    },
    # ISO 42001 Articles
    {
        "id": "ISO_42001_C4",
        "regulation_id": "ISO_42001",
        "article_number": "Clause 4",
        "article_title": "Context of the Organization",
        "obligation_type": "assessment",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "categories": ["llm", "agent", "code_assistant", "data_ai"],
        },
        "plain_english": (
            "Organizations must understand internal and external factors relevant to "
            "their AI management system and determine interested parties' requirements."
        ),
    },
    {
        "id": "ISO_42001_C8",
        "regulation_id": "ISO_42001",
        "article_number": "Clause 8",
        "article_title": "Operation",
        "obligation_type": "documentation",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "categories": ["llm", "agent", "code_assistant"],
        },
        "plain_english": (
            "Organizations must plan, implement, control, and document AI system "
            "development and deployment processes including risk assessments."
        ),
    },
    # NIST AI RMF Functions
    {
        "id": "NIST_GOVERN",
        "regulation_id": "NIST_AI_RMF",
        "article_number": "GOVERN Function",
        "article_title": "AI Risk Governance",
        "obligation_type": "requirement",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "categories": ["llm", "agent", "code_assistant", "data_ai"],
        },
        "plain_english": (
            "Organizational policies and accountability structures for AI risk "
            "management must be established and maintained."
        ),
    },
    {
        "id": "NIST_MAP",
        "regulation_id": "NIST_AI_RMF",
        "article_number": "MAP Function",
        "article_title": "AI Risk Context and Categorization",
        "obligation_type": "assessment",
        "applies_to_risk": ["medium", "high", "critical"],
        "trigger_conditions": {
            "use_cases": [
                "automated_decision",
                "evaluating",
                "processing_personal_data",
            ],
        },
        "plain_english": (
            "AI risks must be identified and prioritized, with the AI system's "
            "context, impacts, and affected parties documented."
        ),
    },
]

MISSING_GOVERNANCE_RULES = [
    {
        "condition": {
            "regulation_ids": ["EU_AI_ACT"],
            "risk_levels": ["high", "critical"],
        },
        "missing": "EU AI Act conformity assessment not completed",
    },
    {
        "condition": {
            "regulation_ids": ["GDPR"],
            "use_cases": ["automated_decision"],
        },
        "missing": "DPIA (Data Protection Impact Assessment) required",
    },
    {
        "condition": {
            "regulation_ids": ["GDPR", "EU_AI_ACT"],
        },
        "missing": "Human oversight mechanism not documented",
    },
    {
        "condition": {
            "regulation_ids": ["HIPAA"],
        },
        "missing": "Business Associate Agreement with AI vendor required",
    },
    {
        "condition": {
            "regulation_ids": ["INDIA_DPDP"],
        },
        "missing": "Consent mechanism for Indian data subjects required",
    },
    {
        "condition": {
            "risk_levels": ["high", "critical"],
        },
        "missing": "AI system risk assessment not found in inventory",
    },
    {
        "condition": {
            "data_subjects": ["patients", "employees", "job_candidates"],
        },
        "missing": "Data subject rights mechanism not documented",
    },
]
