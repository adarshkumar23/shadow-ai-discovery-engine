"""
PATENT NOTICE
Module: registry/signature_registry
This registry is a core IP asset of Patent P1.
System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating
AI Governance Artifacts from Enterprise Telemetry.
The signature definitions, confidence weights,
and keyword patterns constitute the knowledge
base of the detection engine.
"""

from __future__ import annotations

REGISTRY_VERSION = "1.0.0"
REGISTRY_LAST_UPDATED = "2026-06-24"

# ── Decay coefficients by category (patent-invariant λ values) ──
DECAY_COEFFICIENTS: dict[str, float] = {
    "llm": 0.023,
    "code_assistant": 0.023,
    "agent": 0.023,
    "image_gen": 0.046,
    "embedding": 0.035,
    "voice_ai": 0.046,
    "data_ai": 0.035,
    "other": 0.069,
}

# ── Confidence weight patterns ─────────────────────────────────
# Each pattern sums to exactly 1.0

_W_KEYWORD_HEAVY = {
    "endpoint_match": 0.25,
    "identity_match": 0.20,
    "volume_match": 0.15,
    "keyword_match": 0.40,
}

_W_ENDPOINT_HEAVY = {
    "endpoint_match": 0.40,
    "identity_match": 0.20,
    "volume_match": 0.15,
    "keyword_match": 0.25,
}

_W_IDENTITY_HEAVY = {
    "endpoint_match": 0.25,
    "identity_match": 0.35,
    "volume_match": 0.15,
    "keyword_match": 0.25,
}

_W_BALANCED = {
    "endpoint_match": 0.25,
    "identity_match": 0.25,
    "volume_match": 0.20,
    "keyword_match": 0.30,
}

# ── Data egress indicators by category ─────────────────────────

_EGRESS_LLM = {"min_bytes": 1000, "max_bytes": 100000, "typical_latency_ms": 500}
_EGRESS_IMAGE = {"min_bytes": 50000, "max_bytes": 5000000, "typical_latency_ms": 3000}
_EGRESS_CODE = {"min_bytes": 500, "max_bytes": 50000, "typical_latency_ms": 300}
_EGRESS_VOICE = {"min_bytes": 10000, "max_bytes": 1000000, "typical_latency_ms": 1000}
_EGRESS_EMBED = {"min_bytes": 100, "max_bytes": 10000, "typical_latency_ms": 100}
_EGRESS_DATA = {"min_bytes": 1000, "max_bytes": 1000000, "typical_latency_ms": 500}
_EGRESS_AGENT = {"min_bytes": 1000, "max_bytes": 200000, "typical_latency_ms": 1000}
_EGRESS_OTHER = {"min_bytes": 500, "max_bytes": 100000, "typical_latency_ms": 500}


KNOWN_AI_SIGNATURES: list[dict] = [
    # ═══════════════════════════════════════════════════════════
    # OpenAI family (8 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "openai-chatgpt",
        "provider_name": "ChatGPT",
        "category": "llm",
        "keyword_patterns": [
            "chatgpt", "chat gpt", "chat-gpt", "openai chat",
            "gpt chat", "chatgpt.com",
        ],
        "endpoint_patterns": ["api.openai.com", "chatgpt.com"],
        "oauth_app_patterns": ["ChatGPT", "OpenAI ChatGPT"],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "openai-api",
        "provider_name": "OpenAI API",
        "category": "llm",
        "keyword_patterns": [
            "openai api", "openai", "gpt-4", "gpt-4o",
            "gpt-3.5", "gpt4", "gpt 4", "text-davinci",
            "openai.com", "openai sdk",
        ],
        "endpoint_patterns": ["api.openai.com"],
        "oauth_app_patterns": ["OpenAI", "OpenAI API"],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "critical",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "openai-dall-e",
        "provider_name": "DALL-E",
        "category": "image_gen",
        "keyword_patterns": [
            "dall-e", "dalle", "dall e", "dall-e 3",
            "dall-e 2", "openai image", "openai dall",
        ],
        "endpoint_patterns": ["api.openai.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "openai-whisper",
        "provider_name": "Whisper",
        "category": "voice_ai",
        "keyword_patterns": [
            "whisper", "openai whisper",
            "openai transcription", "openai speech",
        ],
        "endpoint_patterns": ["api.openai.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["voice_ai"],
        "data_egress_indicators": _EGRESS_VOICE,
    },
    {
        "slug": "openai-embeddings",
        "provider_name": "OpenAI Embeddings",
        "category": "embedding",
        "keyword_patterns": [
            "openai embed", "text-embedding",
            "openai embeddings", "embedding model",
        ],
        "endpoint_patterns": ["api.openai.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["embedding"],
        "data_egress_indicators": _EGRESS_EMBED,
    },
    {
        "slug": "openai-assistants",
        "provider_name": "OpenAI Assistants",
        "category": "agent",
        "keyword_patterns": [
            "openai assistant", "assistants api",
            "openai thread", "openai run",
        ],
        "endpoint_patterns": ["api.openai.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["agent"],
        "data_egress_indicators": _EGRESS_AGENT,
    },
    {
        "slug": "openai-sora",
        "provider_name": "Sora",
        "category": "image_gen",
        "keyword_patterns": [
            "sora", "openai sora", "openai video",
            "sora ai",
        ],
        "endpoint_patterns": ["api.openai.com", "sora.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "github-copilot",
        "provider_name": "GitHub Copilot",
        "category": "code_assistant",
        "keyword_patterns": [
            "github copilot", "copilot", "gh copilot",
            "copilot for business", "copilot chat",
            "visual studio copilot",
        ],
        "endpoint_patterns": [
            "copilot-proxy.githubusercontent.com",
            "api.githubcopilot.com",
        ],
        "oauth_app_patterns": ["GitHub Copilot", "Copilot"],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["code_assistant"],
        "data_egress_indicators": _EGRESS_CODE,
    },

    # ═══════════════════════════════════════════════════════════
    # Anthropic family (2 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "anthropic-claude",
        "provider_name": "Claude",
        "category": "llm",
        "keyword_patterns": [
            "claude", "anthropic", "claude ai",
            "claude.ai", "anthropic claude", "claude 3",
            "claude opus", "claude sonnet", "claude haiku",
        ],
        "endpoint_patterns": ["api.anthropic.com", "claude.ai"],
        "oauth_app_patterns": ["Claude", "Anthropic", "Claude AI"],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "anthropic-api",
        "provider_name": "Anthropic API",
        "category": "llm",
        "keyword_patterns": [
            "anthropic api", "claude api",
            "anthropic sdk", "messages api anthropic",
        ],
        "endpoint_patterns": ["api.anthropic.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "critical",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },

    # ═══════════════════════════════════════════════════════════
    # Google family (6 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "google-gemini",
        "provider_name": "Gemini",
        "category": "llm",
        "keyword_patterns": [
            "gemini", "google gemini", "bard",
            "google bard", "gemini pro", "gemini ultra",
            "gemini nano", "gemini api",
        ],
        "endpoint_patterns": [
            "generativelanguage.googleapis.com",
            "gemini.google.com",
        ],
        "oauth_app_patterns": ["Gemini", "Google Gemini", "Bard"],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "google-vertex-ai",
        "provider_name": "Vertex AI",
        "category": "llm",
        "keyword_patterns": [
            "vertex ai", "google vertex",
            "vertex", "vertexai", "google cloud ai",
            "palm api", "palm 2",
        ],
        "endpoint_patterns": [
            "us-central1-aiplatform.googleapis.com",
            "aiplatform.googleapis.com",
        ],
        "oauth_app_patterns": ["Vertex AI", "Google Vertex AI"],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "critical",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "google-ai-studio",
        "provider_name": "Google AI Studio",
        "category": "llm",
        "keyword_patterns": [
            "ai studio", "google ai studio",
            "makersuite", "google makersuite",
        ],
        "endpoint_patterns": [
            "aistudio.google.com",
            "generativelanguage.googleapis.com",
        ],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "google-notebooklm",
        "provider_name": "NotebookLM",
        "category": "data_ai",
        "keyword_patterns": [
            "notebooklm", "notebook lm",
            "google notebooklm", "google notebook lm",
        ],
        "endpoint_patterns": ["notebooklm.google.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["data_ai"],
        "data_egress_indicators": _EGRESS_DATA,
    },
    {
        "slug": "google-imagen",
        "provider_name": "Imagen",
        "category": "image_gen",
        "keyword_patterns": [
            "imagen", "google imagen",
            "image generation google", "google image generation",
        ],
        "endpoint_patterns": ["aiplatform.googleapis.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "google-workspace-ai",
        "provider_name": "Google Workspace AI",
        "category": "llm",
        "keyword_patterns": [
            "workspace ai", "google workspace ai",
            "duet ai", "duet ai google", "gemini workspace",
        ],
        "endpoint_patterns": ["workspace.google.com"],
        "oauth_app_patterns": ["Duet AI", "Google Workspace AI"],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },

    # ═══════════════════════════════════════════════════════════
    # Microsoft family (5 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "microsoft-copilot",
        "provider_name": "Microsoft Copilot",
        "category": "llm",
        "keyword_patterns": [
            "microsoft copilot", "ms copilot",
            "copilot microsoft", "m365 copilot",
            "office copilot", "bing chat", "copilot 365",
        ],
        "endpoint_patterns": ["copilot.microsoft.com", "sydney.bing.com"],
        "oauth_app_patterns": ["Microsoft Copilot", "Copilot"],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "azure-openai",
        "provider_name": "Azure OpenAI",
        "category": "llm",
        "keyword_patterns": [
            "azure openai", "azure gpt",
            "aoai", "azure openai service",
            "openai.azure.com", "cognitive services openai",
        ],
        "endpoint_patterns": ["*.openai.azure.com"],
        "oauth_app_patterns": ["Azure OpenAI"],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "critical",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "microsoft-copilot-studio",
        "provider_name": "Copilot Studio",
        "category": "agent",
        "keyword_patterns": [
            "copilot studio", "power virtual agents",
            "microsoft bot framework", "pva",
        ],
        "endpoint_patterns": ["copilotstudio.microsoft.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["agent"],
        "data_egress_indicators": _EGRESS_AGENT,
    },
    {
        "slug": "azure-ai-services",
        "provider_name": "Azure AI Services",
        "category": "data_ai",
        "keyword_patterns": [
            "azure cognitive", "azure ai",
            "cognitive services", "azure ml", "azureml",
            "azure machine learning",
        ],
        "endpoint_patterns": [
            "*.cognitiveservices.azure.com",
            "*.api.cognitive.microsoft.com",
        ],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["data_ai"],
        "data_egress_indicators": _EGRESS_DATA,
    },
    {
        "slug": "bing-ai",
        "provider_name": "Bing AI",
        "category": "llm",
        "keyword_patterns": [
            "bing ai", "bing chat", "new bing",
            "bing image creator",
        ],
        "endpoint_patterns": ["bing.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },

    # ═══════════════════════════════════════════════════════════
    # Meta family (2 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "meta-llama",
        "provider_name": "Llama",
        "category": "llm",
        "keyword_patterns": [
            "llama", "meta llama", "llama 2",
            "llama 3", "meta ai", "llama.meta.com",
        ],
        "endpoint_patterns": ["llama.meta.com"],
        "oauth_app_patterns": ["Meta AI", "Llama"],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "meta-ai",
        "provider_name": "Meta AI",
        "category": "llm",
        "keyword_patterns": [
            "meta ai", "meta.ai", "ai.meta.com",
            "meta ai assistant",
        ],
        "endpoint_patterns": ["meta.ai", "ai.meta.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },

    # ═══════════════════════════════════════════════════════════
    # Mistral family (2 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "mistral-ai",
        "provider_name": "Mistral AI",
        "category": "llm",
        "keyword_patterns": [
            "mistral", "mistral ai", "le chat",
            "mistral api", "mixtral", "mistral large",
        ],
        "endpoint_patterns": ["api.mistral.ai", "chat.mistral.ai"],
        "oauth_app_patterns": ["Mistral", "Le Chat"],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "mistral-api",
        "provider_name": "Mistral API",
        "category": "llm",
        "keyword_patterns": [
            "mistral api", "mistral client",
            "mistralai sdk", "mistral platform",
        ],
        "endpoint_patterns": ["api.mistral.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },

    # ═══════════════════════════════════════════════════════════
    # Cohere (2 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "cohere-api",
        "provider_name": "Cohere",
        "category": "llm",
        "keyword_patterns": [
            "cohere", "cohere api", "cohere ai",
            "command r", "command model", "cohere embed",
            "cohere generate",
        ],
        "endpoint_patterns": ["api.cohere.ai", "api.cohere.com"],
        "oauth_app_patterns": ["Cohere"],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "cohere-embed",
        "provider_name": "Cohere Embed",
        "category": "embedding",
        "keyword_patterns": [
            "cohere embed", "cohere embeddings",
            "embed-english", "embed-multilingual",
        ],
        "endpoint_patterns": ["api.cohere.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["embedding"],
        "data_egress_indicators": _EGRESS_EMBED,
    },

    # ═══════════════════════════════════════════════════════════
    # Hugging Face (2 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "huggingface-inference",
        "provider_name": "Hugging Face Inference",
        "category": "llm",
        "keyword_patterns": [
            "hugging face", "huggingface",
            "hf inference", "hugging face api",
            "inference api huggingface",
        ],
        "endpoint_patterns": [
            "api-inference.huggingface.co",
            "huggingface.co",
        ],
        "oauth_app_patterns": ["Hugging Face"],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "huggingface-hub",
        "provider_name": "Hugging Face Hub",
        "category": "data_ai",
        "keyword_patterns": [
            "huggingface hub", "hf hub",
            "hugging face hub", "transformers library",
        ],
        "endpoint_patterns": ["huggingface.co"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["data_ai"],
        "data_egress_indicators": _EGRESS_DATA,
    },

    # ═══════════════════════════════════════════════════════════
    # Stability AI (2 tools)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "stability-ai",
        "provider_name": "Stability AI",
        "category": "image_gen",
        "keyword_patterns": [
            "stability ai", "stable diffusion",
            "stabilityai", "sdxl", "stable diffusion xl",
            "dreamstudio", "stability api",
        ],
        "endpoint_patterns": ["api.stability.ai", "dreamstudio.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "stability-api",
        "provider_name": "Stability API",
        "category": "image_gen",
        "keyword_patterns": [
            "stability api", "stability sdk",
            "stable diffusion api", "stability rest api",
        ],
        "endpoint_patterns": ["api.stability.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },

    # ═══════════════════════════════════════════════════════════
    # Additional tools (19)
    # ═══════════════════════════════════════════════════════════
    {
        "slug": "midjourney",
        "provider_name": "Midjourney",
        "category": "image_gen",
        "keyword_patterns": [
            "midjourney", "mid journey",
            "mj bot", "midjourney v6",
        ],
        "endpoint_patterns": ["midjourney.com", "discord.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "perplexity-ai",
        "provider_name": "Perplexity AI",
        "category": "llm",
        "keyword_patterns": [
            "perplexity", "perplexity ai",
            "perplexity.ai", "pplx",
        ],
        "endpoint_patterns": ["api.perplexity.ai", "perplexity.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "amazon-bedrock",
        "provider_name": "Amazon Bedrock",
        "category": "llm",
        "keyword_patterns": [
            "bedrock", "amazon bedrock",
            "aws bedrock", "bedrock runtime",
        ],
        "endpoint_patterns": [
            "bedrock-runtime.*.amazonaws.com",
            "bedrock.*.amazonaws.com",
        ],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "critical",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "amazon-titan",
        "provider_name": "Amazon Titan",
        "category": "llm",
        "keyword_patterns": [
            "amazon titan", "aws titan",
            "titan text", "titan embeddings",
        ],
        "endpoint_patterns": ["bedrock-runtime.*.amazonaws.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "ibm-watson",
        "provider_name": "IBM Watson",
        "category": "llm",
        "keyword_patterns": [
            "watson", "ibm watson", "watsonx",
            "ibm watsonx", "watson nlp", "watson assistant",
        ],
        "endpoint_patterns": [
            "*.watsonplatform.net",
            "*.watson.cloud.ibm.com",
        ],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "salesforce-einstein",
        "provider_name": "Salesforce Einstein",
        "category": "llm",
        "keyword_patterns": [
            "einstein gpt", "salesforce ai",
            "einstein ai", "salesforce einstein",
            "agentforce",
        ],
        "endpoint_patterns": ["api.salesforce.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "adobe-firefly",
        "provider_name": "Adobe Firefly",
        "category": "image_gen",
        "keyword_patterns": [
            "firefly", "adobe firefly",
            "adobe ai", "adobe generative",
        ],
        "endpoint_patterns": ["firefly.adobe.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "runway-ml",
        "provider_name": "Runway ML",
        "category": "image_gen",
        "keyword_patterns": [
            "runway", "runway ml", "runwayml",
            "runway gen", "gen-2", "runway ai",
        ],
        "endpoint_patterns": ["api.runwayml.com", "runwayml.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["image_gen"],
        "data_egress_indicators": _EGRESS_IMAGE,
    },
    {
        "slug": "elevenlabs",
        "provider_name": "ElevenLabs",
        "category": "voice_ai",
        "keyword_patterns": [
            "elevenlabs", "eleven labs",
            "eleven labs api", "voice synthesis elevenlabs",
        ],
        "endpoint_patterns": ["api.elevenlabs.io"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["voice_ai"],
        "data_egress_indicators": _EGRESS_VOICE,
    },
    {
        "slug": "synthesia",
        "provider_name": "Synthesia",
        "category": "voice_ai",
        "keyword_patterns": [
            "synthesia", "synthesia io",
            "ai video synthesia", "synthesia video",
        ],
        "endpoint_patterns": ["api.synthesia.io"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["voice_ai"],
        "data_egress_indicators": _EGRESS_VOICE,
    },
    {
        "slug": "deepl",
        "provider_name": "DeepL",
        "category": "data_ai",
        "keyword_patterns": [
            "deepl", "deepl api", "deepl pro",
            "deepl translate",
        ],
        "endpoint_patterns": ["api.deepl.com", "api-free.deepl.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "low",
        "decay_lambda": DECAY_COEFFICIENTS["data_ai"],
        "data_egress_indicators": _EGRESS_DATA,
    },
    {
        "slug": "grammarly",
        "provider_name": "Grammarly",
        "category": "llm",
        "keyword_patterns": [
            "grammarly", "grammarly ai",
            "grammarly business", "grammarly go",
        ],
        "endpoint_patterns": ["api.grammarly.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "notion-ai",
        "provider_name": "Notion AI",
        "category": "llm",
        "keyword_patterns": [
            "notion ai", "notion intelligence",
            "ai in notion", "notion ai assistant",
        ],
        "endpoint_patterns": ["api.notion.so", "notion.so"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_IDENTITY_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "jasper-ai",
        "provider_name": "Jasper AI",
        "category": "llm",
        "keyword_patterns": [
            "jasper", "jasper ai", "jasper.ai",
            "jasper api", "jasper copywriting",
        ],
        "endpoint_patterns": ["api.jasper.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "copy-ai",
        "provider_name": "Copy.ai",
        "category": "llm",
        "keyword_patterns": [
            "copy.ai", "copyai", "copy ai",
            "copyai api",
        ],
        "endpoint_patterns": ["api.copy.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "groq",
        "provider_name": "Groq",
        "category": "llm",
        "keyword_patterns": [
            "groq", "groq api", "groq cloud",
            "groq llm", "groqcloud",
        ],
        "endpoint_patterns": ["api.groq.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "together-ai",
        "provider_name": "Together AI",
        "category": "llm",
        "keyword_patterns": [
            "together ai", "together.ai",
            "together api", "togetherai",
        ],
        "endpoint_patterns": ["api.together.ai", "api.together.xyz"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "deepseek",
        "provider_name": "DeepSeek",
        "category": "llm",
        "keyword_patterns": [
            "deepseek", "deep seek",
            "deepseek api", "deepseek chat",
            "deepseek coder",
        ],
        "endpoint_patterns": ["api.deepseek.com"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_ENDPOINT_HEAVY,
        "risk_level": "high",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
    {
        "slug": "xai-grok",
        "provider_name": "Grok",
        "category": "llm",
        "keyword_patterns": [
            "grok", "xai", "x.ai", "grok ai",
            "grok api", "elon ai",
        ],
        "endpoint_patterns": ["api.x.ai"],
        "oauth_app_patterns": [],
        "confidence_weights": _W_KEYWORD_HEAVY,
        "risk_level": "medium",
        "decay_lambda": DECAY_COEFFICIENTS["llm"],
        "data_egress_indicators": _EGRESS_LLM,
    },
]


TOTAL_SIGNATURES = len(KNOWN_AI_SIGNATURES)


def get_registry_stats() -> dict:
    """Return summary statistics about the registry."""
    by_category: dict[str, int] = {}
    by_risk_level: dict[str, int] = {}

    for sig in KNOWN_AI_SIGNATURES:
        cat = sig["category"]
        risk = sig["risk_level"]
        by_category[cat] = by_category.get(cat, 0) + 1
        by_risk_level[risk] = by_risk_level.get(risk, 0) + 1

    return {
        "version": REGISTRY_VERSION,
        "last_updated": REGISTRY_LAST_UPDATED,
        "total_signatures": TOTAL_SIGNATURES,
        "by_category": by_category,
        "by_risk_level": by_risk_level,
    }
