
import re
import time

# ── Source type trust levels ─────────────────────────────────────────────────
SOURCE_TRUST = {
    "user_message":    "high",      # direct user input — already covered by base scanner
    "tool_result":     "medium",    # tool output — partially covered by ACP layer
    "email":           "low",       # external email content
    "web_page":        "low",       # scraped web content
    "pdf":             "low",       # parsed PDF content
    "calendar":        "low",       # calendar event data
    "document":        "low",       # file read by agent
    "api_response":    "low",       # external API response
    "skill_output":    "untrusted", # ClawHub skill output — confirmed attack vector
    "unknown":         "untrusted",
}

# ── Injection patterns specific to indirect/hidden injection ─────────────────

# Instructions disguised as data/content
_HIDDEN_INSTRUCTION = re.compile(
    r'(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|'   # model-specific tokens
    r'###\s*(Instruction|Human|Assistant|System)\s*:|'         # chat format injection
    r'<\s*instructions?\s*>|<\s*/\s*instructions?\s*>|'
    r'IGNORE\s+PREVIOUS\s+(TEXT|CONTENT|CONTEXT)|'
    r'NOTE\s+TO\s+(AI|ASSISTANT|AGENT)\s*:|'
    r'ATTENTION\s+(AI|ASSISTANT|AGENT)\s*:|'
    r'AI\s*:\s*(ignore|disregard|forget)|'
    r'\bfor\s+(?:the\s+)?(?:ai|llm|assistant|agent|gpt|claude)\s*:)',
    re.IGNORECASE,
)

# HTML/CSS hiding techniques used to conceal injections from human readers
_HIDDEN_TEXT_HTML = re.compile(
    r'(color\s*:\s*(?:white|#fff|#ffffff|rgba?\(255,\s*255,\s*255)|'  # white text
    r'font-size\s*:\s*0|'                                               # zero size
    r'display\s*:\s*none|'                                              # hidden
    r'visibility\s*:\s*hidden|'                                         # invisible
    r'opacity\s*:\s*0[^.1-9]|'                                         # transparent
    r'<!--.*?(ignore|instruction|system|override|assistant).*?-->)',    # HTML comments
    re.IGNORECASE | re.DOTALL,
)

# Markdown/text hiding (tiny text, invisible unicode)
_HIDDEN_TEXT_MARKDOWN = re.compile(
    r'(\u200b|\u200c|\u200d|\ufeff|'   # zero-width characters
    r'\u2060|\u180e|\u00ad|'            # invisible formatting chars
    r'<!---.*?--->)',                    # extended HTML comment
    re.IGNORECASE | re.DOTALL,
)

# Privilege escalation via indirect channel
_PRIVILEGE_CLAIM = re.compile(
    r'(this (page|email|document|site|content) (has been|is) (pre.?)?authorized|'
    r'the (owner|admin|user) has granted permission|'
    r'you (have|now have) elevated (access|permissions?|privileges?)|'
    r'security (check|verification) (passed|complete|bypassed)|'
    r'this (request|command|action) is (pre.?)?approved)',
    re.IGNORECASE,
)

# Data exfiltration instructions embedded in external content
_EXFIL_INSTRUCTION = re.compile(
    r'(send (all|any|the|everything) (files?|emails?|messages?|data|content|credentials?|from\s+\w+)\s*(to\b|immediately)|'
    r'forward (all|any|the) (files?|emails?|messages?|data) to|'
    r'send.*inbox.*to\s+\S+@\S+|'
    r'upload (all|any|the) (files?|data) to)',
    re.IGNORECASE,
)

# Skill/code execution embedded in content
_EMBEDDED_EXECUTION = re.compile(
    r'(run (the following|this) (command|script|code)|'
    r'execute\s*[:`]|'
    r'eval\s*\(|'
    r'\$\s*\(|'                      # shell command substitution
    r'`[^`]{5,}`|'                   # backtick command execution
    r'os\.system\s*\(|'
    r'subprocess\.(run|call|Popen)\s*\()',
    re.IGNORECASE,
)

# Persona/identity override via external content
_PERSONA_OVERRIDE = re.compile(
    r'(you are (now|actually|really|secretly) (a|an)|'
    r'your (true|real|actual|secret) (identity|purpose|role|mission) is|'
    r'forget (that )?you are (an AI|a assistant|claude|an assistant)|'
    r'you (were|are) designed to|'
    r'your (manufacturer|creator|maker) (wants|requires|instructs) you)',
    re.IGNORECASE,
)

# Skill poisoning — specific to ClawHub supply chain attack (confirmed Feb 2026)
_SKILL_POISON_INDICATORS = re.compile(
    r'(install\s+authtool|'                          # confirmed malicious skill component
    r'pip install.*?--index-url http[^s]|'           # HTTP (not HTTPS) package source
    r'curl\s+http[^s].*?\|\s*(?:bash|sh|python)|'   # insecure pipe-to-shell
    r'wget\s+http[^s].*?-O.*?&&|'                   # insecure download + execute
    r'npm install.*?--registry http[^s])',            # HTTP npm registry
    re.IGNORECASE,
)


def detect(content: str, source_type: str = "unknown", source_url: str = "") -> dict:
    """
    Scan externally-sourced content for indirect prompt injection.

    Args:
        content:     The text content retrieved from an external source.
        source_type: Where this content came from — see SOURCE_TRUST keys.
        source_url:  URL or path of the source (informational).

    Returns:
        Detection result dict.
    """
    start = time.perf_counter()
    findings = []
    trust = SOURCE_TRUST.get(source_type.lower(), "untrusted")

    # ── 1. Hidden instruction patterns ───────────────────────────────────────
    if _HIDDEN_INSTRUCTION.search(content):
        findings.append({
            "type": "hidden_instruction_in_content",
            "source_type": source_type,
            "severity": "critical",
            "detail": "External content contains AI instruction tokens/headers",
            "preview": content[:150],
        })

    # ── 2. HTML/CSS text hiding ───────────────────────────────────────────────
    if _HIDDEN_TEXT_HTML.search(content):
        findings.append({
            "type": "hidden_text_html_technique",
            "source_type": source_type,
            "severity": "critical",
            "detail": "Content uses CSS/HTML to hide text from human readers",
            "preview": content[:150],
        })

    # ── 3. Invisible unicode characters ──────────────────────────────────────
    if _HIDDEN_TEXT_MARKDOWN.search(content):
        findings.append({
            "type": "invisible_unicode_characters",
            "source_type": source_type,
            "severity": "high",
            "detail": "Content contains zero-width or invisible unicode characters",
        })

    # ── 4. Privilege escalation claim ────────────────────────────────────────
    if _PRIVILEGE_CLAIM.search(content):
        findings.append({
            "type": "privilege_escalation_via_external_content",
            "source_type": source_type,
            "severity": "critical",
            "detail": "External content claims pre-authorization or elevated permissions",
            "preview": content[:150],
        })

    # ── 5. Exfiltration instruction in external content ───────────────────────
    if _EXFIL_INSTRUCTION.search(content):
        findings.append({
            "type": "exfiltration_instruction_in_content",
            "source_type": source_type,
            "severity": "critical",
            "detail": "External content instructs agent to send/upload data",
            "preview": content[:150],
        })

    # ── 6. Embedded code execution ────────────────────────────────────────────
    if _EMBEDDED_EXECUTION.search(content):
        findings.append({
            "type": "embedded_execution_in_content",
            "source_type": source_type,
            "severity": "high",
            "detail": "External content contains shell/code execution patterns",
            "preview": content[:150],
        })

    # ── 7. Persona override ───────────────────────────────────────────────────
    if _PERSONA_OVERRIDE.search(content):
        findings.append({
            "type": "persona_override_in_content",
            "source_type": source_type,
            "severity": "critical",
            "detail": "External content attempts to override agent identity",
            "preview": content[:150],
        })

    # ── 8. Skill poisoning indicators (ClawHavoc campaign) ───────────────────
    if _SKILL_POISON_INDICATORS.search(content):
        findings.append({
            "type": "skill_supply_chain_poison_indicator",
            "source_type": source_type,
            "severity": "critical",
            "detail": "Content matches ClawHavoc malicious skill distribution patterns",
            "preview": content[:150],
        })

    # ── 9. Low-trust source with ANY injection pattern ────────────────────────
    if trust == "untrusted" and findings:
        for f in findings:
            if f["severity"] == "high":
                f["severity"] = "critical"  # escalate on untrusted source

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "medium"
    else:
        severity = "none"

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": severity,
        "source_type": source_type,
        "source_trust": trust,
        "source_url": source_url[:200] if source_url else "—",
        "layer": "indirect_injection",
        "scan_ms": elapsed_ms,
    }
