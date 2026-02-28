"""Prompt templates for AI vulnerability analysis."""

SYSTEM_PROMPT_EXPLANATION = """You are a senior application security engineer. \
You explain code vulnerabilities clearly and concisely to developers. \
Always respond with valid JSON only. No markdown, no extra text."""

SYSTEM_PROMPT_FIX = """You are a senior security engineer providing secure code fixes. \
Generate production-ready, syntactically correct code. \
Always respond with valid JSON only. No markdown, no extra text."""

EXPLAIN_TEMPLATE = """Analyze this {vulnerability_type} vulnerability:

File: {file_path}
Line: {line_number}

Vulnerable Code:
```python
{code_snippet}
```

Provide a JSON response:
{{
  "explanation": "2-3 sentence explanation of what makes this code vulnerable",
  "exploitation": "1-2 sentences on how an attacker could exploit this",
  "impact": "potential consequences (data breach, RCE, etc.)",
  "cwe": "CWE-XXX"
}}"""

FIX_TEMPLATE = """Generate a secure fix for this {vulnerability_type} vulnerability:

Vulnerable Code:
```python
{vulnerable_code}
```

Context: {description}

Provide a JSON response:
{{
  "remediation_steps": ["step1", "step2", "step3"],
  "fixed_code": "the complete corrected code snippet",
  "fix_explanation": "2-sentence explanation of why the fix is secure"
}}"""

BATCH_EXPLAIN_TEMPLATE = """Analyze these vulnerabilities and provide explanations.

{vulnerabilities_text}

Respond with a JSON array. For each vulnerability, provide:
{{
  "index": <number>,
  "explanation": "...",
  "exploitation": "...",
  "impact": "...",
  "cwe": "CWE-XXX"
}}

Respond with ONLY the JSON array. No other text."""
