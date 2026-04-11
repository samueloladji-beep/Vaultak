"""
Vaultak PII Masking Module
Detects and masks sensitive data in agent inputs and outputs.
Works standalone or integrated with Vaultak Core SDK.

Detects:
- Credit card numbers
- Email addresses
- Phone numbers
- Social Security Numbers (SSN)
- API keys and tokens
- Passwords in key=value pairs
- IP addresses
- Dates of birth
- Passport numbers
- Bank account numbers
- AWS/GCP/Azure credentials
- Private keys (PEM headers)
- JWT tokens
- URLs with embedded credentials
"""

import re
import hashlib
import json
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum


class PIIType(str, Enum):
    CREDIT_CARD       = "credit_card"
    EMAIL             = "email"
    PHONE             = "phone"
    SSN               = "ssn"
    API_KEY           = "api_key"
    PASSWORD          = "password"
    IP_ADDRESS        = "ip_address"
    DATE_OF_BIRTH     = "date_of_birth"
    PASSPORT          = "passport"
    BANK_ACCOUNT      = "bank_account"
    AWS_KEY           = "aws_key"
    PRIVATE_KEY       = "private_key"
    JWT_TOKEN         = "jwt_token"
    URL_WITH_CREDS    = "url_with_credentials"
    GENERIC_SECRET    = "generic_secret"


@dataclass
class PIIMatch:
    pii_type:   PIIType
    original:   str
    masked:     str
    start:      int
    end:        int
    confidence: float = 1.0


@dataclass
class MaskingResult:
    original:       str
    masked:         str
    matches:        list = field(default_factory=list)
    pii_found:      bool = False
    risk_score:     float = 0.0

    def to_dict(self):
        return {
            "original_length": len(self.original),
            "masked":          self.masked,
            "pii_found":       self.pii_found,
            "risk_score":      self.risk_score,
            "detections":      [
                {
                    "type":       m.pii_type.value,
                    "masked":     m.masked,
                    "confidence": m.confidence,
                }
                for m in self.matches
            ],
        }


# Risk weight per PII type
PII_RISK_WEIGHTS = {
    PIIType.CREDIT_CARD:    0.95,
    PIIType.SSN:            0.95,
    PIIType.PRIVATE_KEY:    0.95,
    PIIType.AWS_KEY:        0.95,
    PIIType.PASSWORD:       0.90,
    PIIType.API_KEY:        0.90,
    PIIType.JWT_TOKEN:      0.85,
    PIIType.BANK_ACCOUNT:   0.85,
    PIIType.URL_WITH_CREDS: 0.85,
    PIIType.PASSPORT:       0.80,
    PIIType.DATE_OF_BIRTH:  0.70,
    PIIType.PHONE:          0.65,
    PIIType.EMAIL:          0.60,
    PIIType.IP_ADDRESS:     0.40,
    PIIType.GENERIC_SECRET: 0.80,
}

# Compiled regex patterns
PATTERNS = [
    # Credit cards (Visa, Mastercard, Amex, Discover)
    (PIIType.CREDIT_CARD,
     re.compile(
         r'\b(?:4[0-9]{12}(?:[0-9]{3})?'       # Visa
         r'|5[1-5][0-9]{14}'                    # Mastercard
         r'|3[47][0-9]{13}'                     # Amex
         r'|6(?:011|5[0-9]{2})[0-9]{12}'        # Discover
         r'|(?:\d{4}[-\s]){3}\d{4})\b'         # spaced/dashed
     ), 0.95),

    # SSN
    (PIIType.SSN,
     re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'), 0.90),

    # Email
    (PIIType.EMAIL,
     re.compile(
         r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
     ), 0.99),

    # Phone (US and international)
    (PIIType.PHONE,
     re.compile(
         r'(?:\+?1[-.\s]?)?'
         r'(?:\(?\d{3}\)?[-.\s]?)'
         r'\d{3}[-.\s]?\d{4}\b'
     ), 0.85),

    # JWT tokens
    (PIIType.JWT_TOKEN,
     re.compile(
         r'\beyJ[A-Za-z0-9_\-]+\.'
         r'[A-Za-z0-9_\-]+\.'
         r'[A-Za-z0-9_\-]+\b'
     ), 0.99),

    # AWS Access Key
    (PIIType.AWS_KEY,
     re.compile(r'\b(?:AKIA|AIPA|AIDA|AROA|ASIA)[A-Z0-9]{16}\b'), 0.99),

    # Generic API keys / tokens (key=value patterns)
    (PIIType.API_KEY,
     re.compile(
         r'(?i)(?:api[_\-]?key|token|secret|access[_\-]?key|auth)'
         r'\s*[:=]\s*'
         r'["\']?([A-Za-z0-9_\-\.]{16,})["\']?'
     ), 0.85),

    # Password patterns
    (PIIType.PASSWORD,
     re.compile(
         r'(?i)(?:password|passwd|pwd|pass)'
         r'\s*[:=]\s*'
         r'["\']?([^\s"\']{6,})["\']?'
     ), 0.85),

    # PEM private key header
    (PIIType.PRIVATE_KEY,
     re.compile(
         r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
     ), 0.99),

    # URL with embedded credentials
    (PIIType.URL_WITH_CREDS,
     re.compile(
         r'https?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-]+'
         r'@[A-Za-z0-9.\-]+'
     ), 0.95),

    # IP address
    (PIIType.IP_ADDRESS,
     re.compile(
         r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
         r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
     ), 0.80),

    # Date of birth patterns
    (PIIType.DATE_OF_BIRTH,
     re.compile(
         r'(?i)(?:dob|date.of.birth|born)\s*[:=]?\s*'
         r'(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})'
     ), 0.85),

    # Passport number (simple pattern)
    (PIIType.PASSPORT,
     re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), 0.60),

    # Bank account (IBAN or generic account numbers)
    (PIIType.BANK_ACCOUNT,
     re.compile(
         r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'  # IBAN
     ), 0.90),

    # Generic secrets (high-entropy strings after secret keywords)
    (PIIType.GENERIC_SECRET,
     re.compile(
         r'(?i)(?:secret|private|credential|key|token)'
         r'\s*[:=]\s*'
         r'["\']?([A-Za-z0-9+/=_\-]{20,})["\']?'
     ), 0.75),
]


def _mask_value(original: str, pii_type: PIIType,
                strategy: str = "partial") -> str:
    """
    Mask a detected PII value.
    strategy: 'partial' shows first/last chars, 'full' replaces entirely,
              'hash' replaces with a deterministic hash token
    """
    if strategy == "full":
        return f"[{pii_type.value.upper()}]"

    if strategy == "hash":
        token = hashlib.sha256(original.encode()).hexdigest()[:8]
        return f"[{pii_type.value.upper()}:{token}]"

    # Partial masking: show context but hide sensitive part
    n = len(original)
    if pii_type == PIIType.EMAIL:
        parts = original.split("@")
        if len(parts) == 2:
            local = parts[0]
            visible = local[0] if local else "*"
            return f"{visible}{'*' * min(4, len(local)-1)}@{parts[1]}"

    if pii_type == PIIType.CREDIT_CARD:
        digits = re.sub(r'\D', '', original)
        return f"{'*' * (len(digits)-4)}{digits[-4:]}"

    if pii_type == PIIType.PHONE:
        digits = re.sub(r'\D', '', original)
        return f"{'*' * (len(digits)-4)}{digits[-4:]}"

    if n <= 4:
        return "*" * n
    if n <= 8:
        return original[0] + "*" * (n-2) + original[-1]

    show = max(2, n // 6)
    return original[:show] + "*" * (n - show * 2) + original[-show:]


class PIIMasker:
    """
    Main PII detection and masking engine.

    Usage:
        masker = PIIMasker()
        result = masker.mask("My email is john@example.com and SSN is 123-45-6789")
        print(result.masked)
        # "My email is j****@example.com and SSN is [SSN]"
    """

    def __init__(
        self,
        strategy:         str        = "partial",
        enabled_types:    list       = None,
        disabled_types:   list       = None,
        custom_patterns:  list       = None,
        min_confidence:   float      = 0.75,
    ):
        self.strategy       = strategy
        self.min_confidence = min_confidence
        self.enabled_types  = set(enabled_types)  if enabled_types  else None
        self.disabled_types = set(disabled_types) if disabled_types else set()
        self.patterns       = list(PATTERNS)

        if custom_patterns:
            for pii_type, pattern, confidence in custom_patterns:
                self.patterns.append((pii_type, re.compile(pattern), confidence))

    def mask(self, text: str) -> MaskingResult:
        if not text or not isinstance(text, str):
            return MaskingResult(original=text or "", masked=text or "")

        matches   = []
        positions = set()

        for pii_type, pattern, confidence in self.patterns:
            if confidence < self.min_confidence:
                continue
            if self.enabled_types and pii_type not in self.enabled_types:
                continue
            if pii_type in self.disabled_types:
                continue

            for m in pattern.finditer(text):
                start, end = m.start(), m.end()
                # Avoid overlapping matches
                overlap = any(
                    not (end <= p[0] or start >= p[1])
                    for p in positions
                )
                if overlap:
                    continue

                original_val = m.group(0)
                masked_val   = _mask_value(original_val, pii_type,
                                           self.strategy)
                matches.append(PIIMatch(
                    pii_type   = pii_type,
                    original   = original_val,
                    masked     = masked_val,
                    start      = start,
                    end        = end,
                    confidence = confidence,
                ))
                positions.add((start, end))

        # Sort by position descending so replacements don't shift indices
        matches.sort(key=lambda x: x.start, reverse=True)

        masked_text = text
        for match in matches:
            masked_text = (
                masked_text[:match.start]
                + match.masked
                + masked_text[match.end:]
            )

        # Compute overall risk score
        risk = 0.0
        if matches:
            risk = max(PII_RISK_WEIGHTS.get(m.pii_type, 0.5)
                       for m in matches)

        return MaskingResult(
            original   = text,
            masked     = masked_text,
            matches    = sorted(matches, key=lambda x: x.start),
            pii_found  = len(matches) > 0,
            risk_score = risk,
        )

    def scan(self, text: str) -> bool:
        """Quick check: returns True if any PII is detected."""
        return self.mask(text).pii_found

    def mask_dict(self, data: dict,
                  keys_to_mask: list = None) -> dict:
        """
        Recursively mask PII in all string values of a dict.
        Optionally only mask specific keys.
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                if keys_to_mask is None or key in keys_to_mask:
                    result[key] = self.mask(value).masked
                else:
                    result[key] = value
            elif isinstance(value, dict):
                result[key] = self.mask_dict(value, keys_to_mask)
            elif isinstance(value, list):
                result[key] = [
                    self.mask(v).masked if isinstance(v, str) else v
                    for v in value
                ]
            else:
                result[key] = value
        return result


# ── Integration with Vaultak Core ────────────────────────────────────────────

class VaultakPIIGuard:
    """
    Drop-in PII guard for Vaultak Core.
    Wraps agent inputs and outputs with automatic PII masking.

    Usage with Vaultak Core:
        from vaultak import Vaultak
        from vaultak_pii import VaultakPIIGuard

        guard  = VaultakPIIGuard()
        vt     = Vaultak(api_key="vtk_...")

        # Before sending input to your agent
        safe_input = guard.guard_input(user_message)

        with vt.monitor("my-agent"):
            result = agent.run(safe_input.masked)

        # Before returning output to the user
        safe_output = guard.guard_output(result)
        return safe_output.masked

    """

    def __init__(self, strategy: str = "partial",
                 log_detections: bool = True):
        self.masker         = PIIMasker(strategy=strategy)
        self.log_detections = log_detections
        self._log           = []

    def guard_input(self, text: str) -> MaskingResult:
        result = self.masker.mask(text)
        if result.pii_found and self.log_detections:
            self._log.append({
                "direction": "input",
                "types":     [m.pii_type.value for m in result.matches],
                "risk":      result.risk_score,
            })
        return result

    def guard_output(self, text: str) -> MaskingResult:
        result = self.masker.mask(text)
        if result.pii_found and self.log_detections:
            self._log.append({
                "direction": "output",
                "types":     [m.pii_type.value for m in result.matches],
                "risk":      result.risk_score,
            })
        return result

    def detection_log(self) -> list:
        return list(self._log)

    def clear_log(self):
        self._log.clear()


# ── Standalone CLI ────────────────────────────────────────────────────────────

def main():
    import argparse, sys

    parser = argparse.ArgumentParser(
        prog="vaultak-pii",
        description="Vaultak PII Scanner and Masker"
    )
    parser.add_argument("text", nargs="?",
                        help="Text to scan (or pipe via stdin)")
    parser.add_argument("--strategy",
                        choices=["partial", "full", "hash"],
                        default="partial",
                        help="Masking strategy (default: partial)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--scan-only", action="store_true",
                        help="Only report if PII found, do not mask")

    args = parser.parse_args()

    text = args.text
    if not text:
        text = sys.stdin.read()

    masker = PIIMasker(strategy=args.strategy)
    result = masker.mask(text)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    if args.scan_only:
        if result.pii_found:
            print(f"PII DETECTED: {len(result.matches)} match(es)")
            for m in result.matches:
                print(f"  {m.pii_type.value}  (confidence: {m.confidence:.0%})")
            sys.exit(1)
        else:
            print("No PII detected.")
            sys.exit(0)

    print(result.masked)
    if result.pii_found:
        print(f"\n[Vaultak PII]  {len(result.matches)} detection(s)  "
              f"risk: {result.risk_score:.2f}", file=sys.stderr)


if __name__ == "__main__":
    main()
