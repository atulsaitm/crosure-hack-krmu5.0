"""Attack primitive definitions and transition rules for chain discovery."""

from dataclasses import dataclass, field
from typing import Set, Dict
from core.models import AttackType, AttackPrimitive


@dataclass
class TransitionRule:
    """Defines which primitives can chain into which other primitives."""
    from_primitive: AttackPrimitive
    to_primitive: AttackPrimitive
    required_conditions: Set[str] = field(default_factory=set)
    boost: float = 1.0  # Multiplier when this transition occurs


# ── Primitive → AttackType mapping ──
ATTACK_TYPE_TO_PRIMITIVE: Dict[AttackType, AttackPrimitive] = {
    # Code Execution
    AttackType.SSTI: AttackPrimitive.CODE_EXEC,
    AttackType.RCE: AttackPrimitive.CODE_EXEC,
    AttackType.COMMAND_INJECTION: AttackPrimitive.CODE_EXEC,
    AttackType.DESERIALIZATION: AttackPrimitive.CODE_EXEC,
    AttackType.PROTOTYPE_POLLUTION: AttackPrimitive.CODE_EXEC,

    # XSS / Client-side
    AttackType.XSS: AttackPrimitive.SESSION_HIJACK,
    AttackType.CSTI: AttackPrimitive.SESSION_HIJACK,
    AttackType.CORS: AttackPrimitive.DATA_ACCESS,
    AttackType.WEBSOCKET: AttackPrimitive.DATA_ACCESS,

    # Data Access
    AttackType.SQLI: AttackPrimitive.DATA_ACCESS,
    AttackType.BOLA: AttackPrimitive.DATA_ACCESS,
    AttackType.SSRF: AttackPrimitive.DATA_ACCESS,

    # Auth
    AttackType.BAC: AttackPrimitive.AUTH_BYPASS,
    AttackType.AUTH_BYPASS: AttackPrimitive.AUTH_BYPASS,
    AttackType.JWT: AttackPrimitive.AUTH_BYPASS,
    AttackType.SESSION: AttackPrimitive.SESSION_HIJACK,

    # Escalation
    AttackType.MASS_ASSIGNMENT: AttackPrimitive.PRIVILEGE_ESCALATION,

    # Info
    AttackType.MISCONFIG: AttackPrimitive.INFO_DISCLOSURE,
    AttackType.GRAPHQL: AttackPrimitive.INFO_DISCLOSURE,
}


# ── Transition Rules ──
# These define how one vulnerability primitive can chain into another.
TRANSITION_RULES: list[TransitionRule] = [
    # XSS → Session Hijack → Auth Bypass
    TransitionRule(AttackPrimitive.SESSION_HIJACK, AttackPrimitive.AUTH_BYPASS, boost=1.4),

    # Info Disclosure → Data Access (leaked info helps exploit access)
    TransitionRule(AttackPrimitive.INFO_DISCLOSURE, AttackPrimitive.DATA_ACCESS, boost=1.2),

    # Info Disclosure → Auth Bypass (leaked creds/tokens)
    TransitionRule(AttackPrimitive.INFO_DISCLOSURE, AttackPrimitive.AUTH_BYPASS, boost=1.3),

    # Auth Bypass → Data Access (once authed, access data)
    TransitionRule(AttackPrimitive.AUTH_BYPASS, AttackPrimitive.DATA_ACCESS, boost=1.5),

    # Auth Bypass → Privilege Escalation
    TransitionRule(AttackPrimitive.AUTH_BYPASS, AttackPrimitive.PRIVILEGE_ESCALATION, boost=1.4),

    # Data Access → Code Exec (e.g., SQLi → RCE via xp_cmdshell)
    TransitionRule(AttackPrimitive.DATA_ACCESS, AttackPrimitive.CODE_EXEC, boost=1.6),

    # Auth Bypass → Code Exec (admin panel → RCE)
    TransitionRule(AttackPrimitive.AUTH_BYPASS, AttackPrimitive.CODE_EXEC, boost=1.5),

    # Session Hijack → Data Access (stolen session → access data)
    TransitionRule(AttackPrimitive.SESSION_HIJACK, AttackPrimitive.DATA_ACCESS, boost=1.3),

    # Privilege Escalation → Code Exec
    TransitionRule(AttackPrimitive.PRIVILEGE_ESCALATION, AttackPrimitive.CODE_EXEC, boost=1.3),

    # Data Access → Privilege Escalation (dump admin creds from DB)
    TransitionRule(AttackPrimitive.DATA_ACCESS, AttackPrimitive.PRIVILEGE_ESCALATION, boost=1.4),

    # Code Exec → Data Access (full system access)
    TransitionRule(AttackPrimitive.CODE_EXEC, AttackPrimitive.DATA_ACCESS, boost=1.1),

    # Info Disclosure → Code Exec (leak secrets → exploit)
    TransitionRule(AttackPrimitive.INFO_DISCLOSURE, AttackPrimitive.CODE_EXEC, boost=1.2),

    # Session Hijack → Privilege Escalation (steal admin session)
    TransitionRule(AttackPrimitive.SESSION_HIJACK, AttackPrimitive.PRIVILEGE_ESCALATION, boost=1.3),
]


def get_allowed_transitions() -> Dict[AttackPrimitive, list[AttackPrimitive]]:
    """Build adjacency map of primitive transitions."""
    adjacency: Dict[AttackPrimitive, list[AttackPrimitive]] = {}
    for rule in TRANSITION_RULES:
        if rule.from_primitive not in adjacency:
            adjacency[rule.from_primitive] = []
        adjacency[rule.from_primitive].append(rule.to_primitive)
    return adjacency


def get_transition_boost(from_p: AttackPrimitive, to_p: AttackPrimitive) -> float:
    """Get the boost multiplier for a specific transition."""
    for rule in TRANSITION_RULES:
        if rule.from_primitive == from_p and rule.to_primitive == to_p:
            return rule.boost
    return 1.0
