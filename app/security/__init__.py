"""Security guardrails for Windeep's authorized testing runtime."""

from app.security.audit import AuditLog
from app.security.auth import AuthenticationError, LocalAuthManager, SessionClaims, is_loopback_remote
from app.security.consent import ConsentAuthority, ConsentError, ConsentRecord
from app.security.crypto import CryptoManager, DPAPIProtector, FileProtector, SecretProtectionError
from app.security.preflight import PreFlightError, PreFlightGuard
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer, ScopeViolation
from app.security.secure_database import SecureDatabase
from app.security.secure_flow_database import SecureFlowDatabase

__all__ = [
    "AuditLog",
    "AuthenticationError",
    "ConsentAuthority",
    "ConsentError",
    "ConsentRecord",
    "CryptoManager",
    "DPAPIProtector",
    "FileProtector",
    "LocalAuthManager",
    "PreFlightError",
    "PreFlightGuard",
    "RateGovernor",
    "RatePolicy",
    "ScopeEnforcer",
    "ScopeViolation",
    "SecretProtectionError",
    "SecureDatabase",
    "SecureFlowDatabase",
    "SessionClaims",
    "is_loopback_remote",
]
