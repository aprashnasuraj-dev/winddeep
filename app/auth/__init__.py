"""Authentication and session assurance subsystem for authorized Windeep testing."""

from app.auth.protocols import JWTAnalysis, OAuthAnalysis, SAMLAnalysis, analyze_jwt, analyze_oauth, analyze_saml
from app.auth.session_analysis import SessionAnalysis, SessionToken, analyze_sessions
from app.auth.suite import AUTH_TECHNIQUES, AuthBypassSuite, AuthTechnique, AuthTestResult

__all__ = [
    "AUTH_TECHNIQUES",
    "AuthBypassSuite",
    "AuthTechnique",
    "AuthTestResult",
    "JWTAnalysis",
    "OAuthAnalysis",
    "SAMLAnalysis",
    "SessionAnalysis",
    "SessionToken",
    "analyze_jwt",
    "analyze_oauth",
    "analyze_saml",
    "analyze_sessions",
]
