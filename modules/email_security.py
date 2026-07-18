"""Email security compatibility wrapper."""

from phantomscan.email_security import analyze_email
from phantomscan.scope import root_domain

__all__ = ["analyze_email", "root_domain"]
