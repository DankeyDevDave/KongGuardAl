"""Kong Guard AI - Enterprise security plugin for Kong Gateway."""

__version__ = "2.0.0"
__author__ = "Jacques Wainwright"
__email__ = "jacques@jacqueswainwright.com"
__description__ = "Enterprise AI-powered security plugin for Kong Gateway with advanced threat detection"

from kongguard.ai_service import AIThreatAnalyzer
from kongguard.ml_models import ModelManager

__all__ = ["AIThreatAnalyzer", "ModelManager", "__version__"]
