"""
Kong Guard AI - Machine Learning Models
Copyright (c) 2024 Jacques Francois Coetzee. All Rights Reserved.

PROPRIETARY AND CONFIDENTIAL
Advanced ML-powered threat detection and prevention
"""

from .anomaly_detector import AnomalyDetector
from .attack_classifier import AttackClassifier
from .feature_extractor import FeatureExtractor
from .model_manager import ModelManager

__all__ = ["AnomalyDetector", "AttackClassifier", "FeatureExtractor", "ModelManager"]

__version__ = "1.0.0"
