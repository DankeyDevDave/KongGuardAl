"""
Kong Guard AI - Model Management Module
Orchestrates all ML models for comprehensive threat detection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import joblib
import json
import logging
import asyncio
from pathlib import Path
import threading
from collections import deque

from .anomaly_detector import AnomalyDetector
from .attack_classifier import AttackClassifier
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

class ModelManager:
    """
    Centralized ML model orchestration and management
    """
    
    def __init__(self, model_dir: str = "models/trained"):
        """
        Initialize the model manager
        
        Args:
            model_dir: Directory to store/load trained models
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector(contamination=0.1)
        self.attack_classifier = AttackClassifier(model_type='random_forest')
        
        # Model metadata
        self.models_loaded = False
        self.last_training_time = None
        self.model_versions = {
            'anomaly': '1.0.0',
            'classifier': '1.0.0',
            'features': '1.0.0'
        }
        
        # Performance tracking
        self.prediction_cache = {}
        self.cache_ttl = 60  # seconds
        self.metrics = {
            'total_requests': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'processing_times': deque(maxlen=1000),
            'accuracy_history': deque(maxlen=100)
        }
        
        # Threat intelligence
        self.threat_patterns = {}
        self.known_attackers = set()
        self.whitelist = set()
        
        # Auto-training configuration
        self.auto_train_enabled = True
        self.training_buffer = deque(maxlen=5000)
        self.min_training_samples = 1000
        
        # Load existing models if available
        self.load_models()
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive request analysis using all ML models
        
        Args:
            request_data: Complete request information
            
        Returns:
            Comprehensive threat analysis results
        """
        start_time = datetime.now()
        
        # Check cache
        cache_key = self._generate_cache_key(request_data)
        if cache_key in self.prediction_cache:
            cached = self.prediction_cache[cache_key]
            if (datetime.now() - cached['timestamp']).seconds < self.cache_ttl:
                return cached['result']
        
        # Extract features
        features = self.feature_extractor.extract_all_features(request_data)
        
        # Run anomaly detection
        anomaly_result = self.anomaly_detector.predict(request_data)
        
        # Run attack classification
        attack_result = self.attack_classifier.predict(request_data)
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(
            features, anomaly_result, attack_result
        )
        
        # Determine action
        action = self._determine_action(threat_score, attack_result)
        
        # Generate comprehensive analysis
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'threat_score': threat_score,
            'risk_level': self._get_risk_level(threat_score),
            'anomaly': {
                'is_anomaly': anomaly_result['is_anomaly'],
                'score': anomaly_result['anomaly_score'],
                'confidence': anomaly_result['confidence'],
                'reason': anomaly_result['reason']
            },
            'classification': {
                'attack_type': attack_result['attack_type'],
                'confidence': attack_result['confidence'],
                'top_3': attack_result.get('top_3', [attack_result['attack_type']]),
                'probabilities': attack_result['probabilities']
            },
            'action': action,
            'features_summary': self._summarize_features(features),
            'processing_time_ms': (datetime.now() - start_time).total_seconds() * 1000
        }
        
        # Update metrics
        self.metrics['total_requests'] += 1
        if threat_score > 0.5:
            self.metrics['threats_detected'] += 1
        self.metrics['processing_times'].append(analysis['processing_time_ms'])
        
        # Cache result
        self.prediction_cache[cache_key] = {
            'timestamp': datetime.now(),
            'result': analysis
        }
        
        # Store for training
        if self.auto_train_enabled:
            self.training_buffer.append({
                'request': request_data,
                'features': features,
                'analysis': analysis,
                'timestamp': datetime.now()
            })
            
            # Auto-train if buffer is full
            if len(self.training_buffer) >= self.min_training_samples:
                self._trigger_auto_training()
        
        return analysis
    
    def _calculate_threat_score(self, features: Dict[str, float], 
                                anomaly_result: Dict[str, Any],
                                attack_result: Dict[str, Any]) -> float:
        """
        Calculate unified threat score from all models
        
        Args:
            features: Extracted features
            anomaly_result: Anomaly detection results
            attack_result: Attack classification results
            
        Returns:
            Threat score between 0 and 1
        """
        # Base score from models
        anomaly_weight = 0.3
        classification_weight = 0.4
        features_weight = 0.3
        
        # Anomaly contribution
        anomaly_score = anomaly_result['anomaly_score'] if anomaly_result['is_anomaly'] else 0
        
        # Classification contribution
        if attack_result['attack_type'] != 'normal':
            classification_score = attack_result['confidence']
        else:
            classification_score = 0
        
        # Feature-based risk indicators
        feature_score = 0
        risk_features = [
            'sql_risk_score', 'xss_risk_score', 'path_risk_score',
            'cmd_risk_score', 'overall_risk_score'
        ]
        
        for feature in risk_features:
            if feature in features:
                feature_score = max(feature_score, features[feature])
        
        # Behavioral indicators
        if features.get('is_high_rate', 0) > 0:
            feature_score = max(feature_score, 0.7)
        if features.get('is_burst', 0) > 0:
            feature_score = max(feature_score, 0.8)
        
        # Calculate weighted score
        threat_score = (
            anomaly_weight * anomaly_score +
            classification_weight * classification_score +
            features_weight * feature_score
        )
        
        # Apply modifiers
        if attack_result['attack_type'] in ['sql_injection', 'command_injection', 'xxe']:
            threat_score = min(threat_score * 1.5, 1.0)  # Critical attacks
        
        if features.get('temporal_risk', 0) > 0:
            threat_score = min(threat_score * (1 + features['temporal_risk']), 1.0)
        
        return float(min(max(threat_score, 0), 1))
    
    def _determine_action(self, threat_score: float, 
                         attack_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determine recommended action based on threat analysis
        
        Args:
            threat_score: Overall threat score
            attack_result: Attack classification results
            
        Returns:
            Action recommendation
        """
        if threat_score >= 0.9:
            return {
                'action': 'block',
                'reason': 'Critical threat detected',
                'confidence': 'high',
                'additional': ['log_incident', 'alert_admin', 'add_to_blacklist']
            }
        elif threat_score >= 0.7:
            return {
                'action': 'block',
                'reason': f"High risk {attack_result['attack_type']} detected",
                'confidence': 'high',
                'additional': ['log_warning', 'rate_limit']
            }
        elif threat_score >= 0.5:
            return {
                'action': 'challenge',
                'reason': 'Suspicious activity detected',
                'confidence': 'medium',
                'additional': ['captcha', 'log_warning']
            }
        elif threat_score >= 0.3:
            return {
                'action': 'monitor',
                'reason': 'Elevated risk indicators',
                'confidence': 'low',
                'additional': ['increase_logging', 'track_session']
            }
        else:
            return {
                'action': 'allow',
                'reason': 'Normal traffic',
                'confidence': 'high',
                'additional': []
            }
    
    def _get_risk_level(self, threat_score: float) -> str:
        """Get human-readable risk level"""
        if threat_score >= 0.8:
            return 'CRITICAL'
        elif threat_score >= 0.6:
            return 'HIGH'
        elif threat_score >= 0.4:
            return 'MEDIUM'
        elif threat_score >= 0.2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _summarize_features(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Summarize key features for reporting
        
        Args:
            features: All extracted features
            
        Returns:
            Summary of important features
        """
        summary = {
            'request_characteristics': {
                'size': features.get('request_size', 0),
                'method': self._get_method_from_features(features),
                'path_depth': features.get('path_depth', 0),
                'has_auth': bool(features.get('has_auth', 0))
            },
            'security_indicators': {
                'sql_risk': features.get('sql_risk_score', 0),
                'xss_risk': features.get('xss_risk_score', 0),
                'injection_risk': features.get('cmd_risk_score', 0),
                'traversal_risk': features.get('path_risk_score', 0)
            },
            'behavioral': {
                'request_rate': features.get('requests_per_minute', 0),
                'is_bot': bool(features.get('is_bot', 0)),
                'temporal_risk': features.get('temporal_risk', 0)
            }
        }
        return summary
    
    def _get_method_from_features(self, features: Dict[str, float]) -> str:
        """Extract HTTP method from one-hot encoded features"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        for method in methods:
            if features.get(f'method_{method}', 0) == 1:
                return method
        return 'UNKNOWN'
    
    def _generate_cache_key(self, request_data: Dict[str, Any]) -> str:
        """Generate cache key for request"""
        import hashlib
        key_parts = [
            request_data.get('method', ''),
            request_data.get('path', ''),
            str(request_data.get('body', '')),
            str(request_data.get('headers', {}))
        ]
        key_str = '|'.join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def train_models(self, training_data: List[Dict[str, Any]], 
                     labels: Optional[Dict[str, List]] = None):
        """
        Train all ML models
        
        Args:
            training_data: List of request dictionaries
            labels: Optional labels for supervised learning
        """
        logger.info(f"Training models with {len(training_data)} samples")
        
        # Train anomaly detector
        self.anomaly_detector.train(training_data)
        
        # Train classifier if labels provided
        if labels and 'attack_types' in labels:
            self.attack_classifier.train(training_data, labels['attack_types'])
        
        self.last_training_time = datetime.now()
        self.save_models()
        
        logger.info("Model training complete")
    
    def _trigger_auto_training(self):
        """Trigger automatic model retraining"""
        def train_async():
            try:
                # Extract training data
                requests = [item['request'] for item in self.training_buffer]
                
                # Train models
                self.anomaly_detector.retrain()
                
                # Clear buffer
                self.training_buffer.clear()
                
                logger.info("Auto-training complete")
            except Exception as e:
                logger.error(f"Auto-training failed: {e}")
        
        # Run training in background thread
        thread = threading.Thread(target=train_async)
        thread.daemon = True
        thread.start()
    
    def save_models(self):
        """Save all trained models to disk"""
        try:
            # Save anomaly detector
            self.anomaly_detector.save_model(
                self.model_dir / 'anomaly_detector.joblib'
            )
            
            # Save attack classifier
            self.attack_classifier.save_model(
                self.model_dir / 'attack_classifier.joblib'
            )
            
            # Save metadata
            metadata = {
                'versions': self.model_versions,
                'last_training': self.last_training_time.isoformat() if self.last_training_time else None,
                'metrics': dict(self.metrics)
            }
            
            with open(self.model_dir / 'metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Models saved to {self.model_dir}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            # Load anomaly detector
            anomaly_path = self.model_dir / 'anomaly_detector.joblib'
            if anomaly_path.exists():
                self.anomaly_detector.load_model(str(anomaly_path))
            
            # Load attack classifier
            classifier_path = self.model_dir / 'attack_classifier.joblib'
            if classifier_path.exists():
                self.attack_classifier.load_model(str(classifier_path))
            
            # Load metadata
            metadata_path = self.model_dir / 'metadata.json'
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    self.model_versions = metadata.get('versions', self.model_versions)
                    if metadata.get('last_training'):
                        self.last_training_time = datetime.fromisoformat(metadata['last_training'])
            
            self.models_loaded = True
            logger.info("Models loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load models: {e}")
    
    def get_model_status(self) -> Dict[str, Any]:
        """
        Get current status of all models
        
        Returns:
            Status information for all models
        """
        return {
            'models_loaded': self.models_loaded,
            'versions': self.model_versions,
            'last_training': self.last_training_time.isoformat() if self.last_training_time else None,
            'anomaly_detector': {
                'trained': self.anomaly_detector.is_trained,
                'contamination': self.anomaly_detector.contamination,
                'metrics': self.anomaly_detector.get_metrics()
            },
            'attack_classifier': {
                'trained': self.attack_classifier.is_trained,
                'model_type': self.attack_classifier.model_type,
                'metrics': self.attack_classifier.get_metrics()
            },
            'performance': {
                'total_requests': self.metrics['total_requests'],
                'threats_detected': self.metrics['threats_detected'],
                'avg_processing_time_ms': np.mean(self.metrics['processing_times']) if self.metrics['processing_times'] else 0,
                'cache_size': len(self.prediction_cache),
                'training_buffer_size': len(self.training_buffer)
            }
        }
    
    def update_threat_intelligence(self, threat_data: Dict[str, Any]):
        """
        Update threat intelligence data
        
        Args:
            threat_data: New threat intelligence information
        """
        if 'patterns' in threat_data:
            self.threat_patterns.update(threat_data['patterns'])
        
        if 'attackers' in threat_data:
            self.known_attackers.update(threat_data['attackers'])
        
        if 'whitelist' in threat_data:
            self.whitelist.update(threat_data['whitelist'])
        
        logger.info(f"Threat intelligence updated: {len(self.threat_patterns)} patterns, "
                   f"{len(self.known_attackers)} known attackers")
    
    def provide_feedback(self, request_id: str, correct_label: str, 
                        was_correct: bool):
        """
        Provide feedback for continuous learning
        
        Args:
            request_id: Identifier for the request
            correct_label: The correct classification
            was_correct: Whether the prediction was correct
        """
        if was_correct:
            self.metrics['true_positives'] += 1
        else:
            self.metrics['false_positives'] += 1
        
        # Calculate rolling accuracy
        total = self.metrics['true_positives'] + self.metrics['false_positives']
        if total > 0:
            accuracy = self.metrics['true_positives'] / total
            self.metrics['accuracy_history'].append(accuracy)
        
        logger.info(f"Feedback recorded. Current accuracy: "
                   f"{np.mean(self.metrics['accuracy_history']):.2%}")