"""
Kong Guard AI - Anomaly Detection Module
Real-time anomaly detection using Isolation Forest
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import joblib
import logging
from collections import deque
import json

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Advanced anomaly detection for API requests using Isolation Forest
    """
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        """
        Initialize the anomaly detector
        
        Args:
            contamination: Expected proportion of outliers (0.1 = 10%)
            n_estimators: Number of trees in the forest
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        self.training_data = deque(maxlen=10000)  # Keep last 10k samples
        self.anomaly_threshold = -0.5
        self.request_cache = {}
        
        # Performance metrics
        self.metrics = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'last_training': None,
            'model_version': '1.0.0'
        }
        
    def extract_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract numerical features from API request
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            Dictionary of feature names and values
        """
        features = {}
        
        # Request size features
        features['request_size'] = len(str(request_data.get('body', '')))
        features['header_count'] = len(request_data.get('headers', {}))
        features['query_param_count'] = len(request_data.get('query_params', {}))
        
        # Path features
        path = request_data.get('path', '')
        features['path_depth'] = path.count('/')
        features['path_length'] = len(path)
        features['has_extension'] = 1 if '.' in path.split('/')[-1] else 0
        
        # Timing features
        features['hour_of_day'] = datetime.now().hour
        features['day_of_week'] = datetime.now().weekday()
        features['is_weekend'] = 1 if datetime.now().weekday() >= 5 else 0
        
        # Content features
        features['content_length'] = request_data.get('content_length', 0)
        features['unique_params'] = len(set(request_data.get('query_params', {}).keys()))
        
        # Method features (one-hot encoding)
        method = request_data.get('method', 'GET')
        for m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            features[f'method_{m}'] = 1 if method == m else 0
        
        # Rate features
        features['requests_per_minute'] = request_data.get('requests_per_minute', 0)
        
        # Security indicators
        body_str = str(request_data.get('body', ''))
        features['has_sql_keywords'] = 1 if any(kw in body_str.lower() for kw in ['select', 'drop', 'union', 'insert']) else 0
        features['has_script_tags'] = 1 if '<script' in body_str.lower() else 0
        features['has_special_chars'] = sum(1 for c in body_str if c in "';\"<>")
        
        # User agent features
        user_agent = request_data.get('user_agent', '')
        features['ua_length'] = len(user_agent)
        features['is_bot'] = 1 if 'bot' in user_agent.lower() else 0
        
        return features
    
    def train(self, training_data: List[Dict[str, Any]], labels: Optional[List[int]] = None):
        """
        Train the anomaly detection model
        
        Args:
            training_data: List of request dictionaries
            labels: Optional labels (-1 for anomaly, 1 for normal)
        """
        logger.info(f"Training anomaly detector with {len(training_data)} samples")
        
        # Extract features
        feature_dicts = [self.extract_features(req) for req in training_data]
        df = pd.DataFrame(feature_dicts)
        
        # Store feature names
        self.feature_names = df.columns.tolist()
        
        # Scale features
        X_scaled = self.scaler.fit_transform(df)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1
        )
        
        if labels is not None:
            # Semi-supervised: use labels if available
            self.model.fit(X_scaled, labels)
        else:
            # Unsupervised training
            self.model.fit(X_scaled)
        
        self.is_trained = True
        self.metrics['last_training'] = datetime.now().isoformat()
        
        logger.info("Anomaly detector training complete")
        
    def predict(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if a request is anomalous
        
        Args:
            request_data: Request dictionary
            
        Returns:
            Dictionary with anomaly detection results
        """
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'reason': 'Model not trained',
                'features': {}
            }
        
        # Extract features
        features = self.extract_features(request_data)
        
        # Convert to DataFrame with correct column order
        df = pd.DataFrame([features])[self.feature_names]
        
        # Scale features
        X_scaled = self.scaler.transform(df)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]  # -1 for anomaly, 1 for normal
        anomaly_score = self.model.score_samples(X_scaled)[0]
        
        # Calculate confidence (normalize score to 0-1 range)
        confidence = abs(anomaly_score)
        
        # Update metrics
        self.metrics['total_predictions'] += 1
        if prediction == -1:
            self.metrics['anomalies_detected'] += 1
        
        # Store in training data for online learning
        self.training_data.append(request_data)
        
        # Determine reason for anomaly
        reason = self._explain_anomaly(features, anomaly_score) if prediction == -1 else 'Normal behavior'
        
        return {
            'is_anomaly': prediction == -1,
            'anomaly_score': float(abs(anomaly_score)),
            'confidence': float(min(confidence, 1.0)),
            'reason': reason,
            'features': features,
            'prediction': int(prediction)
        }
    
    def _explain_anomaly(self, features: Dict[str, float], score: float) -> str:
        """
        Generate explanation for detected anomaly
        
        Args:
            features: Extracted features
            score: Anomaly score
            
        Returns:
            Human-readable explanation
        """
        explanations = []
        
        # Check for obvious anomalies
        if features.get('has_sql_keywords'):
            explanations.append("SQL injection patterns detected")
        if features.get('has_script_tags'):
            explanations.append("XSS patterns detected")
        if features.get('requests_per_minute', 0) > 100:
            explanations.append(f"High request rate: {features['requests_per_minute']}/min")
        if features.get('request_size', 0) > 10000:
            explanations.append(f"Unusually large request: {features['request_size']} bytes")
        if features.get('path_depth', 0) > 10:
            explanations.append(f"Deep path traversal: {features['path_depth']} levels")
        
        if not explanations:
            explanations.append(f"Unusual pattern detected (score: {abs(score):.2f})")
        
        return "; ".join(explanations)
    
    def update_model(self, feedback: Dict[str, Any]):
        """
        Update model with feedback (online learning)
        
        Args:
            feedback: Dictionary with request and correct label
        """
        # Add to training data
        request_data = feedback['request']
        label = feedback['label']  # -1 for anomaly, 1 for normal
        
        # Store for next retraining
        self.training_data.append({
            'request': request_data,
            'label': label,
            'timestamp': datetime.now().isoformat()
        })
        
        # Retrain periodically (every 1000 new samples)
        if len(self.training_data) % 1000 == 0:
            self.retrain()
    
    def retrain(self):
        """
        Retrain model with accumulated data
        """
        if len(self.training_data) < 100:
            logger.warning("Not enough data for retraining")
            return
        
        # Extract requests and labels
        requests = [d.get('request', d) for d in self.training_data]
        labels = [d.get('label', 1) for d in self.training_data if 'label' in d]
        
        # Retrain
        self.train(requests, labels if labels else None)
        
    def save_model(self, filepath: str):
        """
        Save trained model to disk
        
        Args:
            filepath: Path to save model
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'contamination': self.contamination,
            'metrics': self.metrics
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """
        Load trained model from disk
        
        Args:
            filepath: Path to load model from
        """
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.contamination = model_data['contamination']
        self.metrics = model_data['metrics']
        self.is_trained = True
        
        logger.info(f"Model loaded from {filepath}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current model metrics
        
        Returns:
            Dictionary of performance metrics
        """
        return {
            **self.metrics,
            'detection_rate': self.metrics['anomalies_detected'] / max(self.metrics['total_predictions'], 1),
            'is_trained': self.is_trained,
            'training_samples': len(self.training_data)
        }