"""
Kong Guard AI - Attack Classification Module
Multi-class classification for attack type detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from typing import Dict, List, Optional, Tuple, Any
import joblib
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class AttackClassifier:
    """
    Multi-class classifier for identifying specific attack types
    """
    
    # Known attack types
    ATTACK_TYPES = [
        'normal',
        'sql_injection',
        'xss',
        'ddos',
        'brute_force',
        'path_traversal',
        'api_abuse',
        'command_injection',
        'xxe',
        'csrf',
        'unauthorized_access'
    ]
    
    def __init__(self, model_type: str = 'random_forest'):
        """
        Initialize the attack classifier
        
        Args:
            model_type: Type of classifier ('random_forest' or 'gradient_boosting')
        """
        self.model_type = model_type
        self.model = None
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.feature_importance = {}
        
        # Initialize model
        if model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1
            )
        else:  # gradient_boosting
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
        
        # Performance metrics
        self.metrics = {
            'accuracy': 0.0,
            'precision': {},
            'recall': {},
            'f1_score': {},
            'confusion_matrix': None,
            'last_training': None
        }
        
    def extract_attack_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract features specific to attack classification
        
        Args:
            request_data: Request dictionary
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # Get basic request info
        body = str(request_data.get('body', '')).lower()
        path = request_data.get('path', '').lower()
        headers = request_data.get('headers', {})
        query = request_data.get('query', '').lower()
        method = request_data.get('method', 'GET')
        
        # SQL Injection indicators
        sql_keywords = ['select', 'union', 'drop', 'insert', 'update', 'delete', 'exec', 'declare']
        features.append(sum(1 for kw in sql_keywords if kw in body + query))
        features.append(1 if "'" in body + query or '"' in body + query else 0)
        features.append(1 if '--' in body + query or '/*' in body + query else 0)
        features.append(1 if ' or ' in body + query or ' and ' in body + query else 0)
        
        # XSS indicators
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onclick=', 'onload=', '<iframe']
        features.append(sum(1 for pattern in xss_patterns if pattern in body + query))
        features.append(body.count('<') + body.count('>'))
        features.append(1 if 'alert(' in body or 'prompt(' in body else 0)
        
        # Path Traversal indicators
        features.append(1 if '../' in path + query or '..\\' in path + query else 0)
        features.append(path.count('/'))
        features.append(1 if '/etc/' in path or '/windows/' in path.lower() else 0)
        
        # Command Injection indicators
        cmd_chars = ['|', '&', ';', '$', '`', '\n', '\r']
        features.append(sum(1 for char in cmd_chars if char in body + query))
        cmd_keywords = ['exec', 'system', 'eval', 'cmd', 'powershell']
        features.append(sum(1 for kw in cmd_keywords if kw in body + query))
        
        # API Abuse indicators
        features.append(request_data.get('requests_per_minute', 0))
        features.append(len(body))
        features.append(len(headers))
        features.append(1 if method in ['PUT', 'DELETE', 'PATCH'] else 0)
        
        # DDoS indicators
        features.append(1 if request_data.get('requests_per_minute', 0) > 100 else 0)
        features.append(1 if len(body) > 10000 else 0)
        
        # Brute Force indicators
        auth_header = headers.get('Authorization', '')
        features.append(1 if auth_header else 0)
        features.append(1 if '/login' in path or '/auth' in path else 0)
        features.append(1 if method == 'POST' and ('/login' in path or '/auth' in path) else 0)
        
        # XXE indicators
        features.append(1 if '<!DOCTYPE' in body else 0)
        features.append(1 if 'ENTITY' in body else 0)
        features.append(1 if 'SYSTEM' in body else 0)
        
        # CSRF indicators
        features.append(1 if 'csrf' not in headers and method == 'POST' else 0)
        features.append(1 if 'Referer' not in headers and method == 'POST' else 0)
        
        # General suspicious patterns
        features.append(sum(1 for c in body if ord(c) < 32 or ord(c) > 126))  # Non-printable chars
        features.append(1 if 'base64' in body else 0)
        features.append(1 if '%00' in query or '\x00' in body else 0)  # Null byte
        
        return np.array(features)
    
    def train(self, training_data: List[Dict[str, Any]], labels: List[str]):
        """
        Train the attack classifier
        
        Args:
            training_data: List of request dictionaries
            labels: List of attack type labels
        """
        logger.info(f"Training attack classifier with {len(training_data)} samples")
        
        # Extract features
        X = np.array([self.extract_attack_features(req) for req in training_data])
        
        # Encode labels
        y = self.label_encoder.fit_transform(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        # Calculate metrics
        self.metrics['accuracy'] = self.model.score(X_test, y_test)
        
        # Get classification report
        report = classification_report(
            y_test, y_pred,
            target_names=self.label_encoder.classes_,
            output_dict=True
        )
        
        for attack_type in self.label_encoder.classes_:
            if attack_type in report:
                self.metrics['precision'][attack_type] = report[attack_type]['precision']
                self.metrics['recall'][attack_type] = report[attack_type]['recall']
                self.metrics['f1_score'][attack_type] = report[attack_type]['f1-score']
        
        # Confusion matrix
        self.metrics['confusion_matrix'] = confusion_matrix(y_test, y_pred).tolist()
        
        # Feature importance (for tree-based models)
        if hasattr(self.model, 'feature_importances_'):
            self.feature_importance = {
                f'feature_{i}': importance 
                for i, importance in enumerate(self.model.feature_importances_)
            }
        
        self.is_trained = True
        self.metrics['last_training'] = datetime.now().isoformat()
        
        logger.info(f"Attack classifier training complete. Accuracy: {self.metrics['accuracy']:.2f}")
    
    def predict(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify the attack type of a request
        
        Args:
            request_data: Request dictionary
            
        Returns:
            Classification results
        """
        if not self.is_trained:
            return {
                'attack_type': 'unknown',
                'confidence': 0.0,
                'probabilities': {},
                'reason': 'Model not trained'
            }
        
        # Extract features
        features = self.extract_attack_features(request_data).reshape(1, -1)
        
        # Predict
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        
        # Decode prediction
        attack_type = self.label_encoder.inverse_transform([prediction])[0]
        
        # Get confidence
        confidence = max(probabilities)
        
        # Get probability distribution
        prob_dist = {
            self.label_encoder.inverse_transform([i])[0]: float(prob)
            for i, prob in enumerate(probabilities)
        }
        
        # Sort by probability
        prob_dist = dict(sorted(prob_dist.items(), key=lambda x: x[1], reverse=True))
        
        # Generate explanation
        reason = self._explain_classification(attack_type, prob_dist, request_data)
        
        return {
            'attack_type': attack_type,
            'confidence': float(confidence),
            'probabilities': prob_dist,
            'reason': reason,
            'top_3': list(prob_dist.keys())[:3]
        }
    
    def _explain_classification(self, attack_type: str, probabilities: Dict[str, float], 
                                request_data: Dict[str, Any]) -> str:
        """
        Generate explanation for the classification
        
        Args:
            attack_type: Predicted attack type
            probabilities: Probability distribution
            request_data: Original request data
            
        Returns:
            Human-readable explanation
        """
        confidence = probabilities[attack_type]
        
        explanations = {
            'sql_injection': "SQL injection patterns detected in request",
            'xss': "Cross-site scripting (XSS) patterns found",
            'ddos': "Distributed denial of service indicators",
            'brute_force': "Brute force authentication attempt detected",
            'path_traversal': "Path traversal attempt detected",
            'api_abuse': "API abuse patterns identified",
            'command_injection': "Command injection attempt detected",
            'xxe': "XML External Entity (XXE) patterns found",
            'csrf': "Cross-site request forgery indicators",
            'unauthorized_access': "Unauthorized access attempt detected",
            'normal': "Request appears to be legitimate"
        }
        
        base_explanation = explanations.get(attack_type, f"Classified as {attack_type}")
        
        # Add confidence level
        if confidence > 0.9:
            confidence_text = "very high confidence"
        elif confidence > 0.7:
            confidence_text = "high confidence"
        elif confidence > 0.5:
            confidence_text = "moderate confidence"
        else:
            confidence_text = "low confidence"
        
        return f"{base_explanation} ({confidence_text}: {confidence:.1%})"
    
    def batch_predict(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Classify multiple requests at once
        
        Args:
            requests: List of request dictionaries
            
        Returns:
            List of classification results
        """
        return [self.predict(req) for req in requests]
    
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
            'label_encoder': self.label_encoder,
            'metrics': self.metrics,
            'feature_importance': self.feature_importance,
            'model_type': self.model_type
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Attack classifier saved to {filepath}")
    
    def load_model(self, filepath: str):
        """
        Load trained model from disk
        
        Args:
            filepath: Path to load model from
        """
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.label_encoder = model_data['label_encoder']
        self.metrics = model_data['metrics']
        self.feature_importance = model_data['feature_importance']
        self.model_type = model_data['model_type']
        self.is_trained = True
        
        logger.info(f"Attack classifier loaded from {filepath}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current model metrics
        
        Returns:
            Dictionary of performance metrics
        """
        return {
            **self.metrics,
            'is_trained': self.is_trained,
            'model_type': self.model_type,
            'feature_importance': self.feature_importance
        }