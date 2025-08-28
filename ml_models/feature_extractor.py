"""
Kong Guard AI - Feature Extraction Module
Copyright (c) 2024 Jacques Francois Coetzee. All Rights Reserved.

PROPRIETARY AND CONFIDENTIAL
This module contains proprietary feature engineering algorithms.
Unauthorized use, reproduction, or distribution is prohibited.

Advanced feature engineering for ML models
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import hashlib
import re
from urllib.parse import urlparse, parse_qs
import json
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """
    Comprehensive feature extraction for API requests
    """
    
    def __init__(self):
        """Initialize the feature extractor"""
        self.feature_cache = {}
        self.ip_history = {}
        self.user_history = {}
        
        # Pattern compilations for efficiency
        self.sql_pattern = re.compile(
            r'(select|union|drop|insert|update|delete|exec|declare|cast|convert|waitfor|delay|benchmark)',
            re.IGNORECASE
        )
        self.xss_pattern = re.compile(
            r'(<script|javascript:|onerror=|onclick=|onload=|<iframe|alert\(|prompt\(|confirm\()',
            re.IGNORECASE
        )
        self.path_traversal_pattern = re.compile(r'(\.\./|\.\./|%2e%2e|%252e%252e)')
        self.cmd_injection_pattern = re.compile(r'([|;&$`\n\r]|\bexec\b|\bsystem\b|\beval\b)')
        
    def extract_all_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract comprehensive features from request
        
        Args:
            request_data: Complete request information
            
        Returns:
            Dictionary containing all extracted features
        """
        features = {}
        
        # Extract different feature categories
        features.update(self.extract_basic_features(request_data))
        features.update(self.extract_content_features(request_data))
        features.update(self.extract_security_features(request_data))
        features.update(self.extract_behavioral_features(request_data))
        features.update(self.extract_temporal_features(request_data))
        features.update(self.extract_statistical_features(request_data))
        
        return features
    
    def extract_basic_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract basic request features"""
        features = {}
        
        # Method features
        method = request_data.get('method', 'GET')
        for m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
            features[f'method_{m}'] = 1.0 if method == m else 0.0
        
        # Path features
        path = request_data.get('path', '')
        features['path_length'] = float(len(path))
        features['path_depth'] = float(path.count('/'))
        features['has_file_extension'] = 1.0 if '.' in path.split('/')[-1] else 0.0
        
        # Parse URL components
        parsed = urlparse(path)
        features['has_query'] = 1.0 if parsed.query else 0.0
        features['has_fragment'] = 1.0 if parsed.fragment else 0.0
        
        # Headers features
        headers = request_data.get('headers', {})
        features['header_count'] = float(len(headers))
        features['has_auth'] = 1.0 if 'Authorization' in headers else 0.0
        features['has_cookie'] = 1.0 if 'Cookie' in headers else 0.0
        features['has_referer'] = 1.0 if 'Referer' in headers else 0.0
        features['has_user_agent'] = 1.0 if 'User-Agent' in headers else 0.0
        
        # Content features
        features['content_length'] = float(request_data.get('content_length', 0))
        features['body_size'] = float(len(str(request_data.get('body', ''))))
        
        # Query parameters
        query_params = request_data.get('query_params', {})
        features['query_param_count'] = float(len(query_params))
        features['unique_param_count'] = float(len(set(query_params.keys())))
        
        return features
    
    def extract_content_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract content-based features"""
        features = {}
        
        body = str(request_data.get('body', ''))
        query = str(request_data.get('query', ''))
        content = body + query
        
        # Character statistics
        features['total_chars'] = float(len(content))
        features['unique_chars'] = float(len(set(content))) if content else 0.0
        features['char_diversity'] = features['unique_chars'] / max(features['total_chars'], 1)
        
        # Special character counts
        features['special_char_count'] = float(sum(1 for c in content if not c.isalnum()))
        features['numeric_char_count'] = float(sum(1 for c in content if c.isdigit()))
        features['alpha_char_count'] = float(sum(1 for c in content if c.isalpha()))
        
        # Encoding detection
        features['has_base64'] = 1.0 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', content) else 0.0
        features['has_hex_encoding'] = 1.0 if re.search(r'(%[0-9a-fA-F]{2}){3,}', content) else 0.0
        features['has_unicode'] = 1.0 if re.search(r'\\u[0-9a-fA-F]{4}', content) else 0.0
        
        # Entropy calculation
        features['content_entropy'] = self._calculate_entropy(content)
        
        # Token analysis
        tokens = re.findall(r'\b\w+\b', content.lower())
        features['token_count'] = float(len(tokens))
        features['unique_token_count'] = float(len(set(tokens)))
        features['avg_token_length'] = float(np.mean([len(t) for t in tokens])) if tokens else 0.0
        
        return features
    
    def extract_security_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract security-related features"""
        features = {}
        
        body = str(request_data.get('body', ''))
        query = str(request_data.get('query', ''))
        path = request_data.get('path', '')
        headers = request_data.get('headers', {})
        content = body + query + path
        
        # SQL Injection indicators
        sql_matches = self.sql_pattern.findall(content)
        features['sql_keyword_count'] = float(len(sql_matches))
        features['has_sql_comment'] = 1.0 if ('--' in content or '/*' in content) else 0.0
        features['has_sql_quotes'] = 1.0 if ("'" in content or '"' in content) else 0.0
        features['sql_risk_score'] = min(features['sql_keyword_count'] / 10, 1.0)
        
        # XSS indicators
        xss_matches = self.xss_pattern.findall(content)
        features['xss_pattern_count'] = float(len(xss_matches))
        features['has_javascript'] = 1.0 if 'javascript:' in content.lower() else 0.0
        features['tag_count'] = float(content.count('<') + content.count('>'))
        features['xss_risk_score'] = min(features['xss_pattern_count'] / 5, 1.0)
        
        # Path Traversal indicators
        features['has_path_traversal'] = 1.0 if self.path_traversal_pattern.search(content) else 0.0
        features['dot_dot_count'] = float(content.count('../') + content.count('..\\'))
        features['path_risk_score'] = min(features['dot_dot_count'] / 3, 1.0)
        
        # Command Injection indicators
        cmd_matches = self.cmd_injection_pattern.findall(content)
        features['cmd_pattern_count'] = float(len(cmd_matches))
        features['has_pipe_char'] = 1.0 if '|' in content else 0.0
        features['cmd_risk_score'] = min(features['cmd_pattern_count'] / 5, 1.0)
        
        # CSRF protection
        features['has_csrf_token'] = 1.0 if 'csrf' in content.lower() or 'X-CSRF-Token' in headers else 0.0
        features['is_state_changing'] = 1.0 if request_data.get('method') in ['POST', 'PUT', 'DELETE'] else 0.0
        
        # General security
        features['has_null_byte'] = 1.0 if '\x00' in content or '%00' in content else 0.0
        features['non_printable_chars'] = float(sum(1 for c in content if ord(c) < 32 or ord(c) > 126))
        
        # Combined risk score
        features['overall_risk_score'] = min(
            features['sql_risk_score'] + 
            features['xss_risk_score'] + 
            features['path_risk_score'] + 
            features['cmd_risk_score'],
            1.0
        )
        
        return features
    
    def extract_behavioral_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract behavioral pattern features"""
        features = {}
        
        client_ip = request_data.get('client_ip', '')
        user_agent = request_data.get('user_agent', '')
        
        # IP-based features
        if client_ip:
            if client_ip not in self.ip_history:
                self.ip_history[client_ip] = {
                    'first_seen': datetime.now(),
                    'request_count': 0,
                    'unique_paths': set(),
                    'methods': set()
                }
            
            ip_data = self.ip_history[client_ip]
            ip_data['request_count'] += 1
            ip_data['unique_paths'].add(request_data.get('path', ''))
            ip_data['methods'].add(request_data.get('method', ''))
            
            # Calculate features
            time_since_first = (datetime.now() - ip_data['first_seen']).total_seconds()
            features['ip_request_count'] = float(ip_data['request_count'])
            features['ip_unique_paths'] = float(len(ip_data['unique_paths']))
            features['ip_method_diversity'] = float(len(ip_data['methods']))
            features['ip_requests_per_minute'] = features['ip_request_count'] / max(time_since_first / 60, 1)
        
        # User agent features
        features['ua_length'] = float(len(user_agent))
        features['is_bot'] = 1.0 if any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']) else 0.0
        features['is_browser'] = 1.0 if any(browser in user_agent.lower() for browser in ['chrome', 'firefox', 'safari', 'edge']) else 0.0
        features['is_mobile'] = 1.0 if any(mobile in user_agent.lower() for mobile in ['mobile', 'android', 'iphone']) else 0.0
        
        # Request rate features
        features['requests_per_minute'] = float(request_data.get('requests_per_minute', 0))
        features['is_high_rate'] = 1.0 if features['requests_per_minute'] > 60 else 0.0
        features['is_burst'] = 1.0 if features['requests_per_minute'] > 100 else 0.0
        
        return features
    
    def extract_temporal_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract time-based features"""
        features = {}
        
        now = datetime.now()
        
        # Time of day features
        features['hour_of_day'] = float(now.hour)
        features['minute_of_hour'] = float(now.minute)
        features['day_of_week'] = float(now.weekday())
        features['day_of_month'] = float(now.day)
        features['month'] = float(now.month)
        
        # Business hours (9 AM - 5 PM, Monday-Friday)
        features['is_business_hours'] = 1.0 if (
            9 <= now.hour < 17 and now.weekday() < 5
        ) else 0.0
        
        # Weekend
        features['is_weekend'] = 1.0 if now.weekday() >= 5 else 0.0
        
        # Night time (10 PM - 6 AM)
        features['is_night'] = 1.0 if now.hour >= 22 or now.hour < 6 else 0.0
        
        # Time-based risk (higher risk during off-hours)
        if features['is_night'] or features['is_weekend']:
            features['temporal_risk'] = 0.3
        elif not features['is_business_hours']:
            features['temporal_risk'] = 0.2
        else:
            features['temporal_risk'] = 0.0
        
        return features
    
    def extract_statistical_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract statistical and aggregate features"""
        features = {}
        
        # Calculate various ratios and statistics
        body_size = len(str(request_data.get('body', '')))
        path_length = len(request_data.get('path', ''))
        header_count = len(request_data.get('headers', {}))
        
        # Size ratios
        features['body_to_path_ratio'] = body_size / max(path_length, 1)
        features['header_to_body_ratio'] = header_count / max(body_size, 1)
        
        # Complexity scores
        features['request_complexity'] = (
            features['body_to_path_ratio'] * 0.3 +
            header_count * 0.1 +
            request_data.get('query_param_count', 0) * 0.2
        )
        
        # Anomaly indicators
        features['is_oversized'] = 1.0 if body_size > 10000 else 0.0
        features['is_minimal'] = 1.0 if body_size < 10 and header_count < 5 else 0.0
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text
        
        Args:
            text: Input text
            
        Returns:
            Entropy value
        """
        if not text:
            return 0.0
        
        # Character frequency
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return float(entropy)
    
    def create_feature_vector(self, features: Dict[str, float], 
                            feature_names: List[str]) -> np.ndarray:
        """
        Convert feature dictionary to numpy array with consistent ordering
        
        Args:
            features: Feature dictionary
            feature_names: Ordered list of feature names
            
        Returns:
            Feature vector as numpy array
        """
        return np.array([features.get(name, 0.0) for name in feature_names])
    
    def get_feature_names(self) -> List[str]:
        """
        Get list of all feature names in consistent order
        
        Returns:
            List of feature names
        """
        # This would be populated from a sample request
        return sorted([
            # Basic features
            'method_GET', 'method_POST', 'method_PUT', 'method_DELETE', 'method_PATCH',
            'path_length', 'path_depth', 'has_file_extension', 'has_query', 'has_fragment',
            'header_count', 'has_auth', 'has_cookie', 'has_referer', 'has_user_agent',
            'content_length', 'body_size', 'query_param_count', 'unique_param_count',
            # Content features
            'total_chars', 'unique_chars', 'char_diversity', 'special_char_count',
            'numeric_char_count', 'alpha_char_count', 'has_base64', 'has_hex_encoding',
            'has_unicode', 'content_entropy', 'token_count', 'unique_token_count',
            # Security features
            'sql_keyword_count', 'has_sql_comment', 'has_sql_quotes', 'sql_risk_score',
            'xss_pattern_count', 'has_javascript', 'tag_count', 'xss_risk_score',
            'has_path_traversal', 'dot_dot_count', 'path_risk_score',
            'cmd_pattern_count', 'has_pipe_char', 'cmd_risk_score',
            'has_csrf_token', 'is_state_changing', 'has_null_byte', 'non_printable_chars',
            'overall_risk_score',
            # Behavioral features
            'ip_request_count', 'ip_unique_paths', 'ip_method_diversity',
            'ip_requests_per_minute', 'ua_length', 'is_bot', 'is_browser', 'is_mobile',
            'requests_per_minute', 'is_high_rate', 'is_burst',
            # Temporal features
            'hour_of_day', 'minute_of_hour', 'day_of_week', 'day_of_month', 'month',
            'is_business_hours', 'is_weekend', 'is_night', 'temporal_risk',
            # Statistical features
            'body_to_path_ratio', 'header_to_body_ratio', 'request_complexity',
            'is_oversized', 'is_minimal'
        ])