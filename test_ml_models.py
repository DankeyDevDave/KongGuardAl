#!/usr/bin/env python3
"""
Test script for ML models in Kong Guard AI
"""

import sys
import json
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from ml_models.feature_extractor import FeatureExtractor
from ml_models.anomaly_detector import AnomalyDetector
from ml_models.attack_classifier import AttackClassifier
from ml_models.model_manager import ModelManager

def test_feature_extraction():
    """Test feature extraction"""
    print("\n=== Testing Feature Extraction ===")
    
    extractor = FeatureExtractor()
    
    # Test normal request
    normal_request = {
        'method': 'GET',
        'path': '/api/users/123',
        'client_ip': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0',
        'requests_per_minute': 5,
        'content_length': 0,
        'query_params': {},
        'headers': {'Authorization': 'Bearer token123'},
        'query': '',
        'body': ''
    }
    
    features = extractor.extract_all_features(normal_request)
    print(f"✅ Extracted {len(features)} features from normal request")
    print(f"   Sample features: sql_risk_score={features.get('sql_risk_score', 0):.2f}, "
          f"xss_risk_score={features.get('xss_risk_score', 0):.2f}")
    
    # Test malicious request
    malicious_request = {
        'method': 'POST',
        'path': '/api/login',
        'client_ip': '10.0.0.1',
        'user_agent': 'curl/7.64.1',
        'requests_per_minute': 150,
        'content_length': 500,
        'query_params': {},
        'headers': {},
        'query': "'; DROP TABLE users; --",
        'body': '{"username": "admin\' OR \'1\'=\'1", "password": "password"}'
    }
    
    mal_features = extractor.extract_all_features(malicious_request)
    print(f"✅ Extracted {len(mal_features)} features from malicious request")
    print(f"   Risk scores: sql={mal_features.get('sql_risk_score', 0):.2f}, "
          f"overall={mal_features.get('overall_risk_score', 0):.2f}")

def test_anomaly_detection():
    """Test anomaly detection"""
    print("\n=== Testing Anomaly Detection ===")
    
    detector = AnomalyDetector(contamination=0.1)
    
    # Generate training data
    training_data = []
    for i in range(100):
        training_data.append({
            'method': 'GET',
            'path': f'/api/resource/{i}',
            'client_ip': f'192.168.1.{i % 255}',
            'user_agent': 'Normal Browser',
            'requests_per_minute': 10,
            'content_length': 100,
            'query': '',
            'body': ''
        })
    
    # Train detector
    detector.train(training_data)
    print(f"✅ Trained anomaly detector with {len(training_data)} samples")
    
    # Test normal request
    normal_result = detector.predict(training_data[0])
    print(f"   Normal request: anomaly={normal_result['is_anomaly']}, "
          f"score={normal_result['anomaly_score']:.2f}")
    
    # Test anomalous request
    anomalous = {
        'method': 'DELETE',
        'path': '../../etc/passwd',
        'client_ip': '1.2.3.4',
        'user_agent': 'HackBot/1.0',
        'requests_per_minute': 500,
        'content_length': 10000,
        'query': 'cmd=ls&exec=true',
        'body': '<script>alert("XSS")</script>'
    }
    
    anomaly_result = detector.predict(anomalous)
    print(f"   Anomalous request: anomaly={anomaly_result['is_anomaly']}, "
          f"score={anomaly_result['anomaly_score']:.2f}")
    print(f"   Reason: {anomaly_result['reason']}")

def test_attack_classification():
    """Test attack classification"""
    print("\n=== Testing Attack Classification ===")
    
    classifier = AttackClassifier(model_type='random_forest')
    
    # Generate training data with labels
    training_data = []
    labels = []
    
    # Add normal requests
    for i in range(20):
        training_data.append({
            'method': 'GET',
            'path': f'/api/resource/{i}',
            'query': '',
            'body': ''
        })
        labels.append('normal')
    
    # Add SQL injection attempts
    for i in range(20):
        training_data.append({
            'method': 'POST',
            'path': '/api/login',
            'query': f"id={i} OR 1=1",
            'body': "username=admin' OR '1'='1"
        })
        labels.append('sql_injection')
    
    # Add XSS attempts
    for i in range(20):
        training_data.append({
            'method': 'POST',
            'path': '/api/comment',
            'query': '',
            'body': f'<script>alert("XSS{i}")</script>'
        })
        labels.append('xss')
    
    # Train classifier
    classifier.train(training_data, labels)
    print(f"✅ Trained attack classifier with {len(training_data)} samples")
    
    # Test classification
    test_cases = [
        {
            'request': {
                'method': 'GET',
                'path': '/api/users',
                'query': '',
                'body': ''
            },
            'expected': 'normal'
        },
        {
            'request': {
                'method': 'POST',
                'path': '/api/query',
                'query': "search='; DROP TABLE users; --",
                'body': ''
            },
            'expected': 'sql_injection'
        },
        {
            'request': {
                'method': 'POST',
                'path': '/api/feedback',
                'query': '',
                'body': '<iframe src="javascript:alert(1)"></iframe>'
            },
            'expected': 'xss'
        }
    ]
    
    for test in test_cases:
        result = classifier.predict(test['request'])
        print(f"   Test {test['expected']}: detected={result['attack_type']}, "
              f"confidence={result['confidence']:.2f}")
        if result['attack_type'] == test['expected']:
            print(f"      ✅ Correct classification")
        else:
            print(f"      ❌ Misclassified")

def test_model_manager():
    """Test model manager orchestration"""
    print("\n=== Testing Model Manager ===")
    
    manager = ModelManager(model_dir="test_models")
    
    # Test comprehensive analysis
    requests = [
        {
            'method': 'GET',
            'path': '/api/health',
            'client_ip': '192.168.1.1',
            'user_agent': 'Mozilla/5.0',
            'requests_per_minute': 5,
            'content_length': 0,
            'query': '',
            'body': ''
        },
        {
            'method': 'POST',
            'path': '/api/admin',
            'client_ip': '10.0.0.1',
            'user_agent': 'curl',
            'requests_per_minute': 200,
            'content_length': 1000,
            'query': "cmd=exec&payload=' OR 1=1 --",
            'body': '<script>document.cookie</script>'
        }
    ]
    
    for i, request in enumerate(requests):
        print(f"\n   Request {i+1}:")
        result = manager.analyze_request(request)
        print(f"      Threat Score: {result['threat_score']:.2f}")
        print(f"      Risk Level: {result['risk_level']}")
        print(f"      Attack Type: {result['classification']['attack_type']}")
        print(f"      Action: {result['action']['action']}")
        print(f"      Processing Time: {result['processing_time_ms']:.1f}ms")
    
    # Get model status
    status = manager.get_model_status()
    print(f"\n✅ Model Manager Status:")
    print(f"   Models Loaded: {status['models_loaded']}")
    print(f"   Total Requests: {status['performance']['total_requests']}")
    print(f"   Threats Detected: {status['performance']['threats_detected']}")

def main():
    """Run all tests"""
    print("🧪 Testing Kong Guard AI ML Models")
    print("=" * 50)
    
    try:
        test_feature_extraction()
        test_anomaly_detection()
        test_attack_classification()
        test_model_manager()
        
        print("\n" + "=" * 50)
        print("✅ All ML model tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())