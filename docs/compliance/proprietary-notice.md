# PROPRIETARY SOFTWARE NOTICE

## Kong Guard AI - Intellectual Property Protection

This repository contains **PROPRIETARY AND CONFIDENTIAL** software developed for the Kong Agentic AI Hackathon 2024/2025.

### Protected Components

The following components are proprietary and protected by copyright:

#### Machine Learning Models (CONFIDENTIAL)
- `ml_models/anomaly_detector.py` - IsolationForest-based anomaly detection
- `ml_models/attack_classifier.py` - Multi-class attack classification system
- `ml_models/feature_extractor.py` - 70+ feature engineering pipeline
- `ml_models/model_manager.py` - ML orchestration and threat scoring

**Protection Level**: HIGHEST - Contains novel algorithms and trade secrets

#### AI Service Integration (PROPRIETARY)
- `ai-service/app.py` - Multi-provider AI orchestration
- WebSocket real-time streaming architecture
- Hybrid AI/ML threat analysis system

**Protection Level**: HIGH - Unique integration architecture

#### Training & Algorithms (TRADE SECRET)
- Model training pipelines
- Feature selection methodology
- Threat scoring algorithms
- Behavioral fingerprinting logic

**Protection Level**: HIGHEST - Core competitive advantage

### Open Source Components

The following may be used under MIT License:
- Basic Kong plugin structure
- HTML visualization templates
- Docker configuration files
- Basic test scripts

### Strictly Prohibited

Without explicit written permission, the following is PROHIBITED:

1. **Commercial Use** - Using any part of this code in commercial products
2. **Reproduction** - Copying or redistributing the codebase
3. **Derivative Works** - Creating modified versions
4. **Algorithm Extraction** - Reverse engineering the ML models
5. **Production Deployment** - Using in live environments
6. **Sublicensing** - Granting rights to third parties

### Hackathon Judge Access

Hackathon judges and organizers are granted LIMITED access to:
- Review code for evaluation purposes
- Test the demonstration system
- Verify technical implementation
- Score based on competition criteria

This access does NOT grant any ownership rights or commercial licenses.

### Security Measures Implemented

1. **Credential Protection**
   - All API keys removed from repository
   - Sensitive configs in .env (gitignored)
   - Supabase credentials excluded

2. **Code Obfuscation Available**
   - ML models can be compiled to .pyc
   - Critical algorithms can be encrypted
   - Binary distribution possible

3. **Legal Protection**
   - Copyright notices in all files
   - Proprietary license clearly stated
   - Audit trail via git history

### Attribution Requirements

If permission is granted to use any component:
- Include original copyright notice
- Provide clear attribution
- Link back to original repository
- State modifications made

### Licensing Inquiries

For commercial licensing, collaboration, or permission requests:

**Contact**: Jacques Francois Coetzee  
**Project**: Kong Guard AI  
**Year**: 2024  

Available licensing models:
- **Community Edition** - Basic features under MIT
- **Enterprise Edition** - Full features with support
- **OEM Licensing** - Integration into your products
- **Custom Terms** - Tailored to your needs

### Legal Notice

This software is protected by copyright law and international treaties. Unauthorized reproduction or distribution of this program, or any portion of it, may result in severe civil and criminal penalties, and will be prosecuted to the maximum extent possible under law.

**Copyright © 2024 Jacques Francois Coetzee. All Rights Reserved.**

---

*By accessing this repository, you acknowledge that you have read, understood, and agree to be bound by these terms.*