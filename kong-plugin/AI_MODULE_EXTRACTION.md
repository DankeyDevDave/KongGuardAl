# AI Module Extraction - Kong Guard AI

## Overview

This document describes the extraction of AI integration modules from the monolithic `handler.lua` file in the Kong Guard AI project. The extraction improves code maintainability, testability, and follows the modular architecture pattern established with the utility modules.

## Extracted Modules

### 1. AI Service Module (`modules/ai/ai_service.lua`)

**Purpose**: Handles external AI service communication and response parsing.

**Key Functions**:
- `detect_ai_optimized()` - Main AI threat detection with caching
- `build_optimized_request_data()` - Builds request payloads for AI service
- `parse_ai_response()` - Parses and validates AI service responses
- `extract_relevant_headers()` - Privacy-conscious header filtering
- `health_check()` - AI service health monitoring
- `get_statistics()` - AI usage metrics

**Features**:
- ✅ Response caching for performance (30-second TTL)
- ✅ Request body size limiting (configurable, default 10KB)
- ✅ Timeout management (configurable, default 500ms)
- ✅ Privacy-conscious header filtering
- ✅ Comprehensive error handling
- ✅ Metrics tracking (requests, response times, blocks)
- ✅ Anomaly score calculation
- ✅ Configuration management

### 2. Threat Detector Module (`modules/ai/threat_detector.lua`)

**Purpose**: AI-enhanced threat detection with learning capabilities and confidence scoring.

**Key Functions**:
- `detect_threat_optimized()` - Main threat detection orchestrator
- `detect_patterns_optimized()` - Fast pattern-based detection
- `apply_confidence_scoring()` - AI learning and confidence adjustments
- `learn_from_feedback()` - Continuous learning from feedback
- `track_pattern()` - Pattern tracking for analytics
- `cleanup_old_entries()` - Maintenance and cleanup

**Detection Methods**:
- ✅ Pattern-based detection (SQL injection, XSS, path traversal, etc.)
- ✅ AI-enhanced detection via AI service integration
- ✅ TAXII threat intelligence integration
- ✅ Mesh metadata analysis
- ✅ Confidence scoring and learning

**Learning Features**:
- ✅ False positive tracking and adjustment
- ✅ Confidence scoring based on historical data
- ✅ Pattern history analytics
- ✅ Learning data export/import for backup/restore
- ✅ Automatic cleanup of old data

## Handler.lua Changes

### Imports Added
```lua
-- Import AI modules
local ai_service = require "kong.plugins.kong-guard-ai.modules.ai.ai_service"
local threat_detector = require "kong.plugins.kong-guard-ai.modules.ai.threat_detector"
```

### Functions Replaced

1. **`detect_threat_optimized()`** - Now delegates to `threat_detector` module
2. **`detect_ai_optimized()`** - Moved to `ai_service` module
3. **`detect_patterns_optimized()`** - Moved to `threat_detector` module

### Backward Compatibility

✅ All existing function signatures maintained
✅ Configuration parameters preserved
✅ Performance characteristics maintained or improved
✅ Error handling behavior preserved

## Performance Improvements

### Caching
- **Threat Detection**: 5-minute TTL for threat analysis results
- **AI Responses**: 30-second TTL for AI service responses
- **Pattern History**: Efficient tracking without performance impact

### Memory Management
- Pooled tables for threat details (using existing `performance_utils`)
- Efficient cache key generation using MD5 hashing
- Automatic cleanup of old cache entries

### Request Optimization
- Request body size limiting prevents large payload processing
- Privacy-conscious header filtering reduces request size
- Configurable timeouts prevent blocking

## Testing

### Unit Tests Created

1. **`ai_service_spec.lua`** - 15 test cases covering:
   - Initialization and configuration
   - Request data building and optimization
   - Response parsing and validation
   - Caching behavior
   - Header filtering
   - Statistics and metrics
   - Error handling

2. **`threat_detector_spec.lua`** - 20 test cases covering:
   - Pattern detection (SQL, XSS, path traversal, command injection)
   - Threat detection orchestration
   - Learning and confidence scoring
   - False positive handling
   - Data export/import
   - Cache management
   - Statistics and cleanup

### Test Runner
- Updated `run_tests.lua` to include AI module tests
- Individual test runner for AI modules: `run_ai_tests.lua`

## Configuration

### AI Service Configuration
```lua
{
  ai_service_url = "http://ai-service:8000",
  ai_timeout = 500,  -- milliseconds
  ai_max_body_size = 10000,  -- bytes
  enable_ai_gateway = true
}
```

### Threat Detector Configuration
```lua
{
  enable_threat_caching = true,
  threat_cache_ttl = 300,  -- seconds
  ddos_rpm_threshold = 100
}
```

## Migration Guide

### For Developers

1. **Updating Handler Logic**: The main `handler.lua` now uses the extracted modules
2. **New Dependencies**: Import the AI modules in custom code
3. **Configuration**: No configuration changes required - all existing configs work
4. **Testing**: Use the new unit tests as examples for testing AI functionality

### For Operations

1. **Deployment**: Deploy the new module structure
2. **Monitoring**: Use the enhanced statistics from `get_statistics()` methods
3. **Tuning**: Configure cache TTLs and timeouts based on performance needs

## Code Quality Improvements

### Separation of Concerns
- ✅ AI service communication isolated
- ✅ Threat detection logic modularized
- ✅ Learning/confidence logic centralized

### Testability
- ✅ Individual modules can be unit tested
- ✅ Mock-friendly interfaces
- ✅ Isolated state management

### Maintainability
- ✅ Clear module boundaries
- ✅ Documented APIs
- ✅ Consistent error handling
- ✅ Configurable behavior

### Performance
- ✅ Efficient caching strategies
- ✅ Memory-conscious design
- ✅ Optimized request processing

## Future Enhancements

### Potential Improvements
1. **Advanced Caching**: Redis-based caching for multi-node deployments
2. **ML Pipeline**: Integration with more sophisticated ML models
3. **A/B Testing**: Framework for testing different AI models
4. **Real-time Learning**: Streaming learning from feedback
5. **Model Management**: Dynamic model loading and versioning

### Extension Points
- Custom threat detection algorithms
- Additional AI service providers
- Enhanced learning mechanisms
- Advanced analytics and reporting

## Conclusion

The AI module extraction successfully:
- ✅ Reduces handler.lua complexity from 2500+ lines
- ✅ Improves code maintainability and testability
- ✅ Maintains backward compatibility
- ✅ Enhances performance through better caching
- ✅ Provides comprehensive unit test coverage
- ✅ Follows established modular architecture patterns

This extraction makes the codebase more maintainable while preserving all existing functionality and improving performance through better caching and optimization strategies.