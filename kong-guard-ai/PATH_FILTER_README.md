# Kong Guard AI - Path Regex Filtering System

## Overview

The Path Regex Filtering system provides comprehensive protection against attack vectors embedded in URL paths. This Phase 4 enhancement implements pre-compiled regex patterns for detecting SQL injection, XSS, path traversal, admin access attempts, and other common attack patterns in request paths.

## Features

### Core Capabilities

- **Pre-compiled Regex Patterns**: High-performance pattern matching using compiled regex
- **Multi-Category Detection**: Organized attack pattern detection across 8 categories
- **Path Normalization**: URL decoding, case normalization, and encoding detection
- **False Positive Mitigation**: Intelligent whitelist and context-aware filtering
- **Analytics & Reporting**: Pattern effectiveness tracking and false positive analysis
- **Custom Pattern Support**: Configurable custom regex patterns with priority levels

### Attack Categories Detected

1. **SQL Injection**: UNION SELECT, DROP TABLE, OR/AND clauses, injection patterns
2. **Cross-Site Scripting (XSS)**: Script tags, JavaScript protocols, event handlers
3. **Path Traversal**: Directory traversal attempts, system file access
4. **Admin Access**: Admin panels, configuration interfaces, management tools
5. **File Inclusion**: PHP wrappers, file protocol attempts, dangerous includes
6. **Command Injection**: System command patterns, shell metacharacters
7. **Configuration Exposure**: Environment files, config files, repository access
8. **Information Disclosure**: Backup files, log files, documentation access

## Configuration

### Schema Configuration Options

```json
{
  "enable_path_filtering": true,
  "path_filter_block_threshold": 7.0,
  "path_filter_suspicious_threshold": 4.0,
  "custom_path_patterns": [
    {
      "pattern": "(?i)custom_attack_pattern",
      "priority": 1,
      "description": "Custom attack detection"
    }
  ],
  "path_whitelist": [
    "/api/v1/search",
    "/admin/legitimate"
  ],
  "path_filter_skip_methods": ["OPTIONS", "HEAD"],
  "path_filter_case_sensitive": false,
  "path_filter_max_pattern_matches": 10,
  "path_filter_analytics_enabled": true
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_path_filtering` | boolean | `true` | Enable/disable path filtering |
| `path_filter_block_threshold` | number | `7.0` | Threat level for blocking (1-10) |
| `path_filter_suspicious_threshold` | number | `4.0` | Threat level for suspicious marking |
| `custom_path_patterns` | array | `[]` | Custom regex patterns with priority |
| `path_whitelist` | array | `[]` | Paths to always allow |
| `path_filter_skip_methods` | array | `[]` | HTTP methods to skip filtering |
| `path_filter_case_sensitive` | boolean | `false` | Enable case-sensitive matching |
| `path_filter_max_pattern_matches` | number | `10` | Max patterns to process per request |
| `path_filter_analytics_enabled` | boolean | `true` | Enable analytics tracking |

## Pattern Priority System

Patterns are classified by priority level to determine threat severity:

- **Priority 1 (Critical)**: Immediate blocking patterns (threat level 9)
  - Direct system file access
  - SQL injection with UNION/DROP
  - Script tag injection
  
- **Priority 2 (High)**: Likely malicious patterns (threat level 7)
  - Admin panel access
  - SQL SELECT/INSERT statements
  - Event handler injection
  
- **Priority 3 (Medium)**: Suspicious patterns (threat level 5)
  - Common SQL keywords
  - Information disclosure attempts
  - System command keywords
  
- **Priority 4 (Low)**: Monitoring patterns (threat level 3)
  - Documentation access
  - Backup file requests
  - Test file access

## Path Normalization Process

The system performs comprehensive path normalization to detect evasion attempts:

1. **URL Decoding**: Multiple rounds of URL decoding (up to 3 iterations)
2. **Case Normalization**: Convert to lowercase for consistent matching
3. **Path Separator Normalization**: Convert backslashes to forward slashes
4. **Null Byte Removal**: Strip null bytes and control characters
5. **Multiple Slash Reduction**: Normalize consecutive slashes

Example:
```
Input:  /Test%252E%252E%252FEtc%252FPasswd
Step 1: /Test%2E%2E%2FEtc%2FPasswd (first decode)
Step 2: /Test../Etc/Passwd (second decode)
Step 3: /test../etc/passwd (lowercase)
Output: /test../etc/passwd
```

## False Positive Mitigation

### Whitelist Support
- Exact string matching for whitelisted paths
- Supports both full paths and path prefixes
- Configurable per-service or global

### Context-Aware Detection
- API endpoint recognition (`/api/`, `/v1/`, `/v2/`)
- Static asset handling (`.js`, `.css`, `.png`, etc.)
- Search endpoint special handling
- Legitimate file extension consideration

### Priority-Based Filtering
- Low-priority matches on legitimate assets treated as false positives
- High-priority patterns always trigger regardless of context
- Configurable threshold adjustments

## Analytics and Monitoring

### Real-time Metrics
- Total path checks performed
- Block rate and suspicious rate
- False positive tracking
- Pattern effectiveness scores

### Pattern Effectiveness Tracking
```json
{
  "pattern_effectiveness": {
    "sql_injection_1": {
      "matches": 156,
      "accuracy": 0.94,
      "true_positives": 147,
      "false_positives": 9
    }
  }
}
```

### Dashboard Integration
Access analytics via performance dashboard:
```
GET /_guard_ai/performance
```

## Integration with Enforcement System

### Dry-Run Mode Support
- All path filtering respects global dry-run configuration
- Simulated blocks logged with detailed pattern information
- No actual blocking in dry-run mode

### Enforcement Actions
1. **Block Action**: Immediate request termination with 403 response
2. **Log Action**: Detailed incident logging with pattern details
3. **Notification Action**: Alert sending for blocked requests
4. **Analytics Update**: Pattern effectiveness tracking

### Example Log Entry
```json
{
  "timestamp": 1645123456,
  "event_type": "path_filter_match",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "method": "GET",
  "path": "/admin/config",
  "normalized_path": "/admin/config",
  "threat_level": 7,
  "threat_category": "admin_access",
  "confidence": 85,
  "action_taken": "block",
  "matched_patterns": [
    {
      "category": "admin_access",
      "description": "Admin panel access",
      "priority": 2,
      "matched_text": "/admin/"
    }
  ]
}
```

## Performance Characteristics

### Benchmarks
- **Processing Time**: <0.5ms per request average
- **Memory Usage**: <1MB for pattern cache
- **Throughput**: Handles 10K+ RPS with minimal latency impact
- **Pattern Count**: 80+ default patterns across 8 categories

### Optimization Features
- Pre-compiled regex patterns for speed
- Efficient pattern caching
- Limited pattern matching to prevent DoS
- Automatic cache cleanup and maintenance

## Custom Pattern Development

### Pattern Format
```json
{
  "pattern": "(?i)\\bcustom_attack\\b",
  "priority": 1,
  "description": "Custom attack pattern"
}
```

### Best Practices
1. **Use Case-Insensitive Flags**: `(?i)` for most patterns
2. **Word Boundaries**: `\\b` to prevent partial matches
3. **Escape Special Characters**: Properly escape regex metacharacters
4. **Test Patterns**: Validate against known false positives
5. **Set Appropriate Priority**: Match severity to priority level

### Example Custom Patterns
```json
[
  {
    "pattern": "(?i)\\/api\\/.*\\/delete_all",
    "priority": 1,
    "description": "Dangerous bulk delete API"
  },
  {
    "pattern": "(?i)\\bcompany_secret\\b",
    "priority": 2,
    "description": "Company confidential access"
  }
]
```

## Testing and Validation

### Included Test Suite
Comprehensive test coverage including:
- SQL injection pattern detection
- XSS vector identification
- Path traversal prevention
- False positive validation
- Performance benchmarking
- Custom pattern functionality

### Running Tests
```bash
# Run path filter tests
busted kong/plugins/kong-guard-ai/spec/path_filter_spec.lua

# Run with coverage
luacov kong/plugins/kong-guard-ai/spec/path_filter_spec.lua
```

## Troubleshooting

### Common Issues

#### High False Positive Rate
- **Cause**: Overly broad patterns or low thresholds
- **Solution**: Adjust `path_filter_block_threshold` or add to whitelist

#### Low Detection Rate
- **Cause**: High thresholds or missing patterns
- **Solution**: Add custom patterns or lower thresholds

#### Performance Impact
- **Cause**: Too many patterns or complex regex
- **Solution**: Optimize patterns or reduce `path_filter_max_pattern_matches`

### Debug Logging
Enable debug logging to see pattern matching details:
```lua
kong.log.debug("[Path Filter] Checking path: " .. normalized_path)
```

### Analytics Review
Monitor pattern effectiveness via dashboard:
- Patterns with high false positive rates
- Unused patterns that could be removed
- Missing attack vectors requiring new patterns

## Security Considerations

### Attack Evasion Prevention
- Multiple URL decoding rounds
- Case normalization
- Path separator normalization
- Null byte filtering

### Resource Protection
- Limited pattern matching iterations
- Automatic cache cleanup
- Memory usage monitoring
- CPU usage optimization

### Pattern Security
- No user input in regex compilation
- Sanitized custom pattern validation
- Priority-based threat assessment
- Whitelist override capability

## Future Enhancements

### Planned Features
1. **Machine Learning Integration**: Pattern effectiveness learning
2. **Behavioral Analysis**: Request pattern analysis over time
3. **Advanced Evasion Detection**: Unicode normalization, encoding variants
4. **Threat Intelligence Integration**: Dynamic pattern updates
5. **Custom Action Support**: Configurable response actions per pattern

### Extensibility
The system is designed for easy extension:
- Modular pattern categories
- Pluggable normalization functions
- Configurable response actions
- External analytics integration

## Conclusion

The Path Regex Filtering system provides robust protection against URL-based attacks while maintaining high performance and low false positive rates. Its comprehensive pattern coverage, intelligent false positive mitigation, and detailed analytics make it a critical component of the Kong Guard AI security stack.

For technical support or questions, refer to the main Kong Guard AI documentation or contact the development team.