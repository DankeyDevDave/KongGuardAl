# GraphQL Protection Guide
## Query Depth and Complexity Analysis for GraphQL Security

### **Overview**

GraphQL Protection in Kong Guard AI provides specialized security controls for GraphQL APIs, preventing resource exhaustion attacks through query depth limiting and complexity analysis. This feature automatically detects GraphQL endpoints and applies sophisticated query analysis to block malicious queries while allowing legitimate operations.

---

## **GraphQL Security Challenges**

### **Resource Exhaustion Attacks**

**Deeply Nested Queries**
```graphql
query MaliciousDepth {
  user {
    posts {
      comments {
        replies {
          user {
            posts {
              comments {
                replies {
                  # ... continues deeply
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**High Complexity Queries**
```graphql
query MaliciousComplexity {
  users(first: 1000) { # Large dataset
    id
    posts(first: 1000) { # Multiplied load
      id
      comments(first: 1000) { # Exponential growth
        id
        content
      }
    }
  }
}
```

**Circular Query References**
```graphql
query CircularReference {
  user(id: "1") {
    friends {
      friends {
        friends {
          # Circular relationships
        }
      }
    }
  }
}
```

---

## **Configuration**

### **Basic Setup**
```yaml
plugins:
- name: kong-guard-ai
  config:
    enable_graphql_detection: true
    graphql_max_depth: 12
    graphql_max_complexity: 2000
```

### **Advanced Configuration**
```yaml
plugins:
- name: kong-guard-ai
  config:
    enable_graphql_detection: true

    # Depth analysis
    graphql_max_depth: 12
    graphql_depth_weight: 1.0

    # Complexity analysis
    graphql_max_complexity: 2000
    graphql_complexity_multipliers:
      field: 1
      list: 2
      connection: 3
      union: 1.5

    # Performance settings
    graphql_analysis_timeout_ms: 100
    graphql_cache_parsed_queries: true
    graphql_cache_ttl_seconds: 300
```

---

## **Query Depth Analysis**

### **How Depth is Calculated**

```graphql
# Depth: 1
query SimpleQuery {
  user { # Depth 1
    name
    email
  }
}

# Depth: 3
query ModerateDepth {
  user { # Depth 1
    posts { # Depth 2
      title # Depth 3
      content # Depth 3
    }
  }
}

# Depth: 5
query DeepQuery {
  user { # Depth 1
    posts { # Depth 2
      comments { # Depth 3
        replies { # Depth 4
          content # Depth 5
        }
      }
    }
  }
}
```

### **Depth Calculation Rules**

1. **Root fields start at depth 1**
2. **Each nested selection increases depth by 1**
3. **Fragments inherit the depth of their location**
4. **Inline fragments don't increase depth**
5. **Union types use maximum field depth**

### **Configuration Examples**

```yaml
# Conservative (API with simple data models)
config:
  graphql_max_depth: 8

# Moderate (typical business applications)
config:
  graphql_max_depth: 12

# Permissive (complex data relationships)
config:
  graphql_max_depth: 15

# Development/testing
config:
  graphql_max_depth: 20
```

---

## **Query Complexity Analysis**

### **Complexity Scoring Algorithm**

**Base Complexity Rules:**
- **Simple field**: 1 point
- **List field**: 2x multiplier
- **Connection field**: 3x multiplier
- **Union field**: 1.5x multiplier
- **Nested selection**: Multiplicative

### **Complexity Calculation Examples**

```graphql
# Complexity: 3 (1 + 1 + 1)
query Simple {
  user { # 1 point
    name # 1 point
    email # 1 point
  }
}

# Complexity: 12 (1 + (1 + 1) * 2 * 3)
query WithLists {
  user { # 1 point
    posts(first: 10) { # List multiplier: 2, estimated items: 3
      title # 1 point each
      content # 1 point each
    }
  }
}

# Complexity: 60 (1 + (1 + (1 + 1) * 2 * 3) * 2 * 3)
query Nested {
  users(first: 10) { # List: 2x, items: 3
    posts(first: 10) { # List: 2x, items: 3
      comments(first: 5) { # List: 2x, items: 3
        content # 1 point each
        author # 1 point each
      }
    }
  }
}
```

### **Dynamic Complexity Analysis**

```graphql
# Complexity varies by arguments
query DynamicComplexity($limit: Int!) {
  users(first: $limit) { # Complexity scales with $limit
    posts {
      comments {
        content
      }
    }
  }
}
```

**Configuration for Dynamic Analysis:**
```yaml
config:
  graphql_complexity_analysis: "dynamic"
  graphql_max_list_size: 100 # Assume max 100 items if not specified
  graphql_default_list_size: 10 # Default assumption
```

---

## **Query Blocking Examples**

### **Depth Violation**
```graphql
# This query would be blocked with max_depth: 12
query TooDeep {
  user { # 1
    posts { # 2
      comments { # 3
        replies { # 4
          user { # 5
            posts { # 6
              comments { # 7
                replies { # 8
                  user { # 9
                    posts { # 10
                      comments { # 11
                        replies { # 12
                          content # 13 - BLOCKED!
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### **Complexity Violation**
```graphql
# This query would be blocked with max_complexity: 2000
query TooComplex {
  users(first: 1000) { # Base: 2000 complexity points
    posts(first: 100) { # Multiplied by 100
      comments(first: 50) { # Multiplied by 50
        content # Total: > 10,000,000 points
      }
    }
  }
}
```

### **Response Format**
```json
{
  "errors": [
    {
      "message": "Query depth exceeded maximum allowed depth of 12",
      "extensions": {
        "code": "QUERY_DEPTH_LIMIT_EXCEEDED",
        "query_depth": 15,
        "max_depth": 12,
        "incident_id": "kg-ai-20250119-001"
      }
    }
  ]
}
```

---

## **Detection and Analysis**

### **Automatic GraphQL Detection**

Kong Guard AI automatically detects GraphQL endpoints using:

1. **Content-Type headers**: `application/graphql`
2. **HTTP method**: POST requests to typical GraphQL paths
3. **Request body structure**: Presence of `query`, `mutation`, or `subscription`
4. **Path patterns**: `/graphql`, `/api/graphql`, `/v1/graphql`

### **Query Parsing and Validation**

```yaml
config:
  graphql_strict_parsing: true
  graphql_allow_introspection: false # Block introspection in production
  graphql_allow_unknown_fields: false
```

### **Custom Detection Rules**

```yaml
config:
  graphql_detection_rules:
    content_types:
      - "application/graphql"
      - "application/json" # For POST with JSON body
    path_patterns:
      - "/graphql"
      - "/api/graphql"
      - "/api/v*/graphql"
    header_indicators:
      - "X-GraphQL-Operation"
      - "Apollo-*"
```

---

## **Monitoring and Metrics**

### **GraphQL-Specific Metrics**

```bash
# Query analysis metrics
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  graphql_requests: .graphql_requests_total,
  graphql_blocked_depth: .graphql_blocked_max_depth,
  graphql_blocked_complexity: .graphql_blocked_max_complexity,
  avg_query_depth: .graphql_avg_query_depth,
  avg_query_complexity: .graphql_avg_query_complexity
}'

# Performance metrics
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  graphql_analysis_time: .graphql_avg_analysis_time_ms,
  graphql_parsing_errors: .graphql_parsing_errors,
  graphql_cache_hits: .graphql_query_cache_hits
}'
```

### **Top Complex Queries**

```bash
# Monitor most complex queries
curl -s http://localhost:8001/kong-guard-ai/graphql/top-complex | jq '.queries[] | {
  complexity: .complexity_score,
  depth: .query_depth,
  operation: .operation_name,
  timestamp: .first_seen
}'
```

### **Query Pattern Analysis**

```bash
# Analyze query patterns
curl -s http://localhost:8001/kong-guard-ai/graphql/patterns | jq '{
  most_requested_fields: .top_fields,
  deepest_queries: .depth_distribution,
  complexity_distribution: .complexity_histogram
}'
```

---

## **Performance Optimization**

### **Query Caching**

```yaml
config:
  graphql_cache_parsed_queries: true
  graphql_cache_ttl_seconds: 300
  graphql_cache_max_size: 1000
```

**Benefits:**
- Avoid re-parsing identical queries
- Faster complexity analysis
- Reduced CPU usage for repeated queries

### **Analysis Timeouts**

```yaml
config:
  graphql_analysis_timeout_ms: 100 # Fail-safe timeout
  graphql_timeout_action: "allow" # or "block"
```

### **Selective Analysis**

```yaml
# Only analyze on specific routes
routes:
- name: graphql-api
  paths: ["/graphql"]
  plugins:
  - name: kong-guard-ai
    config:
      enable_graphql_detection: true

- name: rest-api
  paths: ["/api/rest/*"]
  plugins:
  - name: kong-guard-ai
    config:
      enable_graphql_detection: false # Skip GraphQL analysis
```

---

## **Advanced Features**

### **Operation-Specific Limits**

```yaml
config:
  graphql_operation_limits:
    query:
      max_depth: 12
      max_complexity: 2000
    mutation:
      max_depth: 8 # More restrictive for mutations
      max_complexity: 1000
    subscription:
      max_depth: 6 # Very restrictive for subscriptions
      max_complexity: 500
```

### **Field-Specific Complexity**

```yaml
config:
  graphql_field_complexity:
    "User.posts": 5 # High complexity field
    "Post.comments": 3 # Medium complexity
    "Comment.replies": 10 # Very high complexity
    "User.profile": 1 # Low complexity
```

### **Rate Limiting by Complexity**

```yaml
config:
  graphql_complexity_rate_limit:
    enabled: true
    window_seconds: 60
    max_complexity_per_window: 10000
    max_queries_per_window: 100
```

---

## **Security Best Practices**

### **Production Configuration**

```yaml
# Production-hardened GraphQL protection
config:
  enable_graphql_detection: true

  # Conservative limits
  graphql_max_depth: 10
  graphql_max_complexity: 1500

  # Security features
  graphql_allow_introspection: false
  graphql_block_debug_queries: true
  graphql_require_operation_name: true

  # Performance
  graphql_analysis_timeout_ms: 50
  graphql_cache_parsed_queries: true

  # Monitoring
  graphql_log_blocked_queries: true
  graphql_log_complex_queries: true
```

### **Development Configuration**

```yaml
# Development-friendly settings
config:
  enable_graphql_detection: true

  # Permissive limits
  graphql_max_depth: 15
  graphql_max_complexity: 5000

  # Development features
  graphql_allow_introspection: true
  graphql_log_all_queries: true
  graphql_dry_run: true # Log only, don't block

  # Performance
  graphql_analysis_timeout_ms: 200
```

---

## **Incident Response**

### **Query Blocking Response**

```json
{
  "errors": [
    {
      "message": "Query complexity exceeded limit",
      "extensions": {
        "code": "QUERY_COMPLEXITY_LIMIT_EXCEEDED",
        "query_complexity": 2150,
        "max_complexity": 2000,
        "incident_id": "kg-ai-20250119-002",
        "timestamp": "2025-01-19T10:30:45Z"
      }
    }
  ]
}
```

### **Investigation Tools**

```bash
# Analyze blocked query
curl -s "http://localhost:8001/kong-guard-ai/incidents/kg-ai-20250119-002" | jq '{
  query: .query_text,
  analysis: .complexity_analysis,
  blocking_reason: .blocking_reason,
  client_info: .client_information
}'

# Query complexity breakdown
curl -s "http://localhost:8001/kong-guard-ai/graphql/analyze" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { user { posts { comments { content } } } }"}' | jq '{
  depth: .query_depth,
  complexity: .total_complexity,
  field_breakdown: .complexity_by_field
}'
```

---

## **Troubleshooting**

### **Common Issues**

**Legitimate Queries Blocked**
```yaml
# Solution: Increase limits or use field-specific complexity
config:
  graphql_max_depth: 15 # Increase if too restrictive
  graphql_field_complexity:
    "User.posts": 2 # Reduce complexity for specific fields
```

**Performance Issues**
```yaml
# Solution: Optimize analysis settings
config:
  graphql_analysis_timeout_ms: 50 # Shorter timeout
  graphql_cache_parsed_queries: true
  graphql_simple_complexity_analysis: true # Faster algorithm
```

**False Positives**
```yaml
# Solution: Tune complexity multipliers
config:
  graphql_complexity_multipliers:
    list: 1.5 # Reduce from default 2
    connection: 2 # Reduce from default 3
```

### **Debug Mode**

```yaml
config:
  log_level: "debug"
  graphql_log_all_queries: true
  graphql_log_analysis_details: true
```

**Debug Output Example:**
```
[DEBUG] GraphQL query detected: operation=UserPosts
[DEBUG] Query depth analysis: depth=8, max=12, passed=true
[DEBUG] Query complexity analysis: complexity=450, max=2000, passed=true
[DEBUG] Analysis time: 12ms
```

---

GraphQL Protection provides essential security controls for modern GraphQL APIs, preventing resource exhaustion attacks while maintaining the flexibility and power that makes GraphQL valuable for application development.