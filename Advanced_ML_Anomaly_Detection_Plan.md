## Advanced ML/Anomaly Detection — Detailed Task List

### Objectives
- Implement custom ML models for behavioral analysis and time-series anomaly detection
- Add user behavior profiling and deviation detection
- Integrate with external ML services for enhanced threat detection

---

### 1) Schema additions (config) [Task 11A.1]
- [ ] Add `enable_ml_models` (boolean, default false)
- [ ] Add `ml_model_config` (record):
  - [ ] `behavioral_model_url` (string, optional)
  - [ ] `anomaly_model_url` (string, optional)
  - [ ] `model_timeout_ms` (int, default 1000)
  - [ ] `model_retry_count` (int, default 2)
- [ ] Add `behavioral_profiling` (record):
  - [ ] `enable_user_profiling` (boolean, default false)
  - [ ] `profile_window_hours` (int, default 24)
  - [ ] `deviation_threshold` (number, default 0.7)
- [ ] Add `time_series_analysis` (record):
  - [ ] `enable_traffic_analysis` (boolean, default false)
  - [ ] `analysis_window_minutes` (int, default 60)
  - [ ] `anomaly_sensitivity` (number, default 0.8)
- [ ] Add `ml_scoring_weights` (record):
  - [ ] `behavioral_deviation` (number, default +0.4)
  - [ ] `traffic_anomaly` (number, default +0.3)
  - [ ] `user_anomaly` (number, default +0.5)

---

### 2) Behavioral profiling module `behavioral_profiler.lua` [Task 11A.2]
- [ ] Create module scaffold and exports
- [ ] Implement user behavior tracking:
  - [ ] Request patterns (endpoints, methods, timing)
  - [ ] Session characteristics (duration, frequency)
  - [ ] Geographic patterns (if available)
- [ ] Implement deviation detection:
  - [ ] Statistical analysis of current vs historical behavior
  - [ ] Anomaly scoring based on deviation magnitude
- [ ] Implement caching and data retention:
  - [ ] User profiles in shared cache with TTL
  - [ ] Historical data cleanup policies
- [ ] Unit tests for profiling and deviation detection

---

### 3) Time-series anomaly detection `timeseries_analyzer.lua` [Task 11A.3]
- [ ] Create module scaffold and exports
- [ ] Implement traffic pattern analysis:
  - [ ] Request volume trends
  - [ ] Response time patterns
  - [ ] Error rate analysis
- [ ] Implement anomaly detection algorithms:
  - [ ] Statistical methods (z-score, moving averages)
  - [ ] Simple ML approaches (if external service unavailable)
- [ ] Implement data aggregation:
  - [ ] Time-window based data collection
  - [ ] Rolling window calculations
- [ ] Unit tests for time-series analysis

---

### 4) External ML service integration `ml_client.lua` [Task 11A.4]
- [ ] Create module scaffold and exports
- [ ] Implement HTTP client for ML services:
  - [ ] Request/response handling
  - [ ] Timeout and retry logic
  - [ ] Error handling and fallbacks
- [ ] Implement data preparation:
  - [ ] Feature extraction and normalization
  - [ ] Request payload formatting
- [ ] Implement response processing:
  - [ ] Score interpretation
  - [ ] Confidence level handling
- [ ] Unit tests for ML client

---

### 5) Handler integration [Task 11A.5]
- [ ] Wire behavioral profiler into feature extraction
- [ ] Wire time-series analyzer into threat detection
- [ ] Wire ML client into threat detection pipeline
- [ ] Add ML features to `features` table:
  - [ ] `behavioral_score`
  - [ ] `traffic_anomaly_score`
  - [ ] `user_deviation_score`
- [ ] Include ML results in `threat_details`

---

### 6) Advanced scoring and decision logic [Task 11A.6]
- [ ] Implement ensemble scoring:
  - [ ] Combine multiple ML model outputs
  - [ ] Weighted scoring based on confidence levels
- [ ] Implement adaptive thresholds:
  - [ ] Dynamic threshold adjustment based on false positive rates
  - [ ] Learning from operator feedback
- [ ] Implement model performance tracking:
  - [ ] Accuracy metrics
  - [ ] Response time monitoring

---

### 7) Metrics and observability [Task 11A.7]
- [ ] Add ML-specific metrics:
  - [ ] Model response times
  - [ ] Model accuracy rates
  - [ ] Behavioral deviation counts
  - [ ] Traffic anomaly detections
- [ ] Add performance monitoring:
  - [ ] Memory usage for profiling data
  - [ ] Cache hit rates for user profiles
- [ ] Add debugging capabilities:
  - [ ] Detailed ML decision logging
  - [ ] Model input/output logging (configurable)

---

### 8) Documentation and testing [Task 11A.8]
- [ ] Documentation:
  - [ ] ML model integration guide
  - [ ] Behavioral profiling configuration
  - [ ] Performance tuning recommendations
- [ ] Testing:
  - [ ] Unit tests for all ML modules
  - [ ] Integration tests with mock ML services
  - [ ] Performance tests for profiling overhead

---

### Acceptance criteria
- [ ] Behavioral profiling tracks user patterns and detects deviations
- [ ] Time-series analysis identifies traffic anomalies
- [ ] External ML services integrate seamlessly with fallbacks
- [ ] ML-enhanced scoring improves threat detection accuracy
- [ ] Performance impact is minimal and configurable
- [ ] All tests pass and documentation is complete
