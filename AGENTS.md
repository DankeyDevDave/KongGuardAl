# Kong Guard AI - Agent Development Guide

## Build/Lint/Test Commands

### Python Development
```bash
# Install dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run specific test file
pytest tests/test_specific.py

# Run single test function
pytest tests/test_file.py::TestClass::test_method -v

# Run tests with coverage
pytest --cov=src/kongguard --cov-report=html

# Lint and format
ruff check src/ tests/ --fix
black src/ tests/

# Type checking
mypy src/

# Pre-commit hooks
pre-commit run --all-files
```

### End-to-End Testing
```bash
# Install Playwright dependencies
npm install

# Run all e2e tests
npm test

# Run specific test suite
./run-tests.sh status    # Status checks
./run-tests.sh normal    # Normal traffic tests
./run-tests.sh attack    # Attack simulations
./run-tests.sh quick     # Smoke tests

# Run tests in UI mode
npm run test:ui

# Debug tests
npm run test:debug
```

### Docker Services
```bash
# Start full stack
docker compose up -d

# Start with AI services
docker compose -f docker-compose-with-ai.yml up -d

# View logs
docker compose logs -f kong
```

## Code Style Guidelines

### Python Standards
- **Line Length**: 120 characters (Black)
- **Imports**: isort with single-line imports, kongguard as first-party
- **Linting**: Ruff with comprehensive rules (E, W, F, I, N, UP, S, B, C4, DTZ, T20, SIM, RET, ARG, PLR, PLW, PLE)
- **Type Hints**: MyPy strict mode required
- **Formatting**: Black with Python 3.11+ target

### Import Organization
```python
# Standard library
import json
from typing import Dict, List

# Third-party
import fastapi
from pydantic import BaseModel

# First-party
from kongguard.ai_service import AIThreatAnalyzer
from kongguard.ml_models import ModelManager
```

### Error Handling
```python
import structlog
from typing import Optional

logger = structlog.get_logger()

def process_request(data: Dict) -> Optional[str]:
    """Process request with comprehensive error handling."""
    try:
        # Validate input
        if not data.get("required_field"):
            raise ValueError("Missing required field")

        # Process data
        result = analyze_data(data)

        # Log success
        logger.info("Request processed successfully", request_id=data.get("id"))
        return result

    except ValueError as e:
        logger.warning("Validation error", error=str(e), request_id=data.get("id"))
        raise
    except Exception as e:
        logger.error("Unexpected error", error=str(e), request_id=data.get("id"))
        raise
```

### Naming Conventions
- **Classes**: PascalCase (e.g., `AIThreatAnalyzer`, `ModelManager`)
- **Functions/Methods**: snake_case (e.g., `process_request`, `analyze_data`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_RETRIES`, `DEFAULT_TIMEOUT`)
- **Private**: Leading underscore (e.g., `_internal_method`)
- **Type Variables**: PascalCase with Type suffix (e.g., `RequestData`, `ResponseType`)

### Type Hints
```python
from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel

class RequestModel(BaseModel):
    """Request data model with validation."""
    name: str
    value: Optional[int] = None
    metadata: Dict[str, Any] = {}

def process_items(items: List[Dict[str, Union[str, int]]]) -> List[str]:
    """Process list of items with type safety."""
    return [str(item.get("name", "")) for item in items]
```

### Async/Await Patterns
```python
import asyncio
from typing import AsyncGenerator

async def process_stream(data_stream: AsyncGenerator[Dict, None]) -> List[Dict]:
    """Process async data stream."""
    results = []
    async for item in data_stream:
        processed = await analyze_item(item)
        results.append(processed)
    return results

async def analyze_item(item: Dict) -> Dict:
    """Analyze single item with timeout."""
    try:
        return await asyncio.wait_for(
            _analyze_item_internal(item),
            timeout=30.0
        )
    except asyncio.TimeoutError:
        logger.warning("Analysis timeout", item_id=item.get("id"))
        raise
```

### Testing Patterns
```python
import pytest
from unittest.mock import Mock, AsyncMock

class TestAIThreatAnalyzer:
    """Test cases for AI threat analyzer."""

    @pytest.fixture
    def analyzer(self) -> AIThreatAnalyzer:
        """Create test analyzer instance."""
        return AIThreatAnalyzer()

    @pytest.mark.asyncio
    async def test_analyze_normal_request(self, analyzer: AIThreatAnalyzer) -> None:
        """Test analysis of normal request."""
        request_data = {"method": "GET", "path": "/api/users"}

        result = await analyzer.analyze(request_data)

        assert result["threat_level"] == "low"
        assert "analysis" in result

    def test_invalid_input_handling(self, analyzer: AIThreatAnalyzer) -> None:
        """Test handling of invalid input."""
        with pytest.raises(ValueError, match="Invalid request data"):
            analyzer.validate_request({})
```

### Logging Standards
```python
import structlog

logger = structlog.get_logger(__name__)

def process_with_logging(data: Dict) -> Dict:
    """Process data with structured logging."""
    logger.info(
        "Processing started",
        operation="data_processing",
        data_size=len(data),
        request_id=data.get("id")
    )

    try:
        result = perform_processing(data)
        logger.info(
            "Processing completed",
            operation="data_processing",
            status="success",
            result_size=len(result)
        )
        return result
    except Exception as e:
        logger.error(
            "Processing failed",
            operation="data_processing",
            status="error",
            error=str(e),
            error_type=type(e).__name__
        )
        raise
```

## Cursor Rules Integration

### Taskmaster Workflow
- Use `task-master next` to get next available task
- Use `task-master show <id>` to view task details
- Use `task-master set-status --id=<id> --status=done` to complete tasks
- Use `task-master update-subtask --id=<id> --prompt="notes"` for implementation logging

### Development Workflow
- Follow iterative subtask implementation pattern
- Log progress and findings during development
- Use research mode for complex technical decisions
- Maintain task context across sessions

### MCP Server Usage
- Prefer MCP tools over CLI commands when available
- Use `get_tasks`, `next_task`, `get_task`, `set_task_status` for task management
- Use `expand_task` for breaking down complex tasks
- Use `research` for fresh technical information

## Testing Guidelines

### Unit Tests
- Minimum 80% code coverage required
- Use pytest with async support
- Mock external dependencies
- Test both success and error paths
- Use descriptive test names and docstrings

### Integration Tests
- Test service interactions
- Use test containers for external services
- Verify data flow between components
- Test error scenarios and recovery

### E2E Tests
- Use Playwright for browser automation
- Test complete user workflows
- Verify UI interactions and API responses
- Run against local development stack

### Test Organization
```
tests/
├── unit/           # Unit tests
├── integration/   # Integration tests
└── e2e/          # End-to-end tests
    ├── utils/     # Test helpers
    └── *.spec.ts  # Playwright test files
```

## Security Considerations

### Code Security
- Use Ruff bandit rules for security scanning
- Avoid hardcoded secrets
- Validate all inputs
- Use parameterized queries for database operations
- Implement proper authentication/authorization

### Dependency Security
- Keep dependencies updated
- Use safety checks for known vulnerabilities
- Review dependency licenses
- Pin critical dependency versions

## Performance Guidelines

### Code Performance
- Use async/await for I/O operations
- Implement proper caching strategies
- Monitor memory usage
- Profile performance-critical code
- Use efficient data structures

### Database Performance
- Use connection pooling
- Implement proper indexing
- Batch database operations
- Use async database drivers
- Monitor query performance

## Documentation Standards

### Code Documentation
- Use docstrings for all public functions/classes
- Include type hints in docstrings
- Document parameters, return values, and exceptions
- Keep docstrings concise but informative

### API Documentation
- Document all API endpoints
- Include request/response examples
- Specify authentication requirements
- Document error responses

## Git Workflow

### Commit Standards
- Use conventional commit format
- Write clear, descriptive commit messages
- Reference task IDs in commits (e.g., `feat: implement JWT auth (task 1.2)`)
- Keep commits focused and atomic

### Branch Strategy
- Use feature branches for new development
- Create branches from task IDs when possible
- Rebase frequently to keep branches up-to-date
- Use descriptive branch names

## Deployment Guidelines

### Container Standards
- Use multi-stage Docker builds
- Minimize image size
- Use specific base image versions
- Include health checks
- Follow security best practices

### Configuration Management
- Use environment variables for configuration
- Provide sensible defaults
- Validate configuration on startup
- Document all configuration options

## Monitoring & Observability

### Logging
- Use structured logging with context
- Include relevant IDs and metadata
- Log at appropriate levels (DEBUG, INFO, WARNING, ERROR)
- Avoid logging sensitive information

### Metrics
- Track key performance indicators
- Monitor error rates and response times
- Use Prometheus for metrics collection
- Set up alerts for critical issues

### Health Checks
- Implement comprehensive health checks
- Check dependencies and external services
- Return detailed health status
- Use for load balancer configuration