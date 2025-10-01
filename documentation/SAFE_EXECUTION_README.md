# Safe Execution & Sandbox

## Overview

The vulnerability detection framework includes comprehensive security controls for all external command execution through the `SecureRunner` system. This ensures that fuzzing, static analysis tools, and other external binaries run in a controlled, sandboxed environment with strict resource limits and security policies.

## Security Controls

### 1. Binary Allowlist
- Only pre-approved binaries can be executed
- System binaries: `ls`, `cat`, `grep`, `python3`, `java`, etc.
- Custom tools: Binaries placed in `./tools/bin/` directory
- Path validation prevents directory traversal attacks

### 2. Resource Limits
- **CPU Time**: Configurable limit (default: 30 seconds)
- **Memory**: Configurable limit (default: 500MB)
- **File Descriptors**: Limited to 256 per process
- **Process Count**: Limited to 10 child processes
- **Core Dumps**: Disabled for security

### 3. Sandboxed Environment
- Each execution runs in isolated directory: `./sandbox_runs/<run_id>/`
- Separate input, output, logs, and temporary directories
- Working directory restricted to sandbox
- Comprehensive audit logging

### 4. Command Validation
- Blocks dangerous patterns: `&&`, `||`, `;`, `|`, shell redirections
- Prevents command injection attacks
- Validates binary paths and arguments
- Syntax validation before execution

## Usage

### Basic Usage
```python
from src.utils.secure_runner import secure_run

# Simple command execution
result = secure_run("echo 'Hello World'", timeout=10)
print(f"Status: {result.status.value}")
print(f"Output: {result.stdout}")
```

### Advanced Usage
```python
from src.utils.secure_runner import SecureRunner

runner = SecureRunner()

# Execute with custom limits and environment
result = runner.secure_run(
    cmd=["python3", "analysis.py", "input.txt"],
    timeout=60,
    cpu_time=45,
    mem_bytes=1024*1024*1024,  # 1GB
    env_vars={"ANALYSIS_MODE": "strict"},
    allowlist=["custom_tool"],
    working_dir="/path/to/workspace"
)
```

### Dry Run Validation
```python
# Validate command without execution
result = secure_run("potentially_dangerous_command", dry_run=True)
if result.status.value == "dry_run":
    print("Command is safe to execute")
else:
    print(f"Command blocked: {result.error_message}")
```

## Running Fuzzers Safely

### AFL++ Integration
The fuzzing orchestrator has been updated to use secure execution:

```python
# Fuzzing automatically uses secure runner
campaign = create_fuzzing_campaign(targets, max_runtime=3600)
orchestrator.start_campaign(campaign_id)
```

Key safety features for fuzzing:
- AFL++ binaries must be in allowlist or `./tools/bin/`
- Memory limits enforced per fuzzing instance
- CPU time limits prevent runaway processes
- Sandbox isolation for each fuzzing target
- Comprehensive logging of all fuzzing activities

### Approved Fuzzing Tools
```bash
# Place fuzzing tools in secure directory
mkdir -p ./tools/bin
cp /usr/bin/afl-fuzz ./tools/bin/
cp /usr/bin/afl-gcc ./tools/bin/
cp /usr/bin/afl-clang ./tools/bin/
```

## Monitoring and Logging

### Execution Logs
Each execution creates detailed logs in `./sandbox_runs/<run_id>/logs/execution.log`:
```json
{
  "run_id": "uuid4-string",
  "timestamp": 1234567890.123,
  "command": ["echo", "test"],
  "status": "success",
  "return_code": 0,
  "execution_time": 0.045,
  "memory_used": 1048576,
  "stdout_length": 5,
  "stderr_length": 0
}
```

### Sandbox Structure
```
./sandbox_runs/<run_id>/
├── input/          # Input files for the execution
├── output/         # Captured stdout/stderr files
├── logs/           # Execution logs and metadata
└── tmp/            # Temporary working directory
```

### Cleanup
```python
# Clean sandbox but keep logs
runner.cleanup_sandbox(run_id, keep_logs=True)

# Complete cleanup
runner.cleanup_sandbox(run_id, keep_logs=False)
```

## Responsible Disclosure

### Security Testing Guidelines
1. **Never test on production systems** without explicit authorization
2. **Use isolated test environments** for vulnerability research
3. **Respect rate limits** and resource constraints
4. **Follow coordinated disclosure** for any vulnerabilities found

### Vulnerability Reporting
If you discover security issues in the framework:

1. **DO NOT** create public issues immediately
2. **Email security concerns** to: [security@project.org]
3. **Include** detailed reproduction steps
4. **Provide** suggested fixes if possible
5. **Allow** reasonable time for remediation before public disclosure

### Testing Targets
Approved targets for vulnerability testing:
- **Synthetic test cases** in `./test_cases/`
- **Public vulnerability databases** (CVE, NVD)
- **Intentionally vulnerable applications** (DVWA, WebGoat)
- **Your own applications** with proper authorization

### Prohibited Activities
- Testing against systems you don't own
- Denial of service attacks
- Data exfiltration or system compromise
- Bypassing security controls in production

## Configuration

### Environment Setup
```bash
# Create necessary directories
mkdir -p ./tools/bin
mkdir -p ./sandbox_runs
mkdir -p ./test_cases

# Set permissions
chmod 755 ./tools/bin
chmod 700 ./sandbox_runs
```

### Custom Configuration
```python
# Custom runner configuration
runner = SecureRunner(
    sandbox_base_dir="./custom_sandbox",
    tools_bin_dir="./custom_tools",
    log_level=logging.DEBUG
)

# Add custom allowed binaries
runner.allowed_binaries.update(['custom_analyzer', 'special_tool'])
```

### Resource Limits
Adjust limits based on your system:
```python
# For memory-intensive analysis
result = secure_run(
    "memory_intensive_tool",
    mem_bytes=8*1024*1024*1024,  # 8GB
    cpu_time=1800,               # 30 minutes
    timeout=2000                 # 33 minutes total
)
```

## Troubleshooting

### Common Issues

1. **"Binary not in allowlist"**
   - Add binary to `./tools/bin/` or update allowlist
   - Verify binary has execute permissions

2. **"Command timed out"**
   - Increase timeout or cpu_time limits
   - Check for infinite loops in target code

3. **"Memory limit exceeded"**
   - Increase mem_bytes limit
   - Optimize target application memory usage

4. **"Permission denied"**
   - Check file permissions in sandbox
   - Verify binary executable permissions

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable debug logging
runner = SecureRunner(log_level=logging.DEBUG)
result = runner.secure_run("debug_command", timeout=10)
```

### Sandbox Inspection
```python
# Get detailed sandbox information
info = runner.get_sandbox_info(run_id)
print(f"Sandbox path: {info['sandbox_path']}")
print(f"Execution log: {info['execution_log']}")
```

## Best Practices

1. **Always use secure_run()** for external commands
2. **Set appropriate timeouts** for long-running processes
3. **Monitor resource usage** in production deployments
4. **Regular cleanup** of sandbox directories
5. **Audit logs** for security monitoring
6. **Test in isolation** before production use
7. **Keep allowlists minimal** and regularly reviewed
8. **Update security policies** as threats evolve

## Integration Examples

### Static Analysis Tool
```python
def run_static_analyzer(source_file, config_file):
    result = secure_run([
        "static_analyzer",
        "--config", config_file,
        "--input", source_file,
        "--format", "json"
    ], timeout=300, mem_bytes=2*1024*1024*1024)

    if result.status.value == "success":
        return json.loads(result.stdout)
    else:
        raise AnalysisError(f"Analysis failed: {result.error_message}")
```

### Fuzzing Campaign
```python
def start_secure_fuzzing(target_binary, corpus_dir):
    fuzzer_config = {
        'timeout': 3600,
        'memory_limit': '1G',
        'cpu_time': 3500
    }

    campaign_id = orchestrator.create_campaign([target_binary], fuzzer_config)
    return orchestrator.start_campaign(campaign_id)
```

This secure execution framework ensures that all external tool integration maintains the highest security standards while enabling comprehensive vulnerability detection capabilities.