# Security Patches for External Command Execution

## Patch 1: Fuzzing Orchestrator (fuzzing_orchestrator.py)

### Before (Lines 230-245):
```python
def start_afl_instance(self, target: FuzzingTarget, instance_id: int = 0) -> Optional[subprocess.Popen]:
    """Start AFL++ fuzzing instance"""
    try:
        if not self.setup_afl_environment(target):
            return None

        cmd = [
            'afl-fuzz',
            '-i', f"{target.output_dir}/corpus",
            '-o', f"{target.output_dir}/findings",
            '-t', str(target.timeout * 1000),
            '-m', target.memory_limit,
            '-D'
        ]

        if target.dictionary_path:
            cmd.extend(['-x', target.dictionary_path])

        cmd.extend(target.command_line)

        env = os.environ.copy()
        env['AFL_SKIP_CPUFREQ'] = '1'
        env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'

        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
```

### After (Secure Implementation):
```python
def start_afl_instance(self, target: FuzzingTarget, instance_id: int = 0) -> Optional[Dict[str, Any]]:
    """Start AFL++ fuzzing instance using secure runner"""
    from src.utils.secure_runner import get_secure_runner

    try:
        if not self.setup_afl_environment(target):
            return None

        # Build AFL++ command
        cmd = [
            'afl-fuzz',
            '-i', f"{target.output_dir}/corpus",
            '-o', f"{target.output_dir}/findings",
            '-t', str(target.timeout * 1000),
            '-m', target.memory_limit,
            '-D'
        ]

        if target.dictionary_path:
            cmd.extend(['-x', target.dictionary_path])

        cmd.extend(target.command_line)

        # Prepare environment variables
        env_vars = {
            'AFL_SKIP_CPUFREQ': '1',
            'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES': '1'
        }

        # Get secure runner and execute
        runner = get_secure_runner()

        # For long-running fuzzing, we use a modified approach
        # First validate the command
        validation_result = runner.secure_run(
            cmd,
            timeout=5,  # Quick validation
            dry_run=True,
            env_vars=env_vars
        )

        if validation_result.status.value != "dry_run":
            logging.error(f"AFL command validation failed: {validation_result.error_message}")
            return None

        # For actual fuzzing execution, we need to handle long-running processes
        # Use secure_run with extended timeout and monitoring
        instance_key = f"{target.target_id}_{instance_id}"

        # Start fuzzing in background with monitoring
        fuzzing_result = runner.secure_run(
            cmd,
            timeout=target.max_runtime,  # Use target's max runtime
            cpu_time=target.max_runtime - 60,  # Slightly less than timeout
            mem_bytes=self._parse_memory_limit(target.memory_limit),
            env_vars=env_vars,
            allowlist=['afl-fuzz', 'afl-gcc', 'afl-clang']  # AFL tools
        )

        # Store result information instead of process object
        self.active_instances[instance_key] = {
            'status': 'running' if fuzzing_result.status.value == 'success' else 'failed',
            'run_id': fuzzing_result.run_id,
            'start_time': time.time(),
            'command': fuzzing_result.command,
            'sandbox_path': fuzzing_result.sandbox_path
        }

        self.instance_configs[instance_key] = {
            'target': target,
            'instance_id': instance_id,
            'command': cmd,
            'start_time': time.time()
        }

        logging.info(f"Started AFL instance {instance_key} with run_id {fuzzing_result.run_id}")
        return self.active_instances[instance_key]

    except Exception as e:
        logging.error(f"Failed to start AFL instance: {e}")
        return None

def _parse_memory_limit(self, memory_limit: str) -> int:
    """Parse memory limit string to bytes"""
    memory_limit = memory_limit.upper().strip()
    if memory_limit.endswith('M'):
        return int(memory_limit[:-1]) * 1024 * 1024
    elif memory_limit.endswith('G'):
        return int(memory_limit[:-1]) * 1024 * 1024 * 1024
    elif memory_limit.endswith('K'):
        return int(memory_limit[:-1]) * 1024
    else:
        return int(memory_limit)
```

## Patch 2: Taint Analyzer (taint_analyzer.py)

The taint analyzer doesn't actually execute external commands - it only analyzes code that contains external calls. However, we should add a secure validation method for any dynamic analysis features.

### Addition to TaintAnalyzer class:

```python
def validate_code_execution(self, code_snippet: str, language: str = "python") -> Dict[str, Any]:
    """
    Safely validate code execution patterns without actually running code.
    Uses secure runner in dry-run mode for validation.
    """
    from src.utils.secure_runner import get_secure_runner

    validation_results = {
        'safe_to_analyze': True,
        'security_issues': [],
        'recommendations': []
    }

    # Check for dangerous patterns that should never be executed
    dangerous_patterns = [
        'os.system', 'subprocess.call', 'subprocess.Popen', 'exec(', 'eval(',
        'rm -rf', 'dd if=', 'mkfs', 'fdisk', '__import__', 'open('
    ]

    for pattern in dangerous_patterns:
        if pattern in code_snippet:
            validation_results['security_issues'].append({
                'type': 'dangerous_pattern',
                'pattern': pattern,
                'severity': 'high',
                'message': f"Code contains potentially dangerous pattern: {pattern}"
            })

    # If we need to execute any validation commands, use secure runner
    if language == "python" and len(validation_results['security_issues']) == 0:
        runner = get_secure_runner()

        # Dry run syntax validation
        syntax_check = runner.secure_run(
            ["python3", "-m", "py_compile", "-"],
            dry_run=True,
            timeout=5
        )

        if syntax_check.status.value == "dry_run":
            validation_results['recommendations'].append(
                "Code syntax can be validated safely"
            )

    return validation_results
```
