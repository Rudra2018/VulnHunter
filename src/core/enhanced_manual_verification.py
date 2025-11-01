#!/usr/bin/env python3
"""
VulnHunter Enhanced Manual Verification Module
Advanced manual verification with context analysis, control flow, and semantic understanding
"""

import re
import ast
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict

# Optional networkx import
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

@dataclass
class VerificationContext:
    """Context information for vulnerability verification"""
    file_path: str
    function_name: str
    line_number: int
    code_context: str
    imports: List[str]
    function_signature: str
    control_flow: Dict[str, Any]
    semantic_patterns: List[str]
    framework_context: str

@dataclass
class VerificationResult:
    """Result of manual verification"""
    vulnerability_id: str
    status: str  # 'verified', 'false_positive', 'needs_review'
    confidence: float
    reason: str
    poc_feasible: bool
    exploitability_score: float
    technical_details: Dict[str, Any]

class EnhancedManualVerifier:
    """Enhanced manual verification with deep code analysis"""

    def __init__(self):
        self.framework_patterns = {
            'cosmwasm': {
                'entry_points': [r'#\[cfg_attr.*entry_point\)', r'cosmwasm_std::entry_point'],
                'access_control': [r'info\.sender', r'deps\.api\.addr_validate', r'ADMIN\.load'],
                'query_functions': [r'StdResult<Binary>', r'to_json_binary'],
                'state_modifying': [r'DepsMut', r'\.save\(', r'\.remove\(']
            },
            'ethereum': {
                'access_control': [r'onlyOwner', r'require\(.*owner', r'msg\.sender'],
                'state_modifying': [r'state\s+\w+', r'mapping\s*\(', r'storage'],
                'view_functions': [r'view\s+returns', r'pure\s+returns']
            },
            'substrate': {
                'extrinsics': [r'#\[pallet::call\]', r'DispatchResult'],
                'access_control': [r'ensure_signed', r'ensure_root', r'T::AdminOrigin']
            }
        }

        self.vulnerability_patterns = {
            'access_control': {
                'admin_bypass': [r'admin\s*=', r'owner\s*=', r'privileged.*='],
                'missing_checks': [r'function.*public', r'pub\s+fn.*admin'],
                'weak_validation': [r'tx\.origin', r'block\.timestamp']
            },
            'reentrancy': {
                'external_calls': [r'\.call\(', r'\.delegatecall\(', r'\.send\('],
                'state_changes': [r'balance\[', r'balances\[', r'\.transfer\(']
            },
            'integer_overflow': {
                'arithmetic': [r'\+\s*\w+', r'\-\s*\w+', r'\*\s*\w+'],
                'unsafe_operations': [r'unchecked', r'unsafe']
            }
        }

    def verify_vulnerability(self, vuln_data: Dict[str, Any], source_code: str) -> VerificationResult:
        """Enhanced vulnerability verification with deep analysis"""

        # Extract context
        context = self._extract_verification_context(vuln_data, source_code)

        # Perform multi-layered analysis
        syntactic_analysis = self._analyze_syntax(context)
        semantic_analysis = self._analyze_semantics(context)
        control_flow_analysis = self._analyze_control_flow(context)
        framework_analysis = self._analyze_framework_context(context)

        # Combine analyses for final verdict
        verification_result = self._combine_analyses(
            vuln_data, context, syntactic_analysis, semantic_analysis,
            control_flow_analysis, framework_analysis
        )

        return verification_result

    def _extract_verification_context(self, vuln_data: Dict[str, Any], source_code: str) -> VerificationContext:
        """Extract comprehensive context for verification"""

        lines = source_code.split('\n')
        line_num = vuln_data.get('line', 1) - 1

        # Extract function context
        function_start, function_end = self._find_function_boundaries(lines, line_num)
        function_code = '\n'.join(lines[function_start:function_end])

        # Extract imports and dependencies
        imports = self._extract_imports(lines)

        # Determine framework context
        framework = self._detect_framework(source_code, imports)

        # Build control flow graph
        control_flow = self._build_control_flow(function_code)

        return VerificationContext(
            file_path=vuln_data.get('file', ''),
            function_name=self._extract_function_name(lines, line_num),
            line_number=vuln_data.get('line', 1),
            code_context=function_code,
            imports=imports,
            function_signature=self._extract_function_signature(lines, function_start),
            control_flow=control_flow,
            semantic_patterns=self._extract_semantic_patterns(function_code),
            framework_context=framework
        )

    def _analyze_syntax(self, context: VerificationContext) -> Dict[str, Any]:
        """Syntactic analysis of the code"""

        analysis = {
            'has_access_control': False,
            'has_state_modification': False,
            'is_view_function': False,
            'parameter_validation': False,
            'error_handling': False
        }

        code = context.code_context.lower()

        # Check for access control patterns
        framework_patterns = self.framework_patterns.get(context.framework_context, {})
        access_patterns = framework_patterns.get('access_control', [])

        for pattern in access_patterns:
            if re.search(pattern, context.code_context, re.IGNORECASE):
                analysis['has_access_control'] = True
                break

        # Check for state modification
        state_patterns = framework_patterns.get('state_modifying', [])
        for pattern in state_patterns:
            if re.search(pattern, context.code_context):
                analysis['has_state_modification'] = True
                break

        # Check for view/query functions
        view_patterns = framework_patterns.get('query_functions', []) + framework_patterns.get('view_functions', [])
        for pattern in view_patterns:
            if re.search(pattern, context.code_context):
                analysis['is_view_function'] = True
                break

        # Check for parameter validation
        validation_patterns = [r'require\(', r'assert\(', r'ensure\(', r'if.*return.*err']
        for pattern in validation_patterns:
            if re.search(pattern, context.code_context, re.IGNORECASE):
                analysis['parameter_validation'] = True
                break

        # Check for error handling
        error_patterns = [r'Result<', r'Error', r'panic', r'revert', r'Err\(']
        for pattern in error_patterns:
            if re.search(pattern, context.code_context):
                analysis['error_handling'] = True
                break

        return analysis

    def _analyze_semantics(self, context: VerificationContext) -> Dict[str, Any]:
        """Semantic analysis of code meaning and intent"""

        analysis = {
            'function_purpose': self._classify_function_purpose(context),
            'privilege_level': self._determine_privilege_level(context),
            'data_flow': self._analyze_data_flow(context),
            'trust_boundaries': self._identify_trust_boundaries(context)
        }

        return analysis

    def _analyze_control_flow(self, context: VerificationContext) -> Dict[str, Any]:
        """Control flow analysis for vulnerability paths"""

        analysis = {
            'has_early_returns': False,
            'authorization_gates': [],
            'vulnerable_paths': [],
            'protection_mechanisms': []
        }

        # Check for early returns (common in access control)
        if re.search(r'if.*return.*Err', context.code_context, re.IGNORECASE):
            analysis['has_early_returns'] = True
            analysis['authorization_gates'].append('early_return_on_unauthorized')

        # Identify authorization gates
        auth_patterns = [
            r'if.*admin.*!=.*sender',
            r'if.*owner.*!=.*sender',
            r'ensure_signed',
            r'only_admin',
            r'require.*owner'
        ]

        for pattern in auth_patterns:
            if re.search(pattern, context.code_context, re.IGNORECASE):
                analysis['authorization_gates'].append(pattern)

        return analysis

    def _analyze_framework_context(self, context: VerificationContext) -> Dict[str, Any]:
        """Framework-specific analysis"""

        analysis = {
            'framework': context.framework_context,
            'is_framework_function': False,
            'framework_compliance': True,
            'standard_patterns': []
        }

        # Check if it's a framework-required function
        framework_functions = {
            'cosmwasm': ['instantiate', 'execute', 'query', 'sudo', 'migrate'],
            'ethereum': ['constructor', 'fallback', 'receive'],
            'substrate': ['on_initialize', 'on_finalize', 'offchain_worker']
        }

        framework_funcs = framework_functions.get(context.framework_context, [])
        for func in framework_funcs:
            if func in context.function_name.lower():
                analysis['is_framework_function'] = True
                break

        return analysis

    def _combine_analyses(self, vuln_data: Dict[str, Any], context: VerificationContext,
                         syntactic: Dict[str, Any], semantic: Dict[str, Any],
                         control_flow: Dict[str, Any], framework: Dict[str, Any]) -> VerificationResult:
        """Combine all analyses for final verification result"""

        # Default to false positive
        status = 'false_positive'
        confidence = 0.1
        reason = 'Unknown analysis result'
        poc_feasible = False
        exploitability_score = 0.0

        # Framework function check
        if framework['is_framework_function']:
            return VerificationResult(
                vulnerability_id=vuln_data.get('id', 'unknown'),
                status='false_positive',
                confidence=0.95,
                reason='Framework-required function',
                poc_feasible=False,
                exploitability_score=0.0,
                technical_details={'framework_function': True}
            )

        # View/Query function check
        if syntactic['is_view_function'] and not syntactic['has_state_modification']:
            return VerificationResult(
                vulnerability_id=vuln_data.get('id', 'unknown'),
                status='false_positive',
                confidence=0.9,
                reason='Read-only function with no state modification',
                poc_feasible=False,
                exploitability_score=0.0,
                technical_details={'view_function': True}
            )

        # Access control verification
        if vuln_data.get('category') == 'access_control':
            if syntactic['has_access_control'] and control_flow['authorization_gates']:
                return VerificationResult(
                    vulnerability_id=vuln_data.get('id', 'unknown'),
                    status='false_positive',
                    confidence=0.85,
                    reason='Proper access control implementation detected',
                    poc_feasible=False,
                    exploitability_score=0.1,
                    technical_details={
                        'access_control_mechanisms': control_flow['authorization_gates'],
                        'protection_level': 'high'
                    }
                )
            elif not syntactic['has_access_control'] and syntactic['has_state_modification']:
                return VerificationResult(
                    vulnerability_id=vuln_data.get('id', 'unknown'),
                    status='verified',
                    confidence=0.8,
                    reason='State-modifying function without access control',
                    poc_feasible=True,
                    exploitability_score=0.7,
                    technical_details={
                        'vulnerability_type': 'missing_access_control',
                        'impact': 'unauthorized_state_modification'
                    }
                )

        # If we reach here, needs manual review
        return VerificationResult(
            vulnerability_id=vuln_data.get('id', 'unknown'),
            status='needs_review',
            confidence=0.5,
            reason='Complex case requiring manual review',
            poc_feasible=False,
            exploitability_score=0.3,
            technical_details={'requires_manual_analysis': True}
        )

    def _find_function_boundaries(self, lines: List[str], target_line: int) -> Tuple[int, int]:
        """Find the start and end of the function containing the target line"""

        start = max(0, target_line - 5)  # Safe fallback
        end = min(len(lines), target_line + 10)  # Safe fallback

        # Find function start
        for i in range(min(target_line, len(lines) - 1), -1, -1):
            if i >= len(lines):
                continue
            line = lines[i].strip()
            if (re.match(r'(pub\s+)?fn\s+\w+', line) or
                re.match(r'function\s+\w+', line) or
                re.match(r'def\s+\w+', line)):
                start = i
                break

        # Find function end
        brace_count = 0
        paren_count = 0
        in_function = False

        for i in range(start, len(lines)):
            line = lines[i]

            if not in_function and ('{' in line or '(' in line):
                in_function = True

            if in_function:
                brace_count += line.count('{') - line.count('}')
                paren_count += line.count('(') - line.count(')')

                if brace_count <= 0 and paren_count <= 0 and i > start:
                    end = i + 1
                    break

        return start, min(end, len(lines))

    def _extract_imports(self, lines: List[str]) -> List[str]:
        """Extract import statements"""
        imports = []
        for line in lines:
            line = line.strip()
            if (line.startswith('use ') or line.startswith('import ') or
                line.startswith('from ') or line.startswith('#include')):
                imports.append(line)
        return imports

    def _detect_framework(self, source_code: str, imports: List[str]) -> str:
        """Detect the framework being used"""

        # Check imports and keywords
        all_text = source_code + ' '.join(imports)

        if 'cosmwasm' in all_text.lower():
            return 'cosmwasm'
        elif any(kw in all_text.lower() for kw in ['solidity', 'pragma', 'contract']):
            return 'ethereum'
        elif any(kw in all_text.lower() for kw in ['substrate', 'pallet', 'frame']):
            return 'substrate'
        else:
            return 'unknown'

    def _extract_function_name(self, lines: List[str], line_num: int) -> str:
        """Extract function name from context"""
        for i in range(line_num, -1, -1):
            line = lines[i].strip()
            match = re.match(r'(pub\s+)?fn\s+(\w+)', line)
            if match:
                return match.group(2)
        return 'unknown'

    def _extract_function_signature(self, lines: List[str], start_line: int) -> str:
        """Extract complete function signature"""
        signature = ""
        in_signature = False

        for i in range(start_line, min(start_line + 5, len(lines))):
            line = lines[i].strip()
            if 'fn ' in line or 'function ' in line:
                in_signature = True

            if in_signature:
                signature += line + " "
                if '{' in line or ';' in line:
                    break

        return signature.strip()

    def _build_control_flow(self, function_code: str) -> Dict[str, Any]:
        """Build control flow representation"""

        # Simple control flow analysis
        flow = {
            'conditionals': len(re.findall(r'\bif\b', function_code)),
            'loops': len(re.findall(r'\b(for|while|loop)\b', function_code)),
            'returns': len(re.findall(r'\breturn\b', function_code)),
            'function_calls': len(re.findall(r'\w+\s*\(', function_code))
        }

        return flow

    def _extract_semantic_patterns(self, code: str) -> List[str]:
        """Extract semantic patterns from code"""
        patterns = []

        # Common security patterns
        if re.search(r'admin|owner|auth', code, re.IGNORECASE):
            patterns.append('access_control_related')

        if re.search(r'transfer|send|withdraw', code, re.IGNORECASE):
            patterns.append('financial_operation')

        if re.search(r'msg\.sender|info\.sender', code):
            patterns.append('sender_verification')

        return patterns

    def _classify_function_purpose(self, context: VerificationContext) -> str:
        """Classify the purpose of the function"""

        func_name = context.function_name.lower()
        code = context.code_context.lower()

        if any(word in func_name for word in ['query', 'get', 'view', 'read']):
            return 'query'
        elif any(word in func_name for word in ['admin', 'owner', 'privileged']):
            return 'administrative'
        elif any(word in func_name for word in ['transfer', 'send', 'withdraw']):
            return 'financial'
        elif any(word in func_name for word in ['init', 'setup', 'deploy']):
            return 'initialization'
        else:
            return 'general'

    def _determine_privilege_level(self, context: VerificationContext) -> str:
        """Determine required privilege level"""

        if 'admin' in context.code_context.lower():
            return 'admin'
        elif 'owner' in context.code_context.lower():
            return 'owner'
        elif any(word in context.code_context.lower() for word in ['public', 'external']):
            return 'public'
        else:
            return 'unknown'

    def _analyze_data_flow(self, context: VerificationContext) -> Dict[str, Any]:
        """Analyze data flow in the function"""

        return {
            'input_validation': 'validate' in context.code_context.lower(),
            'output_sanitization': 'sanitize' in context.code_context.lower(),
            'external_calls': len(re.findall(r'\.call\(|\.send\(', context.code_context)),
            'state_reads': len(re.findall(r'\.load\(|\.get\(', context.code_context)),
            'state_writes': len(re.findall(r'\.save\(|\.set\(', context.code_context))
        }

    def _identify_trust_boundaries(self, context: VerificationContext) -> List[str]:
        """Identify trust boundaries in the code"""

        boundaries = []

        if 'msg.sender' in context.code_context or 'info.sender' in context.code_context:
            boundaries.append('sender_verification')

        if re.search(r'external|public', context.code_context):
            boundaries.append('external_interface')

        if re.search(r'admin|owner', context.code_context):
            boundaries.append('privilege_boundary')

        return boundaries