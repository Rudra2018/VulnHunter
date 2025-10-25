#!/usr/bin/env python3
"""
VulnHunter Verification Engine Demo
Demonstrates the 7-layer verification process on real vulnerability examples
"""

import asyncio
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

from vulnhunter_verification_engine import VulnHunterVerificationEngine, VerificationConfig

# Sample vulnerable code examples
VULNERABLE_SAMPLES = {
    "struts_cve_2006_1546": '''
package com.example.struts;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginAction extends Action {
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                               HttpServletRequest request, HttpServletResponse response) {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // VULNERABILITY: SQL Injection through direct parameter concatenation
        String query = "SELECT * FROM users WHERE username = '" + username +
                      "' AND password = '" + password + "'";

        // Simulate database authentication
        boolean authenticated = performDatabaseAuth(query);

        if (authenticated) {
            return mapping.findForward("success");
        } else {
            return mapping.findForward("failure");
        }
    }

    private boolean performDatabaseAuth(String query) {
        // Database implementation would be here
        return false;
    }
}
''',

    "command_injection": '''
import subprocess
import os

def process_file(filename):
    # VULNERABILITY: Command injection through user input
    # Attacker could inject: "file.txt; rm -rf /"
    command = "cat " + filename
    result = subprocess.call(command, shell=True)
    return result

def backup_files(directory):
    # VULNERABILITY: OS command injection
    backup_cmd = f"tar -czf backup.tar.gz {directory}"
    os.system(backup_cmd)

def ping_host(hostname):
    # VULNERABILITY: Command injection in ping
    ping_cmd = f"ping -c 1 {hostname}"
    subprocess.call(ping_cmd, shell=True)
''',

    "spring_rce": '''
package com.example.spring;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class VulnerableSpringController {

    @PostMapping("/update")
    @ResponseBody
    public String updateUser(@RequestParam String userData, @RequestBody Object userObject) {
        // VULNERABILITY: Potential Spring4Shell via property binding
        // Dangerous pattern: binding user input to object properties
        // Can lead to class.module.classLoader manipulation

        UserData user = new UserData();

        // This pattern is vulnerable in Spring < 5.3.18
        // Attackers can manipulate class.module.classLoader.resources.context.parent.pipeline
        bindUserData(user, userData);

        return "User updated: " + userData;
    }

    private void bindUserData(UserData user, String data) {
        // Simulated property binding - vulnerable implementation
        user.setData(data);
    }

    public static class UserData {
        private String data;

        public void setData(String data) {
            this.data = data;
        }

        public String getData() {
            return data;
        }
    }
}
''',

    "xss_vulnerability": '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABILITY: Cross-Site Scripting (XSS)
    # User input directly embedded in HTML without sanitization
    template = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <script>
            var searchTerm = "{query}";
            document.title = "Results for " + searchTerm;
        </script>
    </body>
    </html>
    """

    return render_template_string(template)

@app.route('/profile')
def profile():
    username = request.args.get('username', 'Guest')

    # VULNERABILITY: Reflected XSS
    return f"<h1>Welcome {username}!</h1>"

if __name__ == '__main__':
    app.run(debug=True)  # VULNERABILITY: Debug mode in production
''',

    "buffer_overflow": '''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];

    // VULNERABILITY: Buffer overflow - no bounds checking
    strcpy(buffer, input);

    printf("Buffer contains: %s\\n", buffer);
}

void unsafe_sprintf(char *user_input) {
    char dest[32];

    // VULNERABILITY: Buffer overflow via sprintf
    sprintf(dest, "User: %s", user_input);

    printf("%s\\n", dest);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);

        char large_input[256];
        // VULNERABILITY: Gets function - no bounds checking
        printf("Enter data: ");
        gets(large_input);

        unsafe_sprintf(large_input);
    }

    return 0;
}
'''
}

async def demonstrate_verification():
    """Demonstrate the verification engine on various vulnerability types"""

    print("🛡️ VulnHunter 7-Layer Verification Engine Demo")
    print("=" * 60)

    # Configure verification engine for demo
    config = VerificationConfig(
        feature_completeness_threshold=0.1,  # Lower for demo
        ensemble_confidence_threshold=0.3,
        final_confidence_threshold=0.4,
        nvd_api_key=None  # Use test CVE database
    )

    engine = VulnHunterVerificationEngine(config)

    results = {}

    for vuln_name, code_sample in VULNERABLE_SAMPLES.items():
        print(f"\n🔍 Testing: {vuln_name.upper().replace('_', ' ')}")
        print("-" * 40)

        # Determine framework
        if 'struts' in vuln_name:
            framework = 'struts'
        elif 'spring' in vuln_name:
            framework = 'spring'
        elif 'flask' in code_sample.lower():
            framework = 'flask'
        else:
            framework = 'general'

        try:
            # Run verification
            result = await engine.verify_vulnerabilities(code_sample, framework)
            results[vuln_name] = result

            # Display results
            print(f"Framework: {framework}")
            print(f"Overall Confidence: {result.get('overall_confidence', 0):.1%}")
            print(f"Validation Status: {result.get('validation_status', 'unknown')}")
            print(f"Verified Findings: {len(result.get('verified_findings', []))}")

            if 'error' in result:
                print(f"Note: {result['error']}")

            # Show top recommendations
            recommendations = result.get('remediation_recommendations', [])
            if recommendations:
                print("Top Recommendations:")
                for i, rec in enumerate(recommendations[:3], 1):
                    print(f"  {i}. {rec}")

        except Exception as e:
            print(f"❌ Verification failed: {e}")
            results[vuln_name] = {'error': str(e)}

    # Summary
    print(f"\n📊 VERIFICATION SUMMARY")
    print("=" * 60)

    successful_verifications = 0
    total_verifications = len(VULNERABLE_SAMPLES)

    for vuln_name, result in results.items():
        status = "✅ SUCCESS" if 'error' not in result else "❌ ERROR"
        confidence = result.get('overall_confidence', 0)
        print(f"{vuln_name.ljust(25)} {status} (Confidence: {confidence:.1%})")

        if 'error' not in result:
            successful_verifications += 1

    print(f"\nSuccess Rate: {successful_verifications}/{total_verifications} ({successful_verifications/total_verifications:.1%})")

    print(f"\n🎯 VulnHunter Verification Engine Demo Complete!")
    print(f"   - Processed {total_verifications} vulnerability samples")
    print(f"   - Successfully analyzed {successful_verifications} samples")
    print(f"   - Demonstrated 7-layer verification process")
    print(f"   - Generated comprehensive security reports")

async def interactive_demo():
    """Interactive demo allowing user to input code"""

    print("\n🎮 Interactive VulnHunter Demo")
    print("=" * 40)
    print("Enter code to analyze (or 'quit' to exit):")
    print("Supported frameworks: spring, struts, flask, django, general")

    config = VerificationConfig(
        feature_completeness_threshold=0.1,
        final_confidence_threshold=0.3
    )
    engine = VulnHunterVerificationEngine(config)

    while True:
        try:
            framework = input("\nFramework (spring/struts/flask/general): ").strip().lower()
            if framework == 'quit':
                break

            if framework not in ['spring', 'struts', 'flask', 'django', 'general']:
                framework = 'general'

            print("Enter your code (press Ctrl+D or Ctrl+Z when done):")
            code_lines = []
            try:
                while True:
                    line = input()
                    code_lines.append(line)
            except EOFError:
                pass

            code_text = '\n'.join(code_lines)

            if not code_text.strip():
                print("No code entered. Skipping...")
                continue

            print(f"\n🔍 Analyzing {len(code_text)} characters of {framework} code...")

            result = await engine.verify_vulnerabilities(code_text, framework)

            print(f"\n📊 ANALYSIS RESULTS")
            print("-" * 30)
            print(f"Overall Confidence: {result.get('overall_confidence', 0):.1%}")
            print(f"Validation Status: {result.get('validation_status', 'unknown')}")
            print(f"Findings: {len(result.get('verified_findings', []))}")

            if result.get('remediation_recommendations'):
                print("\n🚀 Recommendations:")
                for i, rec in enumerate(result['remediation_recommendations'][:5], 1):
                    print(f"  {i}. {rec}")

        except KeyboardInterrupt:
            print("\n\nDemo interrupted by user.")
            break
        except Exception as e:
            print(f"Error during analysis: {e}")

    print("Interactive demo ended.")

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        asyncio.run(interactive_demo())
    else:
        asyncio.run(demonstrate_verification())