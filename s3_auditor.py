# -*- coding: utf-8 -*-
"""
Created on Sun Jun 28 10:03:09 2026

@author: NDTES_YOG
"""

import os
from datetime import datetime

# Mock S3 bucket data (Our mimicked S3 network environment)
mock_buckets = {
    "public-bucket-1": {
        "name": "public-bucket-1",
        "public": True,
        "encryption": False,
        "versioning": False,
        "logging": False,
        "mfa_delete": False,
        "acl": "public-read",
        "block_public_access": False
    },
    "secure-bucket-2": {
        "name": "secure-bucket-2",
        "public": False,
        "encryption": True,
        "versioning": True,
        "logging": True,
        "mfa_delete": True,
        "acl": "private",
        "block_public_access": True
    },
    "partial-bucket-3": {
        "name": "partial-bucket-3",
        "public": False,
        "encryption": True,
        "versioning": False,
        "logging": False,
        "mfa_delete": False,
        "acl": "private",
        "block_public_access": True
    }
}

class S3Auditor:
    """
    S3 Security Auditor (Mock Network Edition)
    Audits simulated S3 buckets for cloud misconfigurations.
    """
    def __init__(self):
        self.findings = []
        self.checks_passed = 0
        self.checks_failed = 0
        self.risk_score = 0
        self.bucket_name = ""
        self.audit_date = datetime.now().strftime("%B %d, %Y")
        self.all_reports_data = {}

    def reset_counters(self):
        self.findings = []
        self.checks_passed = 0
        self.checks_failed = 0
        self.risk_score = 0
        
    def check_public_acl(self, bucket):
        if bucket['public']:
            self.findings.append({
                'name': 'Public ACL Enabled',
                'severity': 'critical',
                'icon': '⚠️',
                'description': 'The bucket has public ACL permissions enabled, allowing global anonymous read access.',
                'fix': 'Change bucket ACL to private and remove public read policies.',
                'risk_points': 30
            })
            self.checks_failed += 1
            self.risk_score += 30
        else:
            self.checks_passed += 1
            
    def check_encryption(self, bucket):
        if not bucket['encryption']:
            self.findings.append({
                'name': 'No Encryption Enabled',
                'severity': 'critical',
                'icon': '🔓',
                'description': 'Default encryption is not enabled. Data is stored unencrypted at rest.',
                'fix': 'Enable default SSE-S3 or SSE-KMS encryption configuration.',
                'risk_points': 25
            })
            self.checks_failed += 1
            self.risk_score += 25
        else:
            self.checks_passed += 1
            
    def check_versioning(self, bucket):
        if bucket['versioning']:
            self.checks_passed += 1
        else:
            self.findings.append({
                'name': 'Versioning Disabled',
                'severity': 'high',
                'icon': '📜',
                'description': 'Object versioning is disabled. Overwritten or deleted files cannot be recovered.',
                'fix': 'Enable S3 Object Versioning under bucket management.',
                'risk_points': 15
            })
            self.checks_failed += 1
            self.risk_score += 15
            
    def check_logging(self, bucket):
        if not bucket['logging']:
            self.findings.append({
                'name': 'Access Logging Disabled',
                'severity': 'high',
                'icon': '👁️',
                'description': 'Server access logging is unconfigured. Cannot audit or trace data access requests.',
                'fix': 'Define an target log bucket and activate access logging.',
                'risk_points': 12
            })
            self.checks_failed += 1
            self.risk_score += 12
        else:
            self.checks_passed += 1
            
    def check_mfa_delete(self, bucket):
        if not bucket['mfa_delete']:
            self.findings.append({
                'name': 'MFA Delete Not Enabled',
                'severity': 'high',
                'icon': '🔑',
                'description': 'MFA Delete is disabled. Destructive actions can occur without multi-factor authorization.',
                'fix': 'Enable versioning and enforce MFA Delete requirement via AWS CLI.',
                'risk_points': 10
            })
            self.checks_failed += 1
            self.risk_score += 10
        else:
            self.checks_passed += 1
            
    def check_block_public_access(self, bucket):
        if not bucket['block_public_access']:
            self.findings.append({
                'name': 'Block Public Access Disabled',
                'severity': 'high',
                'icon': '🔓',
                'description': 'The explicit Block Public Access policy infrastructure is not active.',
                'fix': 'Turn on all 4 Block Public Access parameters in settings.',
                'risk_points': 5
            })
            self.checks_failed += 1
            self.risk_score += 5
        else:
            self.checks_passed += 1
    
    def get_risk_level(self):
        if self.risk_score >= 70: return "HIGH RISK"
        elif self.risk_score >= 40: return "MEDIUM RISK"
        return "LOW RISK"
    
    def get_risk_class(self):
        if self.risk_score >= 70: return "critical"
        elif self.risk_score >= 40: return "medium"
        return "low"
    
    def audit_bucket(self, bucket_name):
        bucket = mock_buckets.get(bucket_name)
        if not bucket:
            print(f"❌ Bucket {bucket_name} not found.")
            return
            
        self.bucket_name = bucket_name
        self.reset_counters()
        
        self.check_public_acl(bucket)
        self.check_encryption(bucket)
        self.check_versioning(bucket)
        self.check_logging(bucket)
        self.check_mfa_delete(bucket)
        self.check_block_public_access(bucket)
        
        # Capture snapshot for global matrix report
        self.all_reports_data[bucket_name] = {
            'findings': list(self.findings),
            'risk_score': self.risk_score,
            'passed': self.checks_passed,
            'failed': self.checks_failed,
            'level': self.get_risk_level(),
            'class': self.get_risk_class()
        }

    def generate_html_report(self):
        os.makedirs('reports', exist_ok=True)
        
        # Build multi-bucket dashboard rows
        dashboard_rows = ""
        detailed_sections = ""
        
        for name, data in self.all_reports_data.items():
            dashboard_rows += f"""
            <tr>
                <td><strong>{name}</strong></td>
                <td>{data['risk_score']}/100</td>
                <td><span class="status-badge {data['class']}">{data['level']}</span></td>
                <td>✅ {data['passed']} Passed / ❌ {data['failed']} Failed</td>
                <td><a href="#section-{name}">View Details ↓</a></td>
            </tr>
            """
            
            # Generate the dynamic finding blocks
            findings_html = ""
            if not data['findings']:
                findings_html = "<p class='secure-msg'>🎉 Configuration complies with cloud security controls!</p>"
            else:
                for f in data['findings']:
                    findings_html += f"""
                    <div class="finding {f['severity']}">
                        <div class="finding-title">{f['icon']} {f['name']}</div>
                        <div class="finding-description">{f['description']}</div>
                        <div class="finding-fix"><strong>Remediation:</strong> {f['fix']}</div>
                    </div>
                    """
            
            detailed_sections += f"""
            <div class="bucket-section" id="section-{name}">
                <h3>Detailed Log: {name}</h3>
                <p>Overall Risk Points: <strong>{data['risk_score']}/100</strong></p>
                {findings_html}
            </div>
            <hr>
            """

        # Using a safer approach: standard .replace mechanics to bypass f-string CSS failures!
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>S3 Security Audit Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f4f7f6; margin: 0; padding: 30px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; border-radius: 8px; text-align: center; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; color: #333; }
        .status-badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .status-badge.critical { background: #f8d7da; color: #721c24; }
        .status-badge.medium { background: #fff3cd; color: #856404; }
        .status-badge.low { background: #d4edda; color: #155724; }
        .bucket-section { padding-top: 20px; margin-top: 20px; }
        .finding { padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 5px solid; }
        .finding.critical { background: #fdf2f2; border-left-color: #dc3545; color: #2c0e0e; }
        .finding.high { background: #fff9f2; border-left-color: #fd7e14; color: #331b07; }
        .finding-title { font-weight: bold; font-size: 15px; }
        .finding-description { font-size: 13px; margin: 5px 0; }
        .finding-fix { background: rgba(255,255,255,0.8); padding: 8px; font-size: 12px; font-family: monospace; border-radius: 4px; border: 1px dashed #ccc; }
        .secure-msg { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 S3 Security Audit Summary Dashboard</h1>
            <p>Automated Cloud Compliance Analysis Report</p>
        </div>
        
        <h2>📋 Global Bucket Risk Matrix</h2>
        <table>
            <thead>
                <tr>
                    <th>Bucket Name</th>
                    <th>Risk Weight</th>
                    <th>Risk Profile</th>
                    <th>Compliance Metrics</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                [DASHBOARD_ROWS]
            </tbody>
        </table>

        <h2>🔍 Deep-Dive Security Logs</h2>
        [DETAILED_SECTIONS]
    </div>
</body>
</html>"""

        html_final = html_template.replace("[DASHBOARD_ROWS]", dashboard_rows).replace("[DETAILED_SECTIONS]", detailed_sections)
        
        filepath = 'reports/s3_audit_dashboard.html'
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_final)
        return filepath

if __name__ == "__main__":
    auditor = S3Auditor()
    print("🚀 Running Local S3 Architecture Security Scan...")
    
    for bucket in mock_buckets.keys():
        auditor.audit_bucket(bucket)
        
    path = auditor.generate_html_report()
    print(f"\n✅ Professional Multi-Bucket Dashboard generated successfully: {path}")