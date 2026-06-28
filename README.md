<img width="1346" height="648" alt="Screenshot 2026-06-28 102518" src="https://github.com/user-attachments/assets/202656e0-1493-458c-b76e-1c6f45e1052c" />
<img width="1329" height="649" alt="Screenshot 2026-06-28 102530" src="https://github.com/user-attachments/assets/83dfac8b-5bd2-434f-b383-40c59a11027d" />
<img width="1344" height="280" alt="Screenshot 2026-06-28 102545" src="https://github.com/user-attachments/assets/bfce1973-385c-4142-8a97-58fd09fd4c62" />

#CloudGuard S3: Automated Security Audit Engine

An automated cloud compliance tool that evaluates AWS S3 storage environments against cybersecurity industry benchmarks. It analyzes data exposure vectors, evaluates default configuration profiles, isolates active threats, and builds unified visual reports.
 
# Project Architecture & Design Pattern
To enable testing without continuous live AWS API connectivity dependencies or developer platform cost overheads, this engine implements a decoupled **Mock Testing Data Layer**. 

The script iterates over custom configuration topologies, processing rules iteratively, and builds a comprehensive visual report that displays individual severity findings alongside copy-paste remediation commands.

#Tracked Compliance Controls
The evaluation pipeline monitors six high-stakes storage vulnerabilities:
- **Public ACL Exposures:** Prevents unauthorized global access configurations.
- **Block Public Access Blocks:** Validates explicit platform security protection.
- **Server-Side Encryption Configuration:** Audits basic storage encryption.
- **S3 Object Versioning:** Assures fallback logic for destructive cyber actions.
- **Data Server Logging:** Assures tracking visibility for forensic audits.
- **MFA Delete Protections:** Validates multi-factor safe delete controls.

⚙️ How To Run Locally
Ensure you have Python 3 installed. No external packages required!

python s3_auditor.py
