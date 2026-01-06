Part 1: Root Account Hardening
What Was Implemented
	•	Enabled Multi-Factor Authentication (MFA) on the AWS root account.
	•	Disabled all root access keys.
	•	Verified root security posture via the IAM dashboard.
	•	Restricted root usage strictly to emergency break-glass scenarios.
Security Principles Applied
	•	Privileged account protection
	•	Strong authentication controls
	•	Cloud shared responsibility awareness
Evidence
	•	screenshots/root_user_MFA.png

Part 2: Secure Administrative Access Using IAM Roles
What Was Implemented
	•	Created a dedicated IAM administrative user with no direct administrative permissions.
	•	Implemented role-based access control using AWS STS AssumeRole.
	•	Created an administrative IAM role with elevated permissions and enforced MFA for role assumption.
	•	Updated role trust policies to explicitly allow secure user-to-role delegation.
	•	Verified successful role switching using the AWS Management Console.
Security Principles Applied
	•	Least privilege and separation of duties
	•	Role-based access control (RBAC)
	•	Zero standing privileges (ZSP)
	•	Secure identity lifecycle management
Security+ Domains Covered
	•	Identity and Access Management (IAM)
	•	Authentication and authorization
	•	Privileged access management
Evidence
	•	screenshots/admin_user_created.png
	•	screenshots/admin_role_created.png
	•	screenshots/admin_user_assume_role.png
	•	screenshots/admin_user_MFA.png
	•	screenshots/admin_role_trust_policy.png

Part 3: Centralized Logging and Security Monitoring
What Was Implemented
	•	Enabled a multi-Region AWS CloudTrail to capture management events across the account.
	•	Configured CloudTrail to deliver logs to a dedicated, secured S3 bucket with log file integrity validation enabled.
	•	Integrated CloudTrail with CloudWatch Logs for near real-time monitoring and alerting.
CloudTrail and CloudWatch Configuration
	•	Validated CloudTrail configuration and S3 log delivery.
	•	Verified CloudWatch log groups and active log streams for CloudTrail events.
CloudWatch Metric Filters and Alarms
	•	Implemented metric filters to detect:
	◦	Console logins without MFA
	◦	Unauthorized or suspicious API activity
	◦	IAM permission and critical configuration changes
	•	Attached CloudWatch alarms to each filter and configured SNS email notifications.
Security Principles Applied
	•	Centralized audit logging and accountability
	•	Early detection of authentication misuse and configuration drift
	•	Alerting to support incident detection and investigation workflows
Evidence
	•	screenshots/cloudtrail_cloudwatch_enabled.png
	•	screenshots/cloudtrail_trail_details.png
	•	screenshots/cloudtrail_S3bucket_1.png
	•	screenshots/cloudtrail_S3bucket_2.png
	•	screenshots/cloudtrail_S3bucket_3.png
	•	screenshots/cloudtrail_logstreams.png
	•	screenshots/cloudtrail-logstream_events.png
	•	screenshots/cloudwatch_log_group.png
	•	screenshots/cloudwatch_log_metricfilters.png
	•	screenshots/cloudwatch_security_alarms.png

Part 4: Threat Detection with Amazon GuardDuty
What Was Implemented
	•	Enabled Amazon GuardDuty to continuously analyze CloudTrail logs, VPC Flow Logs, and DNS logs.
	•	Used the Generate sample findings feature to explore detection categories such as reconnaissance, credential compromise, and resource abuse.
	•	Investigated a high-severity sample finding to review impacted resources, attacker context, and AWS-recommended remediation steps.
Security Principles Applied
	•	Continuous managed threat detection
	•	Use of AWS-maintained threat intelligence
	•	Investigation workflows that pivot from findings to logs and telemetry
Evidence
	•	screenshots/guardduty_enabled.png
	•	screenshots/guardduty_findings.png

Part 5: Security Posture Management with AWS Security Hub
What Was Implemented
	•	Enabled AWS Security Hub to aggregate findings from GuardDuty and other AWS services.
	•	Activated the following standards:
	◦	AWS Foundational Security Best Practices
	◦	CIS AWS Foundations Benchmark v5.0.0
	•	Verified ingestion and normalization of security findings.
Key Controls Referenced
	•	CloudTrail.3 — At least one CloudTrail trail should be enabledEnsures continuous account-wide audit logging.
	•	GuardDuty.1 — GuardDuty should be enabledEnsures continuous threat detection coverage.
Security Principles Applied
	•	Continuous compliance monitoring
	•	Automated misconfiguration detection
	•	Defense-in-depth across identity, logging, detection, and posture management
Evidence
	•	screenshots/security_standards_enabled.png

Part 6: Mini Incident Response Walkthrough (Sample GuardDuty Finding)
Scenario
A high-severity GuardDuty sample finding was generated to simulate a credential compromise or suspicious API activity. The objective was to practice the incident response lifecycle using native AWS services.
Detection
	•	GuardDuty generated a high-severity finding describing suspicious behavior and impacted resources.
	•	CloudWatch-SNS alerts provided additional indicators of abnormal API activity.
Investigation
	•	Reviewed GuardDuty finding metadata including event type, time, attacker context, and remediation guidance.
	•	Pivoted to CloudTrail and CloudWatch Logs to identify correlated API activity.
Containment
	•	Disabled or rotated affected IAM credentials.
	•	Forced credential resets and terminated active sessions as needed.
	•	Reverted any unauthorized configuration changes.
Recovery and Lessons Learned
	•	Reissued credentials only after validating MFA and least-privilege access.
	•	Used Security Hub to confirm that core controls (CloudTrail.3, GuardDuty.1) remained healthy post-remediation.
	•	Documented the workflow in an optional incident-report.pdf to demonstrate incident handling capabilities.

Tools and Services Used
	•	AWS Identity and Access Management (IAM)
	•	AWS Security Token Service (STS)
	•	AWS CloudTrail and Amazon S3
	•	Amazon CloudWatch Logs, metrics, and alarms
	•	Amazon Simple Notification Service (SNS)
	•	Amazon GuardDuty
	•	AWS Security Hub (CIS + AWS Foundational Security Best Practices)
	•	Custom IAM read-only audit policy for security review and investigation


How to Reproduce
	1	Harden the AWS root account with MFA and disable access keys.
	2	Implement secure administrative access using IAM users and AssumeRole.
	3	Enable CloudTrail with secure S3 log delivery and CloudWatch integration.
	4	Create metric filters and alarms for high-risk security events.
	5	Enable GuardDuty and Security Hub to validate detection and compliance.
	6	Perform a controlled incident response exercise using generated findings.


