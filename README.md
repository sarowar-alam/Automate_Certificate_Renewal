# Certificate Automation Platform

**Enterprise-grade SSL/TLS certificate lifecycle automation for multi-cloud and hybrid infrastructure**

A Jenkins-orchestrated automation platform that manages SSL/TLS certificate validation, renewal, distribution, and monitoring across AWS and on-premises Windows/Linux infrastructure. The system uses Let's Encrypt certificates via Route53 DNS validation and maintains zero-downtime deployments across IIS, Jenkins, Zabbix, and AWS Certificate Manager.

---

## Table of Contents

- [System Architecture](#system-architecture)
- [Prerequisites & Dependencies](#prerequisites--dependencies)
- [Environment Setup](#environment-setup)
- [Installation & Configuration](#installation--configuration)
- [Running the System](#running-the-system)
- [Code Navigation Guide](#code-navigation-guide)
- [Deployment Procedures](#deployment-procedures)
- [Operational Procedures](#operational-procedures)
- [Security & Compliance](#security--compliance)
- [Troubleshooting](#troubleshooting)
- [Contributing & Change Management](#contributing--change-management)
- [Disaster Recovery](#disaster-recovery)

---

## System Architecture

### Overview

The platform operates as a multi-stage Jenkins pipeline with orchestrated PowerShell and Python automation modules. Certificate operations follow a validation-first approach with automatic rollback capabilities.

```
┌─────────────────────────────────────────────────────────────────┐
│                    JENKINS ORCHESTRATOR                         │
│                  (automated-certificate-update.gvy)             │
└─────────────────────────────────────────────────────────────────┘
         │
         ├──[Stage 1: Validity Check]──> ssl.ps1
         │                                  │
         │                                  ├─> <15 days: PROCEED
         │                                  └─> >15 days: EXIT
         │
         ├──[Stage 2: AWS Instance Start]──> start-mainline-rc.py
         │                                      └─> Wait for status checks
         │
         ├──[Stage 3: Certificate Creation]──> backup-create-cert.ps1
         │                                        │
         │                                        ├─> Posh-ACME + Route53
         │                                        ├─> Backup existing certs
         │                                        └─> Store in %LOCALAPPDATA%
         │
         ├──[Stage 4: AWS ACM Update]──> update-aws-certificate.py
         │                                  └─> Multi-region import
         │
         ├──[Stage 5: Deployment]
         │     │
         │     ├──> update-iis-robust.ps1 (IIS servers)
         │     ├──> update-jenkins-windows.ps1 (Windows Jenkins)
         │     ├──> update-jenkins-linux.py (Linux Jenkins)
         │     └──> update-zabbix-certificate.py (Zabbix)
         │
         ├──[Stage 6: Distribution]──> send_certificate_email.py
         │                               ├─> Zip certificates
         │                               ├─> Upload to S3
         │                               └─> Email presigned URL
         │
         └──[Post: Cleanup & Notifications]
               ├─> Workspace cleanup
               └─> Failure notifications (SES)
```

### Key Design Decisions

1. **Certificate Authority**: Let's Encrypt via ACME protocol for zero-cost, automated renewals
2. **DNS Validation**: Route53 DNS-01 challenge for wildcard certificate support
3. **Storage Strategy**: Local filesystem (`%LOCALAPPDATA%\Posh-ACME`) with S3 distribution
4. **Deployment Model**: Push-based (Jenkins initiates) rather than pull-based
5. **Rollback Strategy**: Automatic backups created before each deployment with timestamped archives
6. **Credential Management**: Jenkins Credentials Plugin with no plaintext secrets in code
7. **Idempotency**: Scripts detect existing valid certificates to prevent unnecessary renewals
8. **Monitoring Approach**: Validity checks run before renewal attempts (< 15 days triggers renewal)

### Components & Responsibilities

| Component | Language | Purpose | Failure Impact |
|-----------|----------|---------|----------------|
| `automated-certificate-update.gvy` | Groovy | Orchestration & control flow | **Critical** - entire pipeline fails |
| `ssl.ps1` | PowerShell | Certificate validity checking | Medium - may cause unnecessary renewals |
| `backup-create-cert.ps1` | PowerShell | ACME certificate generation | **Critical** - no new certificates |
| `start-mainline-rc.py` | Python | EC2 instance lifecycle | Low - optional pre-deployment step |
| `update-aws-certificate.py` | Python | ACM multi-region import | High - AWS services affected |
| `update-iis-robust.ps1` | PowerShell | IIS binding updates | High - web services affected |
| `update-jenkins-windows.ps1` | PowerShell | Jenkins Windows keystore | **Critical** - Jenkins HTTPS affected |
| `update-jenkins-linux.py` | Python | Jenkins Linux keystore | **Critical** - Jenkins HTTPS affected |
| `update-zabbix-certificate.py` | Python | Zabbix cert deployment | Medium - monitoring UI affected |
| `send_certificate_email.py` | Python | Certificate distribution | Low - notification only |

---

## Prerequisites & Dependencies

### Infrastructure Requirements

#### Jenkins Controller
- **OS**: Windows Server 2016+ or Windows 10+
- **Jenkins**: 2.300+ (LTS recommended)
- **Agent Labels**: `built-in` or Windows agent with PowerShell support
- **Plugins Required**:
  - Pipeline (workflow-aggregator)
  - Credentials Plugin
  - Credentials Binding Plugin
  - PowerShell Plugin (optional, for native PowerShell execution)

#### Target Servers
- **Windows IIS Servers**: WinRM enabled, PowerShell 5.1+, Administrator access
- **Linux Jenkins Servers**: SSH enabled, sudo privileges for `jenkins` user
- **Zabbix Servers**: SSH enabled, Apache/httpd configured for SSL

#### AWS Services
The following AWS services must be available with appropriate IAM permissions:
- **Route53**: Hosted zones for DNS validation
- **EC2**: (Optional) For starting instances before deployment
- **S3**: Certificate archive storage and distribution
- **ACM**: Certificate Manager for multi-region import
- **SES**: Email notifications (sender must be verified)

### Software Dependencies

#### Jenkins Agent (Windows)

| Software | Version | Purpose | Install Command |
|----------|---------|---------|-----------------|
| PowerShell | 5.1+ | Script execution | Pre-installed on Windows |
| Posh-ACME | 4.x | ACME certificate generation | `Install-Module -Name Posh-ACME -Scope CurrentUser` |
| Python | 3.8+ | Automation scripts | Download from python.org |
| boto3 | Latest | AWS SDK for Python | `pip install boto3` |
| paramiko | Latest | SSH connectivity | `pip install paramiko` |
| 7-Zip | 19.00+ | Certificate archiving | Download from 7-zip.org |
| OpenJDK | 11+ | Keytool for JKS conversion | Download from adoptium.net |
| AWS CLI | 2.x | (Optional) Manual testing | `msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi` |

#### Version Lock File

Create `requirements.txt` for Python dependencies:

```txt
boto3==1.26.137
paramiko==3.1.0
cryptography==40.0.2
```

Install with: `pip install -r requirements.txt`

### Network Requirements

#### Outbound Connectivity
- `acme-v02.api.letsencrypt.org:443` - ACME API
- `*.amazonaws.com:443` - AWS services (Route53, S3, ACM, SES)
- Target server IPs on ports: `5986` (WinRM-HTTPS), `22` (SSH)

#### Firewall Rules
```
Jenkins Agent -> Let's Encrypt     : TCP 443 (HTTPS)
Jenkins Agent -> AWS APIs          : TCP 443 (HTTPS)
Jenkins Agent -> IIS Servers       : TCP 5986 (WinRM-HTTPS)
Jenkins Agent -> Linux Servers     : TCP 22 (SSH)
```

### IAM Permissions

Create a dedicated IAM user or role with the following policy:

<details>
<summary>Click to expand IAM Policy JSON</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Route53DNSValidation",
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:GetChange",
        "route53:ChangeResourceRecordSets",
        "route53:ListResourceRecordSets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2InstanceControl",
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ACMCertificateManagement",
      "Effect": "Allow",
      "Action": [
        "acm:ImportCertificate",
        "acm:ListCertificates",
        "acm:DescribeCertificate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3CertificateStorage",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::company-a-logs/certificates/*"
    },
    {
      "Sid": "SESEmailNotifications",
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "ses:FromAddress": "noreply@company-a.example.com"
        }
      }
    }
  ]
}
```
</details>

---

## Environment Setup

### 1. Jenkins Agent Preparation

#### Install Posh-ACME Module

```powershell
# Run as the Jenkins service account
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Install Posh-ACME
Install-Module -Name Posh-ACME -Scope CurrentUser -Force

# Verify installation
Get-Module -ListAvailable -Name Posh-ACME

# Set Let's Encrypt production server (not staging)
Set-PAServer LE_PROD
```

#### Install Python Dependencies

```powershell
# Ensure Python is in PATH
python --version  # Should output 3.8+

# Install required packages
pip install boto3==1.26.137 paramiko==3.1.0 cryptography==40.0.2

# Verify installations
python -c "import boto3; print(boto3.__version__)"
python -c "import paramiko; print(paramiko.__version__)"
```

#### Install 7-Zip

```powershell
# Download and install 7-Zip
$installer = "$env:TEMP\7z-install.msi"
Invoke-WebRequest -Uri "https://7-zip.org/a/7z1900-x64.msi" -OutFile $installer
Start-Process msiexec.exe -Wait -ArgumentList "/i $installer /quiet /norestart"

# Verify installation
& "C:\Program Files\7-Zip\7z.exe" --help
```

#### Install OpenJDK for Keytool

```powershell
# Download OpenJDK 11
$jdkUrl = "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.18%2B10/OpenJDK11U-jdk_x64_windows_hotspot_11.0.18_10.msi"
$installer = "$env:TEMP\openjdk11.msi"
Invoke-WebRequest -Uri $jdkUrl -OutFile $installer
Start-Process msiexec.exe -Wait -ArgumentList "/i $installer /quiet ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome"

# Verify keytool is available
keytool -help
```

### 2. AWS Configuration

#### Create SES Verified Identity

```bash
# Verify sender email address in SES
aws ses verify-email-identity --email-address noreply@company-a.example.com --region us-east-1

# Check verification status
aws ses get-identity-verification-attributes --identities noreply@company-a.example.com --region us-east-1
```

#### Create S3 Bucket for Certificates

```bash
# Create S3 bucket
aws s3 mb s3://company-a-logs --region us-east-1

# Create certificates folder
aws s3api put-object --bucket company-a-logs --key certificates/ --region us-east-1

# Enable versioning for audit trail
aws s3api put-bucket-versioning --bucket company-a-logs --versioning-configuration Status=Enabled --region us-east-1
```

#### Verify Route53 Hosted Zone

```bash
# List hosted zones
aws route53 list-hosted-zones --query "HostedZones[?Name=='example.com.'].Id" --output text

# Note the Hosted Zone ID for configuration
```

### 3. Target Server Configuration

#### Windows IIS Servers - Enable WinRM

```powershell
# Run on each IIS server
Enable-PSRemoting -Force

# Configure HTTPS listener (recommended)
New-SelfSignedCertificate -DnsName $(hostname) -CertStoreLocation Cert:\LocalMachine\My | 
  ForEach-Object {
    $thumbprint = $_.Thumbprint
    New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $thumbprint -Force
  }

# Open firewall
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow

# Test from Jenkins agent
Test-WSMan -ComputerName <IIS-SERVER-IP> -UseSSL
```

#### Linux Servers - Configure SSH Access

```bash
# On Jenkins agent, create SSH key if not exists
ssh-keygen -t rsa -b 4096 -f C:\KEYS\aws-region-1.pem -N ""

# Copy public key to target servers
# (Manual step - append public key to ~/.ssh/authorized_keys on each server)

# Test connectivity
ssh -i C:\KEYS\aws-region-1.pem rocky@<LINUX-SERVER-IP> "echo 'Connection successful'"

# Configure sudo for rocky user (on target server)
echo "rocky ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/rocky
```

---

## Installation & Configuration

### 1. Clone Repository

```powershell
# Clone to Jenkins workspace location
cd C:\Jenkins\workspace
git clone <repository-url> certificate-automation
cd certificate-automation
```

### 2. Configure Jenkins Credentials

Create the following credentials in Jenkins (`Manage Jenkins` > `Manage Credentials`):

| Credential ID | Type | Description | Fields |
|---------------|------|-------------|--------|
| `jenkins-aws-creds-id` | Username/Password | AWS access keys | Username=Access Key, Password=Secret Key |
| `aws-creds-id-1` | Username/Password | AWS for SES/S3 | Username=Access Key, Password=Secret Key |
| `aws-creds-id-2` | Username/Password | AWS for S3 upload | Username=Access Key, Password=Secret Key |
| `jenkins-win-admin-id` | Username/Password | Windows remote admin | Username=Administrator, Password=<password> |

**Security Note**: Use IAM roles instead of access keys when running Jenkins on EC2.

### 3. Update Pipeline Configuration

Edit `automated-certificate-update.gvy` to match your environment:

```groovy
environment {
    // AWS Configuration
    AWS_REGION = "us-west-2"                          // Primary AWS region
    
    // Certificate Passwords
    PFX_PASS = "your_pfx_password"                    // PFX export password
    JENKINS_PFX_PASS = "your_jenkins_pfx_password"    // Jenkins keystore password
    
    // Infrastructure IPs (comma-separated for multiple servers)
    COMPANY_A_PROD_SERVER_IP = "10.0.1.10,10.0.1.11"  // IIS servers
    ZABBIX_PROD_SERVER_IP = "10.0.1.20"               // Zabbix server
    JENKINS_LINUX_SERVER_IP = "10.0.1.30"             // Linux Jenkins
    
    CERTIFICATE_UPDATE_STATUS = false
}

parameters {
    choice(
        name: 'DOMAIN',
        choices: [
            '*.service-x.example.com',
            '*.service-y.example.com'  // Add more domains as needed
        ],
        description: 'Select Certificate Name to Renew and Update'
    )
}
```

Update domain-to-instance mapping (for EC2 start):

```groovy
switch(params.DOMAIN) {
    case '*.service-x.example.com':
        instanceId = "['i-1234567890abcdef0', 'i-0fedcba0987654321']"
        break
    case '*.service-y.example.com':
        instanceId = "['i-abcdef1234567890']"
        break
}
```

### 4. Create Jenkins Pipeline Job

1. New Item > Pipeline
2. Name: "Certificate-Renewal-Automation"
3. Pipeline Definition: "Pipeline script from SCM"
4. SCM: Git
5. Repository URL: <your-repo-url>
6. Script Path: automated-certificate-update.gvy
7. Save

### 5. Initial Test Run

Before production deployment, test individual components:

```powershell
# Test certificate validity check
.\ssl.ps1 -Domain "zabbix.service-x.example.com"

# Test certificate creation (staging)
Set-PAServer LE_STAGE
.\backup-create-cert.ps1 -Domain "*.service-x.example.com" -AccessKey "AWS_KEY" -SecretKey "AWS_SECRET" -PfxPass "test_password"
Set-PAServer LE_PROD
```

---

## Running the System

### Manual Execution

#### Via Jenkins UI
1. Navigate to Jenkins job: `Certificate-Renewal-Automation`
2. Click **"Build with Parameters"**
3. Select domain from dropdown: `*.service-x.example.com`
4. Click **"Build"**
5. Monitor console output for progress

### Automated Scheduling

Add to Jenkins job configuration:

```groovy
triggers {
    // Check daily and only renew if needed (recommended)
    cron('0 2 * * *')
}
```

### Pipeline Stages Overview

1. **Validity Check** (5-10 sec): Query certificate expiration
2. **Start Instances** (2-5 min): Wake EC2 instances if needed
3. **Certificate Creation** (60-90 sec): Generate via Posh-ACME
4. **ACM Update** (10-20 sec/region): Import to AWS
5. **Host Deployment** (5-10 min): Deploy to all infrastructure
6. **Email Distribution** (15-30 sec): Share via S3 presigned URL

---

## Code Navigation Guide

### File Organization

```
certificate-automation/
├── automated-certificate-update.gvy   # [Orchestration] Jenkins pipeline
├── backup-create-cert.ps1             # [Core] Certificate generation
├── ssl.ps1                            # [Utility] Expiration checker
├── start-mainline-rc.py               # [AWS] EC2 instance starter
├── update-aws-certificate.py          # [AWS] ACM importer
├── update-iis-robust.ps1              # [Deploy] IIS certificate update
├── update-jenkins-windows.ps1         # [Deploy] Windows Jenkins update
├── update-jenkins-linux.py            # [Deploy] Linux Jenkins update
├── update-zabbix-certificate.py       # [Deploy] Zabbix update
└── send_certificate_email.py          # [Notify] Email distribution
```

### Key Script Details

#### `automated-certificate-update.gvy`
- **Lines 1-30**: Pipeline structure and parameters
- **Lines 32-50**: Environment variables
- **Lines 52-90**: Validity check logic
- **Lines 222-380**: Host deployment (most complex section)

#### `backup-create-cert.ps1`
- Backs up existing certificates
- Calls Posh-ACME with Route53 DNS validation
- Returns `[RESULT] NEW_CERT` or `[RESULT] REUSED_CERT`

#### `ssl.ps1`
- Queries SSL certificate expiration
- Returns integer (days remaining) or 0 (error)

---

## Deployment Procedures

### Pre-Deployment Checklist

1. Verify Let's Encrypt account: `Get-PAAccount`
2. Test connectivity to all targets (WinRM/SSH)
3. Verify AWS permissions (Route53, ACM, S3, SES)
4. Backup current certificates manually

### Production Deployment

**Via Jenkins UI** (Recommended):
1. Navigate to job
2. Build with Parameters
3. Select domain
4. Monitor console output

### Post-Deployment Verification

```powershell
# Verify certificate validity
.\ssl.ps1 -Domain "zabbix.service-x.example.com"  # Should output ~90 days

# Check IIS bindings
Get-WebBinding | Where-Object { $_.protocol -eq "https" }

# Verify Jenkins HTTPS
curl -I https://jenkins-windows.service-x.example.com

# Check AWS ACM
aws acm list-certificates --region us-west-2
```

### Rollback Procedures

If deployment fails:

**IIS**:
```powershell
# Restore old certificate binding
$backupThumbprint = "<previous-thumbprint>"
Remove-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443
New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443
$binding.AddSslCertificate($backupThumbprint, "My")
```

**Jenkins**:
```powershell
# Restore backup JKS
$backup = Get-ChildItem "jenkins.*.jks_backup_*" | Sort-Object -Descending | Select -First 1
Copy-Item $backup "jenkins.service-x.example.com.jks" -Force
Restart-Service Jenkins
```

---

## Operational Procedures

### Certificate Monitoring

```powershell
# check-all-certificates.ps1
$domains = @(
    "zabbix.service-x.example.com",
    "jenkins-windows.service-x.example.com",
    "jenkins-linux.service-x.example.com"
)

foreach ($domain in $domains) {
    $daysLeft = .\ssl.ps1 -Domain $domain
    $status = if ($daysLeft -gt 30) { "OK" } elseif ($daysLeft -gt 15) { "WARNING" } else { "CRITICAL" }
    
    Write-Host "$domain : $daysLeft days ($status)"
}
```

### Adding New Domains

1. Update pipeline parameters (choices list)
2. Add instance ID mapping (if using EC2 start)
3. Add subdomain mapping (for validity checks)
4. Update email recipients
5. Test end-to-end

---

## Security & Compliance

### Credential Management
- All AWS keys stored as Jenkins Credentials
- No plaintext secrets in code
- Rotate credentials quarterly

### Certificate Security
- PFX files encrypted with strong password (16+ chars)
- Private keys never transmitted unencrypted
- Filesystem permissions restricted

### Audit Logging
- Jenkins Audit Trail Plugin enabled
- AWS CloudTrail for API monitoring
- Certificate lifecycle logs maintained

---

## Troubleshooting

### Common Issues

**1. Certificate Validity Check Failures**
- Symptom: `ssl.ps1` returns `0`
- Causes: DNS resolution failure, firewall blocking 443
- Fix: Verify DNS records, check firewall rules

**2. Posh-ACME Rate Limit Errors**
- Symptom: "too many certificates already issued"
- Causes: Exceeded Let's Encrypt limit (50/week)
- Fix: Wait for rate limit reset, use staging for tests

**3. WinRM Connection Failures**
- Symptom: "Unable to connect to remote server"
- Causes: WinRM not configured, firewall blocking 5986
- Fix: Enable WinRM, configure HTTPS listener

**4. SSH Connection Failures**
- Symptom: Authentication failed
- Causes: SSH key not authorized, incorrect permissions
- Fix: Add public key to authorized_keys

**5. ACM Import Failures**
- Symptom: "Certificate private key does not match"
- Causes: Key/cert mismatch, invalid PEM format
- Fix: Verify certificate chain, regenerate if needed

### Debug Mode

Enable verbose logging:
```powershell
$DebugPreference = "Continue"
$VerbosePreference = "Continue"
```

---

## Contributing & Change Management

### Development Workflow

1. Create feature branch
2. Make changes
3. Test locally (use Let's Encrypt staging)
4. Commit with conventional commit message
5. Create pull request
6. Code review
7. Merge to main
8. Deploy to production

### Git Commit Conventions

```
feat: add new feature
fix: bug fix
docs: documentation only
chore: maintenance tasks
```

### Testing Strategy

- Unit tests (Pester for PowerShell, pytest for Python)
- Integration tests (full pipeline in test environment)
- Smoke tests (quick validation after deployment)

---

## Disaster Recovery

### Backup Strategy

**Certificate Backups**:
- Location: `C:\backup-certificates\`
- Format: ZIP with timestamp
- Retention: 90 days

**Offsite Backup**:
```bash
aws s3 sync C:\backup-certificates\ s3://company-a-disaster-recovery/certificate-backups/
```

### Recovery Procedures

**Scenario 1: Jenkins Server Failure**
- RTO: 4 hours, RPO: 24 hours
- Restore Jenkins home from backup
- Reinstall prerequisites
- Verify job configuration

**Scenario 2: Certificate Loss**
- RTO: 2 hours, RPO: 0
- Restore from backup or regenerate certificate
- Redeploy to all targets

**Scenario 3: AWS Account Compromise**
- RTO: 1 hour
- Disable compromised credentials
- Create new IAM user
- Update Jenkins credentials
- Rotate all secrets

---

## 🧑‍💻 Author
*Md. Sarowar Alam*  
Lead DevOps Engineer, Hogarth Worldwide  
📧 Email: sarowar@hotmail.com  
🔗 LinkedIn: https://www.linkedin.com/in/sarowar/

---

## Appendix

### Quick Reference

**Certificate Locations**:
- Windows: `%LOCALAPPDATA%\Posh-ACME\LE_PROD`
- Backups: `C:\backup-certificates\`
- S3: `s3://company-a-logs/certificates/`

**Key Commands**:
```powershell
# Check certificate validity
.\ssl.ps1 -Domain "example.com"

# Force renewal
.\backup-create-cert.ps1 -Domain "*.example.com" -AccessKey $key -SecretKey $secret -PfxPass $pass

# Test WinRM
Test-WSMan -ComputerName 10.0.1.10 -UseSSL

# Test SSH
ssh -i C:\KEYS\aws-region-1.pem rocky@10.0.1.30 "echo OK"
```

### Reference Links

- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Posh-ACME GitHub](https://github.com/rmbolger/Posh-ACME)
- [AWS ACM Documentation](https://docs.aws.amazon.com/acm/)
- [Jenkins Pipeline Syntax](https://www.jenkins.io/doc/book/pipeline/syntax/)
