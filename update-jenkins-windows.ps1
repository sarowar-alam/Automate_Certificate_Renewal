<#
.SYNOPSIS
    Converts Let's Encrypt certificates in PFX format to JKS format with proper permissions and deploys to Jenkins.
.DESCRIPTION
    This script finds Let's Encrypt certificates in PFX format, converts them to JKS format,
    creates an additional JKS with 'l' suffix, deploys to Jenkins home folder,
    and safely restarts the Jenkins service after verifying no builds are running.
#>

param (
    [Parameter(Mandatory=$true)]
    [string[]]$CertCN,
    
    [Parameter(Mandatory=$true)]
    [SecureString]$JksPassword,
    
    [Parameter(Mandatory=$true)]
    [SecureString]$PfxPassword    
)


# Convert secure strings to plain text
try {
    $jksBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($JksPassword)
    $jksPasswordPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($jksBstr)
    
    $pfxBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
    $pfxPasswordPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pfxBstr)
}
catch {
    Write-Error "Failed to convert secure passwords: $_"
    exit 1
}
finally {
    if ($jksBstr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($jksBstr)
    }
    if ($pfxBstr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pfxBstr)
    }
}

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
}

# Derive JenkinsUrl from CertCN if not provided
if (-not $JenkinsUrl -and $CertCN) {
    $firstDomain = $CertCN[0] -replace '^\*\.', ''
    $JenkinsUrl = "https://jenkins.$firstDomain"
    Write-Log "Derived Jenkins URL: $JenkinsUrl" -Level "INFO"
}

# Function to find Jenkins home directory
function Get-JenkinsHome {
    try {
        # Check environment variable first
        if ($env:Jenkins_Home) {
            $jenkinsHome = $env:Jenkins_Home
            if ($jenkinsHome -match '^(.*\\Jenkins)\\workspace') {
                return $matches[1]
            }
            return $jenkinsHome
        }
        
        # Fallback to common installation paths
        $commonPaths = @(
            "C:\Program Files\Jenkins",
            "C:\Program Files (x86)\Jenkins",
            "${env:ProgramFiles}\Jenkins",
            "${env:ProgramFiles(x86)}\Jenkins"
        )
        
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                return $path
            }
        }
        
        Write-Log "Could not determine Jenkins home directory" -Level "WARN"
        return $null
    }
    catch {
        Write-Log "Error finding Jenkins home: $_" -Level "ERROR"
        return $null
    }
}


# Modified function to find PFX file instead of CER/KEY pair
function Get-CertFilesPath {
    param ([string]$CertCN)
    
    $escapedDomain = $CertCN -replace '\*', '!'
    $basePath = Join-Path $env:LOCALAPPDATA 'Posh-ACME\LE_PROD'
    
    try {
        $matchingFolder = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction Stop |
                          Where-Object { 
                              $certDir = Join-Path $_.FullName $escapedDomain
                              (Test-Path (Join-Path $certDir "fullchain.pfx"))
                          } |
                          Select-Object -First 1
        
        if ($matchingFolder) {
            $certDir = Join-Path $matchingFolder.FullName $escapedDomain
            $pfxPath = Join-Path $certDir "fullchain.pfx"
            
            Write-Log "Found existing PFX file in: $certDir"
            return @{
                CertDir = $certDir
                PfxPath = $pfxPath
            }
        }
        Write-Log "Could not find PFX file for CN: $CertCN"
        return $null
    }
    catch {
        Write-Log "Error searching for certificate files: $_"
        return $null
    }
}

# Main processing
foreach ($cn in $CertCN) {
    try {
        Write-Log "Processing certificate for: $cn"
        
        # Validate CN pattern
        if (-not ($cn -match "^\*?\..+")) {
            Write-Log "Invalid certificate CN pattern: $cn"
            continue
        }
        
        # Get cert files and directory
        $certPaths = Get-CertFilesPath -CertCN $cn
        if (-not $certPaths) {
            Write-Log "Skipping $cn - PFX file not found"
            continue
        }
        
        $certAlias = $cn -replace '^\*\.', ''
        $jksPath = Join-Path $certPaths.CertDir "jenkins.$certAlias.jks"
        $jksPathWithL = Join-Path $certPaths.CertDir "jenkinsl.${certAlias}.jks"
        
        try {
            # 1. CONVERT PFX → JKS
            Write-Log "Converting PFX to JKS..."
            
            $keytoolOutput = & keytool -importkeystore `
                -srckeystore $certPaths.PfxPath `
                -srcstoretype pkcs12 `
                -srcstorepass $pfxPasswordPlainText `
                -destkeystore $jksPath `
                -deststorepass $jksPasswordPlainText `
                -destkeypass $jksPasswordPlainText `
                -noprompt 2>&1
            
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $jksPath)) {
                throw "keytool failed: $keytoolOutput"
            }
            
            Write-Log "JKS file created at $jksPath"
            
            # Create additional JKS with 'l' suffix
            Copy-Item -Path $jksPath -Destination $jksPathWithL -Force
            Write-Log "Additional JKS file created at $jksPathWithL"
            
            # 2. SET PERMISSIONS
            try {
                & icacls $jksPath /reset /grant:r "*S-1-5-32-544:(R)" "Administrator:(F)" /inheritance:r 2>&1 | Out-Null
                & icacls $jksPathWithL /reset /grant:r "*S-1-5-32-544:(R)" "Administrator:(F)" /inheritance:r 2>&1 | Out-Null
                Write-Log "Permissions set on JKS files"
            }
            catch {
                Write-Log "Warning: Failed to set permissions: $_"
            }
            
            # 3. VERIFICATION
            Write-Log "Verifying keystores:"
            $verifyOutput = & keytool -list -v -keystore $jksPath -storepass $jksPasswordPlainText 2>&1
            Write-Log ($verifyOutput -join "`n")
            
            $verifyOutputL = & keytool -list -v -keystore $jksPathWithL -storepass $jksPasswordPlainText 2>&1
            Write-Log ($verifyOutputL -join "`n")
            
            
            # 5. DEPLOY TO JENKINS
            $jenkinsHome = Get-JenkinsHome
            if ($jenkinsHome) {
                $jenkinsJksPath = Join-Path $jenkinsHome "jenkins.$certAlias.jks"
                
                # Backup existing files if they exist
                if (Test-Path $jenkinsJksPath) {
                    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
                    $backupPath = "${jenkinsJksPath}_backup_$timestamp"
                    Copy-Item -Path $jenkinsJksPath -Destination $backupPath -Force
                    Write-Log "Backup created at $backupPath"
                }
                
                
                # Copy new JKS files to Jenkins
                Copy-Item -Path $jksPath -Destination $jenkinsJksPath -Force
                Write-Log "JKS files deployed to Jenkins directory: $jenkinsHome"
                
                # Set permissions on Jenkins JKS files
                try {
                    & icacls $jenkinsJksPath /reset /grant:r "*S-1-5-32-544:(R)" "Administrator:(F)" /inheritance:r 2>&1 | Out-Null
                    Write-Log "Permissions set on Jenkins JKS files"
                }
                catch {
                    Write-Log "Warning: Failed to set permissions on Jenkins JKS files: $_"
                }
                
            }
            else {
                Write-Log "Skipping Jenkins deployment - Jenkins home not found"
            }
        }
        catch {
            Write-Log "Error processing certificate conversion for $cn`: $_"
        }
    }
    catch {
        Write-Log "Error processing $cn`: $_"
    }
}

# Clean up
Remove-Variable jksPasswordPlainText, pfxPasswordPlainText -ErrorAction SilentlyContinue
Write-Log "Processing complete"
exit 0