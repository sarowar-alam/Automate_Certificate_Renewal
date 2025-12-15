<#
.SYNOPSIS
    Updates IIS SSL certificates and manages old certificate cleanup
.DESCRIPTION
    This script now properly transfers all required functions to the remote session
    to avoid "not recognized" errors during execution.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$RemoteIP,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$Password,
    
    [Parameter(Mandatory=$true)]
    [string]$CertCN,
    
    [Parameter(Mandatory=$true)]
    [string]$PfxPassword,
    
    [switch]$ConfirmDeletion = $false,
    
    [switch]$DebugOutput = $false
)

#region Helper Functions
function Write-Log {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] $Message" -ForegroundColor Cyan
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] $Message" -ForegroundColor Red
}

function Get-CertPfxPath {
    param ([string]$CertCN)
    $escapedDomain = $CertCN -replace '\*', '!'
    $basePath = Join-Path $env:LOCALAPPDATA 'Posh-ACME\LE_PROD'
    $matchingFolder = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction SilentlyContinue |
                      Where-Object { Test-Path (Join-Path $_.FullName $escapedDomain) } |
                      Select-Object -First 1
    if ($matchingFolder) {
        $pfxPath = Join-Path $matchingFolder.FullName "$escapedDomain\cert.pfx"
        if (Test-Path $pfxPath) {
            Write-Log "Found cert.pfx at: $pfxPath"
            return $pfxPath
        }
    }
    Write-ErrorLog "Could not find PFX for CN: $CertCN"
    return $null
}

# Define the remote script block with all required functions
$remoteScriptBlock = {
    param($CertCN, $PfxPassword, $ConfirmDeletion, $DebugOutput)

    function Write-RemoteLog {
        param([string]$Message)
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [REMOTE] $Message" -ForegroundColor Green
    }

    function Get-CertificateUsage {
        param($thumbprint)
        $usage = @{
            IISBindings = @()
            OtherUsage = $false
        }
        
        # Check IIS bindings
        Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
        if (Get-Command Get-WebBinding -ErrorAction SilentlyContinue) {
            $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
            foreach ($site in $sites) {
                $bindings = Get-WebBinding -Name $site.Name -ErrorAction SilentlyContinue | 
                           Where-Object { $_.protocol -eq "https" -and ($_.CertificateHash -join "") -eq $thumbprint }
                foreach ($binding in $bindings) {
                    $usage.IISBindings += @{
                        Site = $site.Name
                        Binding = $binding.bindingInformation
                    }
                }
            }
        }
        
        # Check RDP certificate
        try {
            $rdpCertThumb = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SSLCertificateSHA1Hash' -ErrorAction SilentlyContinue).SSLCertificateSHA1Hash
            if ($rdpCertThumb -and ($rdpCertThumb -replace '\s','') -eq $thumbprint) {
                $usage.OtherUsage = $true
            }
        } catch {}
        
        return $usage
    }

    function Get-CertsBySubjectPattern {
        param($pattern)
        $certs = @()
        $certStore = Get-ChildItem "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
        $regexPattern = "^" + [regex]::Escape($pattern) + "$"
        $regexPattern = $regexPattern -replace '\\\*', '.*'
        
        foreach ($cert in $certStore) {
            $subjectCN = if ($cert.Subject -match "CN=([^,]+)") { $matches[1] } else { $cert.Subject }
            if ($subjectCN -match $regexPattern -or $subjectCN -eq $pattern) {
                $certs += $cert
            }
        }
        return $certs | Sort-Object NotAfter -Descending
    }

    function Show-CertificateBindings {
        param($label)
        Write-Host "`n--- $label Certificate Bindings ---"
        Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
        if (Get-Command Get-WebBinding -ErrorAction SilentlyContinue) {
            $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
            foreach ($site in $sites) {
                $bindings = Get-WebBinding -Name $site.Name -ErrorAction SilentlyContinue | Where-Object { $_.protocol -eq "https" }
                foreach ($binding in $bindings) {
                    $thumbprint = $binding.CertificateHash -join ""
                    $cert = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
                    $subject = if ($cert) { $cert.Subject } else { "Unknown" }
                    Write-Host "Site: $($site.Name) | Binding: $($binding.bindingInformation) | Thumbprint: $thumbprint | Subject: $subject"
                }
            }
        }
        Write-Host "--- End of $label Bindings ---`n"
    }

    try {
        # Import new certificate
        $pfxPath = "C:\Temp\newcert.pfx"
        $certPass = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
        $newCert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password $certPass -Exportable -ErrorAction Stop
        $newThumb = $newCert.Thumbprint
        Write-RemoteLog "Imported new certificate: $newThumb"

        # Get all matching certificates
        $allCerts = Get-CertsBySubjectPattern -pattern $CertCN
        Write-RemoteLog "Found $($allCerts.Count) certificates matching CN: $CertCN"

        # Update IIS bindings
        Show-CertificateBindings "Before Update"
        $updatedSites = @()
        $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
        
        # Import WebAdministration module for IIS cmdlets
        Import-Module WebAdministration -ErrorAction Stop
        
        foreach ($site in $sites) {
            $bindings = Get-WebBinding -Name $site.Name -ErrorAction SilentlyContinue | Where-Object { $_.protocol -eq "https" }
            foreach ($binding in $bindings) {
                $currentThumb = $binding.CertificateHash -join ""
                if ($currentThumb -eq $newThumb) { continue }

                $ip, $port, $hostname = $binding.bindingInformation -split ":"
                if ($hostname -like $CertCN -or $hostname -eq ($CertCN -replace '^\*\.','')) {
                    try {
                        Write-RemoteLog "Processing binding: Site=$($site.Name), Host=$hostname, IP=$ip, Port=$port"
                        
                        # Remove the old binding
                        Remove-WebBinding -Name $site.Name -Protocol "https" -HostHeader $hostname -Port $port -IPAddress $ip -ErrorAction Stop
                        Write-RemoteLog "Removed old binding for $($site.Name)"
                        
                        # Create the new binding
                        $newBinding = New-WebBinding -Name $site.Name -Protocol "https" -HostHeader $hostname -Port $port -IPAddress $ip -SslFlags 0 -ErrorAction Stop
                        
                        # Check if binding was created successfully before calling methods on it
                        if ($null -eq $newBinding) {
                            Write-RemoteLog "Warning: New-WebBinding returned null for $($site.Name). Trying alternative approach."
                            # Alternative approach using the IIS provider
                            $bindingPath = "IIS:\Sites\$($site.Name)"
                            $newBinding = Get-WebBinding -Name $site.Name -Protocol "https" -HostHeader $hostname -Port $port -IPAddress $ip
                        }
                        
                        # Add SSL certificate to the binding
                        if ($null -ne $newBinding) {
                            $newBinding.AddSslCertificate($newThumb, "My")
                            $updatedSites += $site.Name
                            Write-RemoteLog "Updated binding for $($site.Name)"
                        } else {
                            Write-RemoteLog "Error: Could not create or find binding for $($site.Name)"
                        }
                    } catch {
                        Write-Host "[!] Failed to update $($site.Name): $_"
                    }
                }
            }
        }
        Show-CertificateBindings "After Update"

        # Certificate cleanup
        $certsToDelete = $allCerts | Where-Object { 
            $_.Thumbprint -ne $newThumb -and 
            (Get-CertificateUsage -thumbprint $_.Thumbprint).IISBindings.Count -eq 0 -and
            -not (Get-CertificateUsage -thumbprint $_.Thumbprint).OtherUsage
        }

        if ($certsToDelete.Count -gt 0) {
            Write-Host "`n=== CERTIFICATES TO DELETE ==="
            $certsToDelete | ForEach-Object { Write-Host "- $($_.Thumbprint)" }

            if ($ConfirmDeletion) {
                $deleted = @()
                foreach ($cert in $certsToDelete) {
                    try {
                        Remove-Item -Path $cert.PSPath -Force -ErrorAction Stop
                        $deleted += $cert.Thumbprint
                        Write-RemoteLog "Deleted certificate: $($cert.Thumbprint)"
                    } catch {
                        Write-Host "[!] Failed to delete $($cert.Thumbprint): $_"
                    }
                }
                Write-RemoteLog "Deleted $($deleted.Count) old certificates"
            } else {
                Write-RemoteLog "Use -ConfirmDeletion to remove $($certsToDelete.Count) old certificates"
            }
        } else {
            Write-RemoteLog "No old certificates to delete"
        }

    } catch {
        Write-Host "[REMOTE ERROR] $_"
        throw $_
    }
}

#region Main Script Execution
try {
    # Validate and initialize
    if (-not $RemoteIP -or -not $Username -or -not $Password -or -not $CertCN -or -not $PfxPassword) {
        Write-ErrorLog "Missing required parameters"
        exit 1
    }

    # Find local certificate
    Write-Log "Locating local PFX certificate for CN: $CertCN"
    $LocalPfxPath = Get-CertPfxPath -CertCN $CertCN
    if (-not $LocalPfxPath) { exit 1 }

    # Create remote session
    Write-Log "Connecting to remote server: $RemoteIP"
    $cred = New-Object System.Management.Automation.PSCredential ($Username, (ConvertTo-SecureString $Password -AsPlainText -Force))
    $session = New-PSSession -ComputerName $RemoteIP -Credential $cred -ErrorAction Stop

    # Prepare remote environment
    Invoke-Command -Session $session -ScriptBlock {
        if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
    }

    # Copy certificate
    Write-Log "Copying PFX to remote server..."
    Copy-Item -Path $LocalPfxPath -Destination "C:\Temp\newcert.pfx" -ToSession $session -Force -ErrorAction Stop

    # Execute remote operations
    Write-Log "Executing remote certificate update..."
    Invoke-Command -Session $session -ScriptBlock $remoteScriptBlock -ArgumentList $CertCN, $PfxPassword, $ConfirmDeletion, $DebugOutput -ErrorAction Stop

    Write-Log "Certificate update completed successfully"
} catch {
    Write-ErrorLog "Script failed: $_"
    exit 1
} finally {
    if ($session) {
        Remove-PSSession $session
        Write-Log "Remote session closed"
    }
    Write-Log "Script execution completed"
}