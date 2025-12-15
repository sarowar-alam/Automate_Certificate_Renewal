param (
    [string]$Domain    = $null,
    [string]$AccessKey = $null,
    [string]$SecretKey = $null,
    [string]$PfxPass   = $null
)

# --- Validate inputs ---
if (-not $Domain -or -not $AccessKey -or -not $SecretKey -or -not $PfxPass) {
    Write-Host "[ERROR] One or more required parameters are missing."
    exit 1
}

try {
    # --- Backup certificate folder if exists ---
    Write-Host "[Starting Backup Existing certificate Folder]"
    $escapedDomain = $Domain -replace '\*', '!'
    $certPathGlob  = "$env:LOCALAPPDATA\Posh-ACME\LE_PROD\*\$escapedDomain"
    $existingPath  = Get-Item -Path $certPathGlob -ErrorAction SilentlyContinue

    if ($existingPath) {
        $backupDir = "C:\backup-certificates"
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $zipFile = Join-Path $backupDir "$($escapedDomain)_$timestamp.zip"
        Compress-Archive -Path $existingPath.FullName -DestinationPath $zipFile -Force
        Write-Host "Backup created: $zipFile"

        # --- Delete contents of the existingPath ---
        Write-Host "[Deleting contents of $($existingPath.FullName)]"
        Get-ChildItem -Path $existingPath.FullName -Recurse -Force | Remove-Item -Recurse -Force
    } else {
        Write-Host "No existing cert folder to back up. Skipping backup."
    }

    # --- Set AWS credentials ---
    Write-Host "[Setting AWS credentials]"
    Set-AWSCredential -AccessKey $AccessKey -SecretKey $SecretKey -StoreAs 'poshacme'

    # --- Prepare PluginArgs ---
    # $pluginArgs = @{R53ProfileName='poshacme'}

    # --- Execute New-PACertificate ---
    Write-Host "[Executing New-PACertificate]"
    $certResult = $null

    try {

        $certResult = New-PACertificate $Domain -AcceptTOS -PfxPass "$PfxPass" -Plugin Route53 -PluginArgs @{R53ProfileName='poshacme'} -Force -ErrorAction Stop
        # --- DEBUG OUTPUT START ---
        Write-Host "`n[DEBUG] Dumping certResult:"
        if ($certResult) {
            $certResult | Format-List *
            Write-Host "`n[DEBUG] Individual Checks:"
            Write-Host "PfxFile        : $($certResult.PfxFile)"
            Write-Host "PfxFileExists  : $(Test-Path $certResult.PfxFile)"
            Write-Host "Thumbprint     : $($certResult.Thumbprint)"
            Write-Host "UsedExisting   : $($certResult.UsedExistingOrder)"
        } else {
            Write-Host "[DEBUG] certResult is `$null"
        }
        # --- DEBUG OUTPUT END ---

        # --- Updated Logic ---
        if ($certResult -and $certResult.PfxFile -and (Test-Path $certResult.PfxFile)) {
            Write-Host "[INFO] Certificate successfully issued."
            Write-Host "[RESULT] NEW_CERT"
            Write-Host "PFX Path    : $($certResult.PfxFile)"
            Write-Host "Thumbprint  : $($certResult.Thumbprint)"
            
            # --- ADDITIONAL ACTIONS START ---
            $certDir = Split-Path $certResult.ChainFile
            $caCertPath = Join-Path $certDir "CAcert.crt"
            Copy-Item -Path $certResult.ChainFile -Destination $caCertPath -Force


            $sanitizedDomain = $Domain -replace '[^a-zA-Z0-9]', '_'
            $sanitizedDomain = $sanitizedDomain -replace '_+', '_'            
            # $keyDir = Split-Path $certResult.KeyFile
            # $pvkPath = Join-Path $keyDir "${sanitizedDomain}_pvk.pem"
            # $privatePath = Join-Path $keyDir "${sanitizedDomain}_private.pem"

            # openssl rsa -in $certResult.KeyFile -text -noout > $pvkPath
            # openssl rsa -in $certResult.KeyFile -out $privatePath
            # --- ADDITIONAL ACTIONS END ---


            exit 0
        } else {
            Write-Host "[WARNING] Certificate creation returned unexpected result."
            exit 1
        }

    } catch {
        Write-Host "[ERROR]"
        $msg = $_.Exception.Message
        Write-Host "[$msg]"

        if ($msg -match "too many certificates .* issued for this exact set of identifiers") {
            Write-Host "Rate limit exceeded for domain $Domain. Try again later."
        }
        elseif ($msg -match "Unable to find Route53 hosted zone") {
            $sanitizedDomain = $Domain -replace '[^a-zA-Z0-9]', '_'
            $sanitizedDomain = $sanitizedDomain -replace '_+', '_' 
            Write-Host "Hosted zone not found for domain $Domain. Please check Route53 setup. | $sanitizedDomain"
        }
        exit 1
    }

} finally {
    # --- Final Cleanup ---
    Write-Host "[Final cleanup]"
    $credFile = "$env:USERPROFILE\.aws\credentials"
    if (Test-Path $credFile) {
        $lines = Get-Content $credFile
        $filteredLines = @()
        $insideProfile = $false

        foreach ($line in $lines) {
            if ($line -match "^\[poshacme\]") {
                $insideProfile = $true
                continue
            }
            if ($insideProfile -and $line -match "^\[") {
                $insideProfile = $false
            }

            if (-not $insideProfile) {
                $filteredLines += $line
            }
        }

        $filteredLines | Set-Content $credFile
        Write-Host "AWS profile 'poshacme' removed."
    }
}
