param (
    [string]$Domain
)

if ([string]::IsNullOrWhiteSpace($Domain)) {
    Write-Error "Domain parameter is required."
    exit 1
}

function Get-SSLExpiryDays {
    param ([string]$HostName)

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.SecurityProtocolType]::Tls12 -bor `
            [System.Net.SecurityProtocolType]::Tls13

        $request = [System.Net.HttpWebRequest]::Create("https://$HostName")
        $request.Method = "HEAD"
        $request.Timeout = 5000
        $request.AllowAutoRedirect = $false
        $request.GetResponse() | Out-Null

        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($request.RequestUri)
        $cert = $servicePoint.Certificate

        if (-not $cert) {
            Write-Host "[ERROR] No certificate received from $HostName"
            return 0
        }

        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert
        $expiryDate = $cert2.NotAfter

        $daysRemaining = ($expiryDate - (Get-Date)).Days

        if ($daysRemaining -lt 0) {
            return 0
        } else {
            return $daysRemaining
        }
    }
    catch {
        Write-Host "Failed to retrieve SSL certificate for $HostName"
        #Write-Host $_.Exception.Message
        return 0
    }
}

# Run the function
$result = Get-SSLExpiryDays -HostName $Domain
Write-Output $result
