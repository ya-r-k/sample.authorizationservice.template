cd $env:APPDATA

# Get the certificate and View the certificate content
Write-Host "Sample Authorization Service HTTPS local development certificate:"

$efasLocalCertKeyPath = "AppData\Roaming\ASP.NET\Https\sample-authorizationservice-https-local.pfx"
$efasLocalCert = Get-ChildItem -Path $efasLocalCertKeyPath | Format-List *

# Get the certificate and View the certificate content
Write-Host "Sample Authorization Service HTTPS remote development certificate:"

$efasCertKeyPath = "AppData\Roaming\ASP.NET\Https\sample-authorizationservice-https-remote.pfx"
$efasCert = Get-ChildItem -Path $efhaCertKeyPath | Format-List *

# Wait for the user to press a key and continues with the script execution.
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")
