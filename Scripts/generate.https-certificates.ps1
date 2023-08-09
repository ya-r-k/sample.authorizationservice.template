cd $env:APPDATA

# Variable for certificates password.
$password = ConvertTo-SecureString 'JF(E@&$g78367GF7dtt23^@7eGydet^Ey7etd75eTQ5t' -AsPlainText -Force

# Generate local certificates for sample-health-api and sample-authorizationservice docker containerized applications.
$localCert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My" -FriendlyName "Sample Docker Compose HTTPS local development certificate"

$efasLocalCertKeyPath = "ASP.NET\Https\sample-authorizationservice-https-local.pfx"
$localCert | Export-PfxCertificate -FilePath $efasLocalCertKeyPath -Password $password
$efasLocalRootCert = $(Import-PfxCertificate -FilePath $efasLocalCertKeyPath -CertStoreLocation 'Cert:\LocalMachine\Root' -Password $password)

# Generate remote certificate for sample-authorizationservice docker containerized application.
$efasCert = New-SelfSignedCertificate -DnsName "sample-authorizationservice" -CertStoreLocation "cert:\LocalMachine\My" -FriendlyName "Sample Authorization Service Docker Compose HTTPS remote development certificate"
$efasCertKeyPath = "ASP.NET\Https\sample-authorizationservice-https-remote.pfx"
$efasCert | Export-PfxCertificate -FilePath $efasCertKeyPath -Password $password
$efasRootCert = $(Import-PfxCertificate -FilePath $efasCertKeyPath -CertStoreLocation 'Cert:\LocalMachine\Root' -Password $password)

# Wait for the user to press a key and continues with the script execution.
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")
