cd $env:APPDATA

# Clean up local certificate for sample-authorizationservice docker containerized application.
$efasLocalCertKeyPath = "ASP.NET\Https\sample-authorizationservice-https-local.pfx"
Get-ChildItem $efasLocalCertKeyPath | Remove-Item

# Clean up remote certificate for sample-authorizationservice docker containerized application.
$efasCertKeyPath = "ASP.NET\Https\sample-authorizationservice-https-remote.pfx"
Get-ChildItem $efasCertKeyPath | Remove-Item

# Clean up certificates from the local machine certificate store
Get-ChildItem -Path Cert:\LocalMachine -Recurse | Where-Object {$_.FriendlyName -eq "Sample Docker Compose HTTPS local development certificate"} | Remove-Item
Get-ChildItem -Path Cert:\LocalMachine -Recurse | Where-Object {$_.Subject -like "*sample-authorizationservice*"} | Remove-Item

# Wait for the user to press a key and continues with the script execution.
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")
