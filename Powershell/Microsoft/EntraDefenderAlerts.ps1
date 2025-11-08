Import-Module PSWriteColor

$tenantID = ''
$clientID = ''
$secret = ''
# In your tenant portal, you need to register an API and to generate a secret
# Make sure you have granted related permissions to your API (in 'API permissions')

$URL_base_API = 'https://api.securitycenter.windows.com'
$Auth_URL = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
$scope = "https://api.securitycenter.windows.com/.default"

$body = @{
    client_id     = $clientID
    scope         = $scope
    client_secret = $secret
    grant_type    = "client_credentials"
}

try {
    $authResponse = Invoke-RestMethod -Method Post -Uri $Auth_URL -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
    $token = $authResponse.access_token
    Write-Output "[+] Token received."
} catch {
    Write-Error "[x] Error : $_.Exception.Message"
    return
}

#last 48 hours
$dateTime = (Get-Date).ToUniversalTime().AddHours(-48).ToString("o")
$url = "$URL_base_API/api/alerts`?\$filter=lastUpdateTime+ge+$dateTime"
$headers = @{
    'Content-Type' = 'application/json'
    'Accept'       = 'application/json'
    'Authorization' = "Bearer $token"
}

try {
    $response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
    $alerts = ($response.Content | ConvertFrom-Json).value 
    foreach ($alert in $alerts) {
        Write-Output "------------------------------------------------------------------------------------------------------------------"
	switch ($alert.severity) {
            "high" { Write-Color "[+] Alert retreived => Severity : $($alert.severity)" -Color Red }
            "medium" { Write-Color "[+] Alert retreived => Severity : $($alert.severity)" -Color DarkYellow }
            "low" { Write-Color "[+] Alert retreived => Severity : $($alert.severity)" -Color Yellow }
            "informational" { Write-Color "[+] Alert retreived => Severity : $($alert.severity)" -Color Blue }
            default { Write-Color "[+] Alert retreived => Severity : $($alert.severity)" -Color White }
        }
	Write-Output "	Alert ID: $($alert.id)"
	Write-Output "	Alert status: $($alert.status)"
        Write-Output "	Alert Message: $($alert.title)"
	Write-Output "	Machine Name: $($alert.computerDnsName)"
        Write-Output "	User(s) Affected: "
	foreach ($user in $alert.loggedOnUsers) {
            Write-Output "    		Account Name: $($user.accountName)"
            Write-Output "    		Domain Name: $($user.domainName)"
        }
	Write-Output "	MITRE Techniques: $($alert.mitreTechniques)"
        Write-Output "	Alert Time: $($alert.lastUpdateTime)"
        Write-Output "------------------------------------------------------------------------------------------------------------------"
    }
     
} catch {
    Write-Error "[x] Error : $_.Exception.Message"
    Write-Error "Response : $($_.Exception.Response.StatusCode) $($_.Exception.Response.StatusDescription)"
}
