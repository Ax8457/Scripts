if ($args.Count -eq 0) {
    Write-Output "[!] Usage :  $($MyInvocation.MyCommand.Name) <policy ID> "
    exit 1
}

Connect-AzAccount
$token = (Get-AzAccessToken).Token
if ([string]::IsNullOrEmpty($token)) {
    Write-Output "[x] Fail to retreive token."
    exit 1
} else {
    Write-Output "------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    Write-Output "[+] Azure Access Token retreived."
    $headers = @{
        "Authorization" = "Bearer $token"
    }
    $policyID = $args[0]
    Write-Output "[+] Policy ID: $policyID"
    $uri = "https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions/" + $policyID + "?api-version=<version>"
    Write-Output "[***] Requesting uri: $uri"
    $response = Invoke-WebRequest -Uri $uri -Headers $headers
    Write-Output "[+] Reply received : "
    Write-Output "------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    $jsonContent = $response.Content | ConvertFrom-Json
    $jsonContent | ConvertTo-Json -Depth 100
    Write-Output "------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
}
