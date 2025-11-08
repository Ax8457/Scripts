if ($args.Count -eq 0) {
    Write-Host "[!] Usage :  $($MyInvocation.MyCommand.Name) <CSV_FILE> "
    exit 1
}
$c1 = 0
$c2 = 0
$ind = 1
$f =  $args[0]
Write-Host "[***] Extracting IDs from $f ..."
$csv = Import-Csv -Path $f
#Extract IDs
$column = "Policy Definition ID"
$policyIds = @()
$builtInPolicies = @()
$staticPolicies = @()
foreach ($ligne in $csv) {
    if ($ligne.$column -match '\/providers\/Microsoft.Authorization\/policyDefinitions\/([a-f0-9\-]{36})') {
        $id_policy = $matches[1]
		$policyIds += $id_policy
    }
}
$size = $policyIds.Count
Write-Host "[+] $size IDs extracted"

#Connect Tenant and Retreived Token
Write-Host "[***] Fetching Azure Tenant, requesting access token ..."
Connect-AzAccount
$token = (Get-AzAccessToken).Token
if ([string]::IsNullOrEmpty($token)) {
    Write-Host "[x] Fail to retreive token."
    exit 1
} else {
    Write-Host "[+] Azure Access Token retreived."
    $headers = @{
        "Authorization" = "Bearer $token"
    }
	Write-Host "[***] Determining Policies Type.... "
	Write-Host "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	Write-Host "`n`n`n"
	Write-Host "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	#Start-Sleep 100
	[System.Console]::SetCursorPosition(0, [System.Console]::CursorTop - 5)
	foreach ($i in $policyIds) {
		$uri = "https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions/" + $i + "?api-version=<version>"
		$response = Invoke-WebRequest -Uri $uri -Headers $headers
		$jsonContent = $response.Content | ConvertFrom-Json

		if ($jsonContent.properties.policyType -eq "Static") {
			$policyType = "[!] Policy is  Static		"
			$staticPolicies += [PSCustomObject]@{
				PolicyID = $i
				PolicyType = "Static"
			}
			$c2 += 1
			
		} elseif ($jsonContent.properties.policyType -eq "BuiltIn") {
			$policyType = "[+] Policy is BuiltIn		"
			$c1 += 1
			$builtInPolicies += [PSCustomObject]@{
				PolicyID = $i
				PolicyType = "Static"
			}
		} else {
			$policyType = "Unknown policy type"
		}

		Write-Host "`r`t[+] Policy ID: $i" 
		Write-Host "`r`t[***] Requesting uri: $uri" 
		Write-Host "`r`t$policyType"
		Write-Host "`r`t[+] ID number : $ind"
		[System.Console]::SetCursorPosition(0, [System.Console]::CursorTop - 4)
		$ind +=1
		
    #Start-Sleep -Milliseconds 500
	}
	[System.Console]::SetCursorPosition(0, [System.Console]::CursorTop + 5)
	Write-Host "RESULTS :"
	$results = @(
		[PSCustomObject]@{ BuiltIn_Policies = $c1 ; Static_Policies = $c2 }
	)
	$results | Format-Table -AutoSize
	$builtInPolicies | Export-Csv -Path "BuiltIn_Policies.csv" -NoTypeInformation
	$staticPolicies | Export-Csv -Path "Static_Policies.csv" -NoTypeInformation
	$results2 = @(
		[PSCustomObject]@{ BuiltIn_Policies = "Builtin_Policies.csv" ; Static_Policies = "Static_Policies.csv" }
	)
	$results2 | Format-Table -AutoSize
	Write-Host "[+] Files saved."
}   
