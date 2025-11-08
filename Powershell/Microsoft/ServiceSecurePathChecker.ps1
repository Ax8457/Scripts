Write-Output "==========================================================="
Write-Output "=============== Service Secure Path Checker ==============="
Write-Output "==========================================================="
Write-Output " "

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$securePath = @("C:\Windows","C:\Program Files","C:\Program Files (x86)","C:\ProgramData","c:\Windows","c:\Program Files","c:\Program Files (x86)","c:\ProgramData")
$services = Get-WmiObject -Class Win32_Service
$serviceStatus = @{}
$serviceFullPath = @{}
$isSecure = $false 
$AllSecure = $true
$Env = $false

function Check-ServicePath{
	foreach ($service in $services) {
		$fullPath = $service.PathName.Trim('"')
		if ($Env) {$fullPath = $ExecutionContext.InvokeCommand.ExpandString($fullPath)}
		$serviceFullPath[$service.Name] = $fullPath
		for($i = 0; $i -lt $securePath.Length; $i++){
			if ($fullPath.StartsWith($securePath[$i])){
				$isSecure = $true
				break
			}else {$isSecure = $false}
		}
		$serviceStatus[$service.Name] = $isSecure	
	}
}

function Print-Result{
	foreach($key in $serviceStatus.Keys){
		if (-not $serviceStatus[$key]){
			Write-Host "[x] Path of Service '$key' isn't secure"
			$resolvedPath = $serviceFullPath[$key]
			Write-Host "Path : $resolvedPath"
			Write-Host "----------------------------------------------------------------------------------------------------------------------"
			$AllSecure = $false	
		}
	}
	if ($AllSecure){Write-Host "All service Paths are secure."}
}

if ( -not $args[0]){
	$Env = $false
	Check-ServicePath
	Print-Result
}
if ($args[0] -eq "-Env"){ 
	$Env = $true
	Check-ServicePath
	Print-Result
 }

if ($args[0] -eq "-h" ){
	Write-Host "Usage : $($MyInvocation.MyCommand.Name) -h : for help."
	Write-Host "Usage : $($MyInvocation.MyCommand.Name) -T : for printing HashTables with status 'true' or 'false' for each service found on the host and full path too."
	Write-Host "Usage : $($MyInvocation.MyCommand.Name) : for using the script to check services found on the host."
	Write-Host "Usage : $($MyInvocation.MyCommand.Name) (-T) -V : for interpreting 'env:<Name>' variables in Paths."
}

if ($args[0] -eq "-T" ){
	if ($args[1] -eq "-Env"){ $Env = $true }
	Check-ServicePath
	Write-Host "----------------------------------------------------------------------------------------------------------------------"
	Write-Host "	HashTable with Service status : {<Service Name>, <IsSecure boolean>}"
	Write-Host "----------------------------------------------------------------------------------------------------------------------"
	$serviceStatus
	Write-Host "----------------------------------------------------------------------------------------------------------------------"
	Write-Host " "
	Write-Host "----------------------------------------------------------------------------------------------------------------------"
	Write-Host "	HashTable with Service full path : {<Service Name>, <Full path>}"
	Write-Host "----------------------------------------------------------------------------------------------------------------------"
	Write-Host " "
	Write-Host "Name                           Value"
	Write-Host "----                           -----"
	$serviceFullPath
	Write-Host "----------------------------------------------------------------------------------------------------------------------"
}

if ($args.Length -gt 2){
	Write-Host "Usage : $($MyInvocation.MyCommand.Name) -h for help"
}
