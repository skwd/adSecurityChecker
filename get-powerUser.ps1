#Affiche le nombre d'admin du domain et Enterprise Admins 
import-module activedirectory
Function Get-PowerUser {
	$PowerUser = New-Object PSObject
	$userDomainAdmin = Get-ADGroupMember "Admins du domaine"
	$userEnterpriseAdmin = Get-ADGroupMember "Enterprise Admins"
	
	$PowerUser | Add-Member NoteProperty DomainAdmins $userDomainAdmin.count
	$PowerUser | Add-Member NoteProperty EnterpriseAdmins $userEnterpriseAdmin.count
	
	return $PowerUser
}
Function Get-PowerUserSecurity{
	$PoserUser = Get-PowerUser
	if ($PoserUser.DomainAdmins -lt 6){
		Write-host "[+] Less than 6 domain admin: Good Job" -f green
	}else {Write-host "[-] you have more than 5 domain admins you should reduce" -b red}
	
	if ($PoserUser.EnterpriseAdmins -lt 6){
		Write-host "[+] Less than 6 Enterprise Admin: Good Job" -f green
	}else {Write-host "[-] you have more than 5 Enterprise Admin you should reduce" -b red}
}
#affiche la politique de mot de passe de l'AD 
Function Get-PasswordPolicy{
	$PasswordPolicyInfo = New-Object PSObject
	$RootDSE = Get-ADRootDSE
	$AccountPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property lockoutDuration, lockoutObservationWindow, lockoutThreshold
	$PasswordPolicyInfo | Add-Member NoteProperty Domain $AccountPolicy.DistinguishedName
	
	$lockoutDuration = ($AccountPolicy.lockoutDuration / -600000000) 
	$lockoutObservationWindow = ($AccountPolicy.lockoutObservationWindow / -600000000) 
	$lockoutThreshold = $AccountPolicy.lockoutThreshold
	
	$PasswordPolicyInfo | Add-Member NoteProperty lockoutDuration $lockoutDuration
	$PasswordPolicyInfo | Add-Member NoteProperty lockoutObservationWindow $lockoutObservationWindow
	$PasswordPolicyInfo | Add-Member NoteProperty lockoutThreshold $lockoutThreshold
	
	
	
	$PasswordPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property minPwdAge, maxPwdAge, minPwdLength, pwdHistoryLength, pwdProperties 
	
	$minPwdAge = ($PasswordPolicy.minPwdAge / -864000000000)
	$maxPwdAge = ($PasswordPolicy.maxPwdAge / -864000000000)
	$minPwdLength = $PasswordPolicy.minPwdLength
	$pwdHistoryLength = $PasswordPolicy.pwdHistoryLength
	$pwdProperties = Switch ($PasswordPolicy.pwdProperties) {
					  0 {"Passwords can be simple and the administrator account cannot be locked out"}
					  1 {"Passwords must be complex and the administrator account cannot be locked out"}
					  8 {"Passwords can be simple, and the administrator account can be locked out"}
					  9 {"Passwords must be complex, and the administrator account can be locked out"}
					  Default {$PasswordPolicy.pwdProperties}}
					  
	$PasswordPolicyInfo | Add-Member NoteProperty minPwdAge $minPwdAge
	$PasswordPolicyInfo | Add-Member NoteProperty maxPwdAge $maxPwdAge
	$PasswordPolicyInfo | Add-Member NoteProperty minPwdLength $minPwdLength
	$PasswordPolicyInfo | Add-Member NoteProperty pwdHistoryLength $pwdHistoryLength
	$PasswordPolicyInfo | Add-Member NoteProperty pwdProperties $pwdProperties
	
	
	return $PasswordPolicyInfo
	
}
# analyse les informations de la politique de mot de passe et affiche le résultat
Function Get-PasswordPolicySecurity{
	$PassowrdPolicy = Get-PasswordPolicy
	Write-host "[*] password Policy for : " $PassowrdPolicy.Domain " " -BackgroundColor blue
	Write-host " lockoutDuration          :"$PassowrdPolicy.lockoutDuration" Minutes"
	Write-host " lockoutObservationWindow :"$PassowrdPolicy.lockoutObservationWindow" Minutes"
	if ($PassowrdPolicy.lockoutThreshold -gt 6){
		Write-host " lockoutThreshold         :"$PassowrdPolicy.lockoutThreshold" tentatives. Should not be greater than 6" -b red
	}else{Write-host " lockoutThreshold         :"$PassowrdPolicy.lockoutThreshold" tentatives" }
	Write-host " minPwdAge                :"$PassowrdPolicy.minPwdAge" days"
	if ($PassowrdPolicy.maxPwdAge -gt 90){
		Write-host " maxPwdAge                :"$PassowrdPolicy.maxPwdAge" days. should not be greater thant 90 days" -b red
	}else{Write-host " maxPwdAge                :"$PassowrdPolicy.maxPwdAge" days"}
	if ($PassowrdPolicy.minPwdLength -lt 8){
		Write-host " minPwdLength             :"$PassowrdPolicy.minPwdLength "sould be greater thant 7" -b red
	}else{Write-host " minPwdLength             :"$PassowrdPolicy.minPwdLength}
	Write-host " pwdHistoryLength         :"$PassowrdPolicy.pwdHistoryLength
	Write-host " pwdProperties            :"$PassowrdPolicy.pwdProperties
	
}
#retourne les utilisateur expirer et activé
Function Get-ExpiredAndActiveUser{
	return Search-ADAccount -AccountExpired -UsersOnly | ?{$_.Enabled -eq "True"}
}
#retourne les utilisateurs du domain inactif depuis 90 jours et activé
Function Get-InactifUser90{
	return Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | ?{$_.Enabled -eq "True"}
}
# trouve les GPO avec un password et retourne un custom object avec l'utilisateur et l'emplacement du group.xml
Function Get-BadGPP{
	$domain = (Get-ADDomain).Forest
	$gpoPath = Get-ChildItem -Path \\$domain\SYSVOL\$domain\ -Filter groups.xml -Recurse -ErrorAction silentlycontinue
	$gpoAll = @()
	if($gpoPath){
		foreach ( $path in $gpoPath){ 
			$file = Get-Content $path.FullName -Encoding UTF8
			$containsWord = [string]$file -match 'cpassword.*userName="([a-zA-ZéèÉÈ`(`) ]+)"'
			If($containsWord)
			{
				$username = $Matches[1]
				$obj = New-Object PSObject
				$obj | Add-Member NoteProperty Username $username
				$obj | Add-Member NoteProperty path $path.FullName
				$gpoAll += $obj
			}
		}
	}
	return $gpoAll
}
#analyse la securité des GPP
Function Get-GPPSecurity{
	$badGPP = Get-BadGPP
	if($badGPP){
		Write-Host "[-]" $badGPP.count "Bad GPP found!" -b red
	
	}
	else{
		Write-host "[+]Aucune GPP : Good Job !" -f green
	}
}
Function Get-ChangePasswordUser{
	return Get-ADUser -Filter {pwdLastSet -eq 0 -and Enabled -eq $true} -Properties Created,lastlogondate
}
Function Get-ADSecurity{
	Get-GPPSecurity
	Get-PasswordPolicySecurity
	Get-PowerUserSecurity
}
