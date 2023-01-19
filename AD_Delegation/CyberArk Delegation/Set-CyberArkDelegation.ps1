<#
.Synopsis
    Simple script provide delegation (exmaple) permissions for CyberArk.

.Description
    
.Notes:
    File Name: Set-CyberArkDelegation.ps1
    Author   : Shawn May
    Email    : shawn@yourdts.com
    Requires : Powershell V3 or greater
    Version  : 1.0

.PARAMETER
#>

# Add or Remove Delegation
$BolAddDelegation = $TRUE
$BolDelDelegation = $FALSE

Function Delegate-Revoke {
    [cmdletbinding()]
        Param
            (
            [Parameter(Mandatory=$TRUE)]
                [String]$ADPrinIn,
            
            [Parameter(Mandatory=$TRUE)]
                [String]$StrOUIn
            )

    # Revokes Permissions
    $cmd = "dsacls.exe '$StrOUIn' /R '`"$ADPrinIn`"'"
    Invoke-Expression $cmd
}

Function Delegate-PWReset {
    [cmdletbinding()]
        Param
            (
            [Parameter(Mandatory=$TRUE)]
                [String]$ADPrinIn,
            
            [Parameter(Mandatory=$TRUE)]
                [String]$StrOUIn,
            
            [Parameter(Mandatory=$TRUE)]
                [String]$StrObjTypeIn
            )

    # Object (User) - Grants Reset Password
    $cmd = "dsacls.exe '$StrOUIn' /I:T /G '`"$ADPrinIn`":CA;`"Reset Password`"'"
    Invoke-Expression $cmd

    # Properties / Attributes - Grants Full Permissions
    $cmd = "dsacls.exe '$StrOUIn' /I:S /G '`"$ADPrinIn`":WP;pwdLastSet;$StrObjTypeIn'"
    Invoke-Expression $cmd
}

Function Delegate-Object {
    [cmdletbinding()]
        Param
            (
            [Parameter(Mandatory=$TRUE)]
                [String]$ADPrinIn,
            
            [Parameter(Mandatory=$TRUE)]
                $ArrOUIn,
            
            [Parameter(Mandatory=$TRUE)]
                [String]$StrObjTypeIn,

            [Parameter(Mandatory=$FALSE)]
                [Switch]$BolPWReset
            )

    # Security Group (Principal)
    $StrPrincipal = ($StrForestNetBIOS + "\" + $ADPrinIn)

    # Cycle through Array
    foreach ($StrOU in $ArrOUIn)
        {
        if ($BolDelDelegation)
            {
            #Calls function to revoke delegation
            Delegate-Revoke -ADPrinIn $StrPrincipal `
                    -StrOUIn $StrOU
            }

        if (($BolAddDelegation) -and ($BolPWReset))
            {
            #Calls function to delegate password reset
            Delegate-PWReset `
                -ADPrinIn $StrGrp -StrOUIn $StrOU `
                -StrObjTypeIn $StrObjTypeIn
            }
        }
}
    
Function Main {
    [cmdletbinding()]
        Param()

    # Forest Root NetBIOSName
    $StrForestNetBIOS = (Get-ADDomain (Get-ADForest).RootDomain).NetBIOSName

    # Domain Root DN
    $ObjDomainDN = (Get-ADDomain -Server (Get-ADDomainController -Discover `
                            -ForceDiscover).hostname[0]).DistinguishedName

    #######################
    # Account OU
    # Target Object
    $ObjType = "User"

        # List of OU(s)
        $ArrOU = [System.Collections.ArrayList]@()
        $Null = $ArrOU.Add("CN=AdminSDHolder,CN=System,$ObjDomainDN")
        $Null = $ArrOU.Add($ObjDomainDN)

        # Additional OUs that have have their inherience broken
        $Null = $ArrOU.Add("OU=Accounts,$ObjDomainDN")

        # Security Group (Principal)
        $StrGrp = "srv_CyberArk"
        
    # Calls function to perform delegation
    Delegate-Object -ADPrinIn $StrGrp -ArrOUIn $ArrOU -StrObjTypeIn $ObjType -BolPWReset
}

Main