<#
.Synopsis
    Simple script that delegates requirement permissions for MIM.

.Description

.Notes:
    File Name: Set-MIMDelegation.ps1
    Author   : Shawn May
    Email    : shawn@yourdts.com
    Requires : Powershell V3 or greater
    Version  : 1.0

.PARAMETER
#>
Clear-Host

# Delegate Dev, Test or Prod
$BolDev  = $FALSE
$BolTest = $TRUE
$BolProd = $FALSE

# Delegate Replication Changes
$BolDelRepChanges = $TRUE

# Add or Remove Delegation
$BolDelGrant   = $TRUE
$BolDelRevoke  = $Null
if (!($BolDelGrant))
    {$BolDelRevoke = $TRUE}

# Function - Delegates MIM Attributes
Function Delegate-Attribs {
    [cmdletbinding()]
        Param
            (
            [Parameter(
                Mandatory=$TRUE)]
                $ADPrinIn,
            [Parameter(
                Mandatory=$TRUE)]
                $DNPathIn,
            [Parameter(
                Mandatory=$FALSE)]
                $AttribFilterIn,
            [Parameter(
                Mandatory=$FALSE)]$ObjSubClassIn
            )


    # Hash Table - Attribute for Delegation
    $ColAttribs = [ordered]@{
            accountExpires               = @{User1 = $TRUE  ; User2 = $TRUE  ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            adminCount                   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $FALSE}
            adminDescription             = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $TRUE}
            adminDisplayName             = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $TRUE}
            c                            = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            co                           = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            company                      = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            countryCode                  = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            department                   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            description                  = @{User1 = $TRUE  ; User2 = $TRUE  ; Group = $TRUE  ; Group2 = $TRUE  ; Computer = $FALSE}
            displayName                  = @{User1 = $TRUE  ; User2 = $TRUE  ; Group = $TRUE  ; Group2 = $TRUE  ; Computer = $FALSE}
            distinguishedName            = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $FALSE}
            employeeID                   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            employeeType                 = @{User1 = $TRUE  ; User2 = $TRUE  ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute1          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute10         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute11         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute12         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute13         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute14         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute15         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute2          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute3          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute4          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute5          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute6          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute7          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute8          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            extensionAttribute9          = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            facsimileTelephoneNumber     = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            givenName                    = @{User1 = $TRUE  ; User2 = $TRUE  ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            groupType                    = @{User1 = $FALSE ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $TRUE  ; Computer = $FALSE}
            homeDirectory                = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            homeDrive                    = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            idmManagedGroup              = @{User1 = $FALSE ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $TRUE  ; Computer = $FALSE}
            info                         = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $TRUE  ; Computer = $TRUE}
            initials                     = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            l                            = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            mailNickname                 = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $FALSE}
            managedBy                    = @{User1 = $FALSE ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $FALSE}
            manager                      = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $TRUE}
            member                       = @{User1 = $FALSE ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $FALSE}
            mobile                       = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            physicalDeliveryOfficeName   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            postalCode                   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            pwdLastSet                   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            sAMAccountName               = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $TRUE  ; Group2 = $FALSE ; Computer = $FALSE}
            sn                           = @{User1 = $TRUE  ; User2 = $TRUE  ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            st                           = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            streetAddress                = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            telephoneNumber              = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            thumbnailPhoto               = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            title                        = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            unicodePwd                   = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            userAccountControl           = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
            userPrincipalName            = @{User1 = $TRUE  ; User2 = $FALSE ; Group = $FALSE ; Group2 = $FALSE ; Computer = $FALSE}
    }

    # Checks if attribute filter was passed to function
    if ($AttribFilterIn)
        {
        # Creates New (temp) HashTable
        $ColAttribsNew = [ordered]@{}
            
        #Cycles through HashTable
        Foreach ($Name in $ColAttribs.Keys) 
            {
            #Enumerates Hashtable and filters on attribute & Boolean True
            ($ColAttribs[$Name]).GetEnumerator() | Where-Object {($_.Name -eq $ObjSubClassIn) -and ($_.Value -eq $True)} | Foreach `
                {$ColAttribsNew.add($Name, @{$_.name =$_.Value})}
            }
        $ColAttribs = $ColAttribsNew
        }

    Foreach ($Name in $ColAttribs.Keys) 
        {$Null = $ArrCmd.Add("dsacls.exe '$DNPathIn' /I:S /G '`"$ADPrinIn`":WP;$Name;$AttribFilterIn'")}
}

# Function - Delegate Objects
Function Delegate-Revoke {
    [cmdletbinding()]
        Param([Parameter(ValueFromPipeline = $TRUE)][hashtable[]]$HashTblIn)

    Begin {}
    Process
        {
        # Cycles through Array
        foreach ($item in $HashTblIn.Values)
            {
            # Adds Delegation Command to Variable
            $DelCmd = "dsacls.exe '$($Item.OU)' /R '`"$($Item.Prin)`"'"
                
            # Checks if command exists in Array
            if (!($ArrCmd.Contains($DelCmd)))
                {
                # Adds command to array
                $Null = $ArrCmd.Add($DelCmd)
                }
            }
        }
    End {}
}

# Function - Delegate Objects
Function Delegate-Grant {
    [cmdletbinding()]
        Param([Parameter(ValueFromPipeline = $TRUE)][hashtable[]]$HashTblIn)

    Begin
            {}

    Process {
            # Cycles through Array
            foreach ($item in $HashTblIn.Values)
                {
                # Security Group (Principal)
                $StrPrincipal = [string]$Item.Prin

                # Check Boolean (grant Delegation)
                Switch ([String]$Item.ObjType)
                    {
                    "OrganizationalUnit"
                        {
                        # Object Delegation - Grants Create Permission (The child objects only)
                        $Null = $ArrCmd.Add("dsacls.exe '$($Item.OU)' /I:S /G '`"$($Item.Prin)`":CC;$($Item.ObjType)'")

                        # Properties / Attributes - Grants Full Permissions
                        $Null = $ArrCmd.Add("dsacls.exe '$($Item.OU)' /I:S /G '`"$($Item.Prin)`":WP;;$($Item.ObjType)'")
                        }

                    "Directory"
                        {
                        # Control Access Delegation - Grants Permissions (The object and its child objects)
                        $Null = $ArrCmd.Add("dsacls.exe '$($Item.OU)' /I:T /G '`"$($Item.Prin)`":CA;`"Replicating Directory Changes`"'")
                        }

                    "User"
                        {
                        #Write-Debug "Pausing Again"

                        # Checks Boolean Value
                        if ([bool]$Item.PWReset)
                            {
                            # Control Access Delegation - Grants Reset Password (The object and its child objects)
                            $Null = $ArrCmd.Add("dsacls.exe '$($Item.OU)' /I:T /G '`"$($Item.Prin)`":CA;`"Reset Password`"'")
                            }

                        if ($Item.ObjSubClass -eq 'User1')
                            {
                            # Object Delegation - Grants Create & Delete Permissions (The child objects only)
                            $Null = $ArrCmd.Add("dsacls.exe '$($Item.OU)' /I:S /G '`"$($Item.Prin)`":CCDC;$($Item.ObjType)'")
                            }

                        # Properties / Attributes - Grants specific permissions
                        Delegate-Attribs -ADPrinIn $($Item.Prin) `
                            -DNPathIn $Item.OU `
                            -AttribFilter $Item.ObjType `
                            -ObjSubClass $Item.ObjSubClass
                        }

                    "Group"
                        {
                        # Checks if ObjSubclass is Group1 - Root level
                        if ($Item.ObjSubClass -eq 'Group1')
                            {
                            # Object Delegation - Grants Create & Delete Permissions (The child objects only)
                            $Null = $ArrCmd.Add("dsacls.exe '$($Item.OU)' /I:S /G '`"$($Item.Prin)`":CCDC;$($Item.ObjType)'")
                            }

                        # Properties / Attributes - Grants specific permissions
                        Delegate-Attribs -ADPrinIn $($Item.Prin) `
                            -DNPathIn $Item.OU `
                            -AttribFilter $Item.ObjType  `
                            -ObjSubClass $Item.ObjSubClass
                        }

                    "Computer"
                        {
                        # Properties / Attributes - Grants specific permissions
                        Delegate-Attribs -ADPrinIn $($Item.Prin) `
                            -DNPathIn $Item.OU `
                            -AttribFilter $Item.ObjType  `
                            -ObjSubClass $Item.ObjSubClass
                        }
                    }
                }
            }
    End {}
}

# Main Function
Function Main {
    [cmdletbinding()]
        Param()

    # Forest Root NetBIOSName
    $StrForestNetBIOS = (Get-ADDomain (Get-ADForest).RootDomain).NetBIOSName

    # Domain Root DN
    $ObjDomainDN = (Get-ADDomain -Server (Get-ADDomainController -Discover `
                            -ForceDiscover).hostname[0]).DistinguishedName

    # Delegation Command Array
    $ArrCmd = [System.Collections.ArrayList]@()

    $ColObj = [ordered]@{}

    if ($BolProd -or $BolTest)
        {
        # MIM Prod Delegation Principal
        $TxtPrin = "Control Plane - Delegation Service - MIM Objects"
    
        if ($BolTest)
            { # MIM Test Delegation Principal
            $TxtPrin = "Control Plane - Delegation Service - MIM Objects - Test"
            }
        
        # Principal for delegation
        $StrPrin = ($StrForestNetBIOS + "\" + $TxtPrin)

        Switch ($StrForestNetBIOS)
            {
                {($_ -eq "Acme") -or ($_ -eq "AcmeLAB")}
                    {
                    # Adds to array
                    $ColObj.User1      = @{Prin = $StrPrin; ObjType = "User"     ; ObjSubClass = "User1"  ; PWReset = $True  ; OU = $ObjDomainDN}
                    $ColObj.User2      = @{Prin = $StrPrin; ObjType = "User"     ; ObjSubClass = "User2"  ; PWReset = $False ; OU = "OU=Control Plane,$ObjDomainDN"}
                    $ColObj.Group1     = @{Prin = $StrPrin; ObjType = "Group"    ; ObjSubClass = "Group1" ; PWReset = $False ; OU = $ObjDomainDN}
                    $ColObj.Group2     = @{Prin = $StrPrin; ObjType = "Group"    ; ObjSubClass = "Group2" ; PWReset = $False ; OU = "OU=Control Plane,$ObjDomainDN"}
                    $ColObj.Computer1  = @{Prin = $StrPrin; ObjType = "Computer" ; ObjSubClass = "Computer1"  ; PWReset = $False ; OU = $ObjDomainDN}
                    $ColObj.OrgUnit1   = @{Prin = $StrPrin; ObjType = "OrganizationalUnit" ; ObjSubClass = "StdOU1" ; PWReset = $False ; OU = "OU=Accounts,$ObjDomainDN"}
                    $ColObj.OrgUnit2   = @{Prin = $StrPrin; ObjType = "OrganizationalUnit" ; ObjSubClass = "StdOU1" ; PWReset = $False ; OU = "OU=Groups,$ObjDomainDN"}
                    }
                {($_ -eq "Prod") -or ($_ -eq "ProdUAT")}
                    {
                    # Adds to array
                    $ColObj.User1      = @{Prin = $StrPrin; ObjType = "User"     ; ObjSubClass = "User1"  ; PWReset = $True  ; OU = $ObjDomainDN}
                    $ColObj.Group1     = @{Prin = $StrPrin; ObjType = "Group"    ; ObjSubClass = "Group1" ; PWReset = $False ; OU = $ObjDomainDN}
                    $ColObj.Computer1  = @{Prin = $StrPrin; ObjType = "Computer" ; ObjSubClass = "Computer1"  ; PWReset = $False ; OU = $ObjDomainDN}
                    $ColObj.OrgUnit2   = @{Prin = $StrPrin; ObjType = "OrganizationalUnit" ; ObjSubClass = "StdOU1" ; PWReset = $False ; OU = "OU=Groups,$ObjDomainDN"}
                    }
            }
        }
    elseif ($BolDev)
        {
        $TxtPrin = "Control Plane - Delegation Service - MIM Objects - Dev"

        # Principal for delegation
        $StrPrin = ($StrForestNetBIOS + "\" + $TxtPrin)

        # Dev Root OU
        $StrDevRoot = (Get-ADOrganizationalUnit `
            -Filter 'name -eq "Dev MIM Objects"').DistinguishedName

        # Adds to array
        $ColObj.User1     = @{Prin = $StrPrin; ObjType = "User"     ; ObjSubClass = "User1"  ; PWReset = $TRUE  ; OU = $StrDevRoot}
        $ColObj.Group1    = @{Prin = $StrPrin; ObjType = "Group"    ; ObjSubClass = "Group1" ; PWReset = $False ; OU = $StrDevRoot}
        $ColObj.Computer1 = @{Prin = $StrPrin; ObjType = "Computer" ; ObjSubClass = "Computer1"  ;PWReset = $False ; OU = $StrDevRoot}
        $ColObj.OrgUnit1  = @{Prin = $StrPrin; ObjType = "OrganizationalUnit" ; ObjSubClass = "StdOU1" ; PWReset = $False ; OU = $StrDevRoot}
        }

    if ($BolDelRepChanges)
        {
        # Adds to array
        $ColObj.DirRepl1  = @{Prin = $StrPrin; ObjType = "Directory"; ObjSubClass = "StdRep" ; PWReset = $False ; OU = $ObjDomainDN}
        }

    # Checks Boolean Revoke
    if ($BolDelRevoke)
        {$ColObj | Delegate-Revoke}

    # Checks Boolean Grant
    if ($BolDelGrant)
        {$ColObj | Delegate-Grant}

    # Cycles through Delegation Commands
    $ArrCmd | Foreach {
        # Writes Output to screen
        Write-Host $_ -ForegroundColor Yellow

        # Invokes command
        $Null = Invoke-Expression $_
        }
}

Main 