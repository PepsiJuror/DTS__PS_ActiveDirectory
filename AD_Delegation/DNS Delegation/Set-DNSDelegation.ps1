<#
.Synopsis
    Simple script that delegates requirement permissions for ADI Primary DNS zones.

.Description
    Regardless of whether the ADI zone lives in either the ForestDNSZones or DomainDNSZones 
    app partition, the script below locates and narrows delegation to only dnsNode objects 
    beneath each Primary AD Integrated DNS zones, including Forward and/or Reverse. 
    
    This script however excluding delegation for Conditional Forwarders, including the 
    coveted _msdcs. zone. 

    Important Note:  Delegation will need to be rerun / reexecuted if:
    - AD zone replication scopes are modified (e.g. zone replication is moved from DomainDNSZone 
    to ForestDNSZones)
    - An AD zone is created

.Notes:
    File Name: Set-DNSDelegation.ps1
    Author   : Shawn May
    Email    : shawn@yourdts.com
    Requires : Powershell V3 or greater
    Version  : 1.0

.PARAMETER
#>

[cmdletbinding()]
    Param ()

# Add or Remove Delegation
# True = Grants | False = Revokes
$BolDelGrant = $TRUE

# AD Domain Object
$ObjADDomain = Get-ADDomain | Select-Object SystemsContainer, NetBIOSName, DistinguishedName

# Microsoft DNS System Container
$StrDNSSystem = ("CN=MicrosoftDNS," + (Get-ADDomain).SystemsContainer)

# Forest Root NetBIOSName
$StrForestNetBIOS = (Get-ADDomain (Get-ADForest).RootDomain).NetBIOSName

# Defines Preferred DC
$PrefDC = [string](Get-ADDomainController -Discover -Service PrimaryDC).HostName

# Principal Groups Names for delegation
$StrADGrp1 = "Sec Group1 - DNS Record Mgmt"
$StrADGrp2 = "Sec Group2 - DNS Record Create"

# Test AD Group Existence
Try
    {
    $StrPrin1 = $Null; $ObjGroup = $Null
    $ObjGroup = Get-ADGroup $StrADGrp1 -ErrorAction Stop
    if ($ObjGroup -is [object])
        {$StrPrin1 = [string]($StrForestNetBIOS + "\" + $ObjGroup.name)}
    }
Catch
    {Write-Warning "Unable to Locate AD SEcurity Group: $StrGrp1"}

# Test AD Group Existence
Try
    {
    $StrPrin2 = $Null; $ObjGroup = $Null
    $ObjGroup = Get-ADGroup $StrADGrp2 -ErrorAction Stop
    if ($ObjGroup -is [object])
        {$StrPrin2 = [string]($StrForestNetBIOS + "\" + $ObjGroup.name)}
    }
Catch
    {Write-Warning "Unable to Locate AD SEcurity Group: $StrADGrp2"}

# Obtains list of filted DNS Zones
# Includes only: Primary & Integrated Zones
# Excludes only: Zonename _msdcs. & TrustedAnchors 
$ArrDNSZones = Get-DnsServerZone -ComputerName $PrefDC | where `
    {($_.Zonetype -eq "Primary") -and ($_.IsDsIntegrated) -and 
    ($_.zonename -notmatch "_msdcs.") -and ($_.zonename -notmatch "TrustAnchors")}

# Create Array
$ArrCmd = [System.Collections.ArrayList]@()

# Delegates permissions
if ($BolDelGrant)
    {
    if ($StrPrin1 -is [object])
        {
        # /G: Grant
        # RC: Read security information.
        # LC: List the child objects of the object.
        # RP: Read a property.
        # Note: Permissions are not inheritiable
        $Null = $ArrCmd.Add("dsacls.exe '$StrDNSSystem' /G '`"$StrPrin1`":RPLCRC;;'")
        
        # /I:T The object and its child objects
        # CC: Create a child object.
        # DC: Delete a child object.
        # Cycle through DNS Zones
        $ArrDNSZones | Foreach {$Null = $ArrCmd.Add("dsacls.exe '$($_.DistinguishedName)' /I:T /G  '`"$StrPrin1`":CCDC;dnsnode'")}
        }
    if ($StrPrin2 -is [object])
        {
        $Null = $ArrCmd.Add("dsacls.exe '$StrDNSSystem' /G '`"$StrPrin2`":RPLCRC;;'")
        
        # /I:T The object and its child objects
        # CC: Create a child object.
        # Cycle through DNS Zones
        $ArrDNSZones | Foreach {$Null = $ArrCmd.Add("dsacls.exe '$($_.DistinguishedName)' /I:T /G  '`"$StrPrin2`":CC;dnsnode'")}
        }
    }
# Revoke permissions
elseif (!($BolDelGrant))
    {
    # /R: Revoke
    if ($StrPrin1 -is [object])
        {
        # /R: Revoke
        $Null = $ArrCmd.Add("dsacls.exe '$StrDNSSystem' /R '$StrPrin1'")

        # Cycle through DNS Zones
        $ArrDNSZones | Foreach {$Null = $ArrCmd.Add("dsacls.exe '$($_.DistinguishedName)' /R '`"$StrPrin1`"'")}
        }
    if ($StrPrin2 -is [object])
        {
        # /R: Revoke
        $Null = $ArrCmd.Add("dsacls.exe '$StrDNSSystem' /R '$StrPrin2'")

        # Cycle through DNS Zones
        $ArrDNSZones | Foreach {$Null = $ArrCmd.Add("dsacls.exe '$($_.DistinguishedName)' /R '`"$StrPrin2`"'")}
        }
    }

# Cycles through Delegation Commands
$ArrCmd | Foreach {
    # Writes Output to screen
    Write-Host $_ -ForegroundColor Yellow

    # Invokes command
    $Null = Invoke-Expression $_
    }