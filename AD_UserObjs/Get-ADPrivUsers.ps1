# Updated 06/18/21
Clear-Host
$Error.Clear()
# Acquires Date
$Date = Get-Date


Class User {
    [Array]    hidden $AddrTypes = @('SMTP','SIP')
    [datetime] hidden $Date
    [Bool]     $IsCriticalSystemObject
    [String]   $ExpireDate
    [String]   $ExpireStatus
    [Bool]     $Expired
    [Bool]     $Stale
    [Bool]     $PWNotRequired
    [Bool]     $PWCantChange
    [Bool]     $PWDoesNotExpire
    [Bool]     $TrustedForDelegation
    [Bool]     $UseDesKeyOnly
    [string]   $SMTPProxyAddr
    [string]   $SIPProxyAddr
    [string]   $LastLogonTimeStamp
    [string]   $LastLogonDate
    [string]   $Memberof
    [Array]    $ArrMemberof
    [Int32]    $GroupCount
    [GUID]     $ObjectGUID
    [string]   $eTypes
    [string]   $UserSID


    # Constructor
    User() {}

    # Constructor
    User($ObjUser)
        {
        $this.ObjectGUID = $ObjUser.ObjectGUID
        $this.SetCriticalFlag($ObjUser.IsCriticalSystemObject)
        $this.GetADExpiration($ObjUser.accountExpires)
        $this.AddrTypes | foreach {$this.GetProxyAddr($ObjUser.proxyAddresses,$_)}
        $this.DecodeLastLogon($ObjUser.LastLogonTimeStamp,$ObjUser.LastLogonDate)
        $this.GetMemberOf($ObjUser.Memberof)
        $this.DecodeUAC($ObjUser.UserAccountControl)
        $this.GetETypes($ObjUser.'msDS-SupportedEncryptionTypes')
        $this.UserSID = $ObjUser.SID.ToString()
        }

    GetETypes($SupportedEncryptionTypesIn)
        {
        Switch ($SupportedEncryptionTypesIn)
            {
            0 {$this.eTypes = "Not defined - defaults to RC4_HMAC_MD5"}
            1 {$this.eTypes = "DES_DES_CBC_CRC"}
            2 {$this.eTypes = "DES_CBC_MD5"}
            3 {$this.eTypes = "DES_CBC_CRC, DES_CBC_MD5"}
            4 {$this.eTypes = "RC4"}
            5 {$this.eTypes = "DES_CBC_CRC, RC4"}
            6 {$this.eTypes = "DES_CBC_MD5, RC4"}
            7 {$this.eTypes = "DES_CBC_CRC, DES_CBC_MD5, RC4"}
            8 {$this.eTypes = "AES 128"}
            9 {$this.eTypes = "DES_CBC_CRC, AES 128"}
            10 {$this.eTypes = "DES_CBC_MD5, AES 128"}
            11 {$this.eTypes = "DES_CBC_CRC, DES_CBC_MD5, AES 128"}
            12 {$this.eTypes = "RC4, AES 128"}
            13 {$this.eTypes = "DES_CBC_CRC, RC4, AES 128"}
            14 {$this.eTypes = "DES_CBC_MD5, RC4, AES 128"}
            15 {$this.eTypes = "DES_CBC_MD5, DES_CBC_MD5, RC4, AES 128"}
            16 {$this.eTypes = "AES 256"}
            17 {$this.eTypes = "DES_CBC_CRC, AES 256"}
            18 {$this.eTypes = "DES_CBC_MD5, AES 256"}
            19 {$this.eTypes = "DES_CBC_CRC, DES_CBC_MD5, AES 256"}
            20 {$this.eTypes = "RC4, AES 256"}
            21 {$this.eTypes = "DES_CBC_CRC, RC4, AES 256"}
            22 {$this.eTypes = "DES_CBC_MD5, RC4, AES 256"}
            23 {$this.eTypes = "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256"}
            24 {$this.eTypes = "AES 128, AES 256"}
            25 {$this.eTypes = "DES_CBC_CRC, AES 128, AES 256"}
            26 {$this.eTypes = "DES_CBC_MD5, AES 128, AES 256"}
            27 {$this.eTypes = "DES_CBC_MD5, DES_CBC_MD5, AES 128, AES 256"}
            28 {$this.eTypes = "RC4, AES 128, AES 256"}
            29 {$this.eTypes = "DES_CBC_CRC, RC4, AES 128, AES 256"}
            30 {$this.eTypes = "DES_CBC_MD5, RC4, AES 128, AES 256"}
            31 {$this.eTypes = "DES+A1:C33_CBC_MD5, DES_CBC_MD5, RC4, AES 128, AES 256"}
            default {$this.eTypes = "Not defined - defaults to RC4_HMAC_MD5"}
            }
        }

    SetCriticalFlag([Bool]$IsCriticalIn)
        {
        if ($IsCriticalIn -is [object])
            {$this.IsCriticalSystemObject = $IsCriticalIn}
        else
            {$this.IsCriticalSystemObject = [DBNull]::Value}
        }

    GetADExpiration([Int64]$ExpirationIn)
        {
        $this.Date = Get-Date

        # Checks value - Nonexpiring Value
        if (($ExpirationIn -eq '9223372036854775807') -or `
                ($ExpirationIn[0] -eq 0) -or `
                ([datetime]::fromfiletime($ExpirationIn) -gt [DateTime]::MaxValue.Ticks)) #($lngValue -gt [DateTime]::MaxValue.Ticks))
            {
            $this.ExpireDate   = $Null
            $this.ExpireStatus = "NonExpiring"
            $this.Expired      = $False
            }
        Else
            {
            $lngValue = [datetime]::fromfiletime($ExpirationIn)

            # Assigns Value to Array
            $this.ExpireDate = $lngValue.ToLocalTime().toshortdatestring()
            #$AcctExpires = @($lngValue.ToLocalTime().toshortdatestring())

            if ([DateTime]$this.ExpireDate -gt [DateTime]$this.Date)
                { # Assigns Values to Array (appends)
                $this.ExpireStatus = "Active"
                $this.Expired = $False
                }
            else
                { # Assigns Values to Array (appends)
                $this.ExpireStatus = "Expired"
                $this.Expired = $True
                #$this.Stale = $True
                }
            }

        }

    GetProxyAddr([array]$ProxyAddrIn,[string]$AddrFilter)
        {
        $ProxyAddr = $Null
        # Checks if Variable is Object
        #if (($ProxyAddrIn | Measure-Object).count -gt 0)
        if (($ProxyAddrIn | where {(($_).split(":")[0] -match $AddrFilter)}| Measure-Object).count -gt 0)
            { # Cycles through Variable
            $ProxyAddrIn | Foreach `
                { # Splits String (see filter)
                if (($_).split(":")[0] -match $AddrFilter)
                    { # Checks if value is Null
                    if ($ProxyAddr -eq $Null)
                        { # Assigns Value to variable
                        $ProxyAddr = ($_).split(":")[1]} `
                    else
                        { # Appends Value to variable
                        $ProxyAddr += ("," + ($_).split(":")[1])}
                    }
                }
            }
        else
            {$ProxyAddr = "None"}

        if ($AddrFilter -eq $this.AddrTypes[0])
            {$this.SMTPProxyAddr = $ProxyAddr}
        else
            {$this.SIPProxyAddr = $ProxyAddr}
        }

    DecodeLastLogon($LastLogonTimeStampIn,$LastLogonDateIn)
        {
        if ($LastLogonTimeStampIn -is [object])
            {$this.LastLogonTimeStamp = [datetime]::FromFileTime($LastLogonTimeStampIn).toshortdatestring()}
        else
            {$this.LastLogonTimeStamp = $Null}

        if ($LastLogonDateIn -is [object])
            {$this.LastLogonDate = ($LastLogonDateIn).toshortdatestring()}
        else
            {$this.LastLogonDate = $Null}
        }

    GetMemberOf($MemberofIn)
        {
        foreach ($Member in $MemberofIn)
            {
            if ([string]::IsNullOrEmpty($this.Memberof))
                {$this.Memberof = $Member}
            else
                {$this.Memberof += ("`n" + $Member)}
            }
        $this.GroupCount = ($MemberofIn | Measure-Object).count
        $MemberofIn | foreach {$this.ArrMemberof += @($_)}
        }

    DecodeUAC($UserAccountControl)
        {
        $this.PWNotRequired = (($UserAccountControl -band 32) -eq 32)
        $this.PWCantChange = (($UserAccountControl -band 64) -eq 64)
        $this.PWDoesNotExpire = (($UserAccountControl -band 65536) -eq 65536)
        $this.TrustedForDelegation = (($UserAccountControl -band 524288) -eq 524288)
        $this.UseDesKeyOnly = (($UserAccountControl -band 2097152) -eq 2097152)
        }

    [Int32]GetDateDiff([datetime]$DateIn, [datetime]$today)
        {
        Return (New-TimeSpan -Start $DateIn -End $today).Days
        #Return $this.Days
        }


}

# Function | Validates and/creates output folder path
Function Validate-Folder {
    [cmdletbinding()]
        Param 
            ([Parameter(Mandatory=$True)]
                [String]$Folderin
            )
    # Tests path
    if ((Test-Path $Folderin) -eq $False)
        {
        # Creates New Directory (supresses output)
        $a = New-Item -ItemType directory -Path $Folderin
        }
    }

# Function | Converts FQDN to DistinguishedName
Function Convert-FQDN2DN {
    [cmdletbinding()]
        Param ([Parameter(Mandatory=$True)]
                [string]$domainFQDN)

    # Splits FQDN in Array 
    $colSplit = $domainFQDN.Split('.')

    # Captures Number of Array
    $FQDNdepth = $colSplit.length
    $DomainDN = ''

    # Cycles Through Array
    For ($i=0; $i -lt ($FQDNdepth); $i++)
        {
        If ($i -eq ($FQDNdepth - 1)) {$Separator=''}
        else {$Separator=','}
        [string]$DomainDN += 'DC=' + $colSplit[$i] + $Separator
        }
    Return $DomainDN
}

# Function | Builds Forest Domains Datatable
Function Build-ForestDomSIDDT {
    [cmdletbinding()]
        Param($ObjForestIn)
    
    # Cycles through all Forest Domains
    foreach ($StrDomain in $ObjForestIn.Domains)
        {
        # Captures single domain controller from each domain in the forest
        $ObjDC = Get-ADDomainController `
            -DomainName $StrDomain `
            -Discover `
            -Service ADWS `
            -ForceDiscover

        # Populates Datatable
        $ObjDTRow_DomSIDs = $DT_DomainSIDs.NewRow()
        $ObjDTRow_DomSIDs.Forest            = $ObjForestIn.RootDomain
        $ObjDTRow_DomSIDs.Domain            = $StrDomain
        $ObjDTRow_DomSIDs.DomainSID         = ((Get-ADDomain $ObjDC.Domain).domainSID).tostring()
        $ObjDTRow_DomSIDs.DomainController  = $ObjDC.HostName[0]
        $ObjDTRow_DomSIDs.DomainDN          = [string](Convert-FQDN2DN ($ObjDC.Domain))
        $DT_DomainSIDs.Rows.Add($ObjDTRow_DomSIDs)
        }
}

# Function | Builds Forest Privileged Group Datatable
Function Build-ForestPrivGroupDT {
    [cmdletbinding()]
        Param($ObjForestIn)

    # Privileged Group Membership for the following groups:
    # Reference: http://support.microsoft.com/kb/243330

    # GPO Full Report CSV File Name
    $CSVFileName = ("_" + $ObjForestIn.name + "_ForestPrivilegedGrps_" + $StrFileDateSuffix + ".csv"`
            -f $Date.year, $Date.month, $Date.Day)

    # Join Path to create Export Variable
    $Export = Join-Path 'S:\UserData\ShawnMay' $CSVFileName

    # Calls Function to Obtain list of Forest Domains, DomainSIDs, and Domain Controllers
    Write-Host ('Querying Forest Details: ' + $ObjForestIn.name)

    # Property Sets
    $GrpProps = @("Name","DistinguishedName","adminCount","nTSecurityDescriptor","objectSID")
    $SelProps = @($GrpProps)
    $SelProps += @({$_.nTSecurityDescriptor.AreAccessRulesProtected})
    $NestedGrpProps = @('Name','objectSID','DistinguishedName','objectclass')
        
    # Converts Forest FQDN to DistinguishedName
    $DomainDN = [String](Convert-FQDN2DN -domainFQDN ($ObjForestIn.name))

    # Captures Forest / Domain SID
    $DomainSID = ((Get-ADDomain $ObjForestIn.name).domainSID).tostring()

    # Default Forest & Domain Privileged SIDs
    $DefForestSIDs = @("$DomainSID-518","$DomainSID-519")
    $DefDomainSIDs = @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-551','S-1-5-32-550')
    $AppendDomSIDs = @('512','517','520','521','553')

    # Cycles through Forest Domains
    foreach ($StrDomain in $ObjForestIn.Domains)
        {
        # Writes message to screen
        Write-Host ('- Querying for Domain Controller: ' + $StrDomain)
        
        # Queryies Domain Controller (Local Parent)
        $ObjDC = Get-ADDomainController `
            -DomainName $StrDomain -Discover `
            -Service ADWS -ForceDiscover

        # -- Builds Unique Domain Privileged SID Collection -- #
            # Creates Array
            $ColDomainSIDs = @()

            # Captures Unique Domain SID
            $DomainSID = ((Get-ADDomain -Server $ObjDC.Domain).domainSID).tostring()

            # Adds Forest Privileged SIDs to Collection
            if ($StrDomain.name -eq $ObjForest.name)
                {$ColDomainSIDs = $DefForestSIDs}

            # Adds Domain Privileged SIDs to Collection
            if ($ColDomainSIDs -is [object]) 
                {$ColDomainSIDs += $DefDomainSIDs}
            else
                {$ColDomainSIDs = $DefDomainSIDs}

            # Adds Domain Privileged SIDs to Collection
            $AppendDomSIDs | foreach `
                {$ColDomainSIDs += ($DomainSID + '-' + $_)}
            
            # Writes message to screen
            Write-Host "- Querying Domain Privileged Group SIDs - DC: $($ObjDC.Hostname[0])"
        # ----------------------------------------- #
        
        # Cycles through Unique Domain Privileged SID Collection
        Foreach ($SID in $ColDomainSIDs)
            {
            # Create Array Varible
            $ColNestedGrps = @()

            # Writes Nested Group Details Datatable
            $ColNestedGrps = Write-toTable -ObjDCIn $ObjDC -StrSIDIn $SID

            # Checks if Variable is object
            if ($ColNestedGrps -is [object])
                {
                # Cycles through Domain Privileged Nested Groups
                foreach ($NestedGrp in $ColNestedGrps) 
                    {
                    # Queries Datatable for Nested Group's Domain Details (i.e. Domain, DN, SID & DC)
                    $ObjNestedDomain = ($DT_DomainSIDs.where({$NestedGrp.objectSID.ToString() -match $_.DomainSid}))

                    # Writes Nested Group Details Datatable
                    Write-toTable -ObjDCIn $ObjDC -StrSIDIn $NestedGrp.objectSID
                    }
                }
            # Nulls variable
            $ColNestedGrps = $Null ; $ObjNestedDomain = $Null
            }
        }
    
    # Exports Datatable to CSV
    $DT_ForestPrivGrps | Export-Csv $Export -NoTypeInformation
    
    
    }

Function Get-NestDNs {
    [cmdletbinding()]
        Param($ObjIn)

    foreach ($DN in $ObjIn)
        { 
        if ([string]::IsNullOrEmpty($Temp1) -or [string]::IsNullOrEmpty($Temp2))
            {
            $Temp1 = $DN.DistinguishedName
            $Temp2 = $DN.Name
            }
        else
            {
            $Temp1 += "`n" + $DN.DistinguishedName
            $Temp2 += "`n" + $DN.Name
            }
        }
    $StrNestedDNOut = @()        
    $StrNestedDNOut += $Temp1
    $StrNestedDNOut += $Temp2
    Return [array]$StrNestedDNOut
}
    
Function Define-Attributes {
        <#
        .Synopsis
            Function Defines & Populates:
                1.) Data Table Columns

        .Notes:
            Function Name: Define-Attributes
            Author: Shwan May
            Email: shawn.may@yourdts.com
            Requires: Powershell V3 or greater

        .PARAMETER
    
        .EXAMPLE
        #>

    [cmdletbinding()]
        Param([Parameter(Mandatory=$True)]
                [Int32]$IntGrp)

    # Define Array
    $ArrDTCols = @()
    $ArrDTCols += @('Counter')

    # Define Array
    $Script:ADUserAttribs = @()
    $Script:ADUserAttribs += @('IsCriticalSystemObject')
    $Script:ADUserAttribs += @('AccountExpirationDate','accountExpires')
    $Script:ADUserAttribs += @('Enabled')
    $Script:ADUserAttribs += @('CanonicalName','DisplayName')
    $Script:ADUserAttribs += @('Department','Description')
    $Script:ADUserAttribs += @('Division')
    $Script:ADUserAttribs += @('EmailAddress','mail')
    $Script:ADUserAttribs += @('adminCount','adminDescription')
    $Script:ADUserAttribs += @('ProxyAddresses')
    $Script:ADUserAttribs += @('lastLogonTimestamp','LastLogonDate')
    $Script:ADUserAttribs += @('logonCount')
    $Script:ADUserAttribs += @('msDS-SupportedEncryptionTypes')
    $Script:ADUserAttribs += @('MemberOf','Organization')
    $Script:ADUserAttribs += @('PasswordLastSet','pwdLastSet')
    $Script:ADUserAttribs += @('PasswordExpired')
    $Script:ADUserAttribs += @('CannotChangePassword')
    $Script:ADUserAttribs += @('PasswordNeverExpires','PasswordNotRequired')
    $Script:ADUserAttribs += @('SamAccountName','ScriptPath')
    $Script:ADUserAttribs += @('SIDHistory')
    $Script:ADUserAttribs += @('UserAccountControl','UserPrincipalName')
    $Script:ADUserAttribs += @('whenChanged','whenCreated')
    $Script:ADUserAttribs += @('DistinguishedName')


    Switch ($IntGrp)
        {
            0
                {
                $ArrDTCols += @('Forest')
                $ArrDTCols += @('Domain')
                $ArrDTCols += @('DomainDN')
                $ArrDTCols += @('DomainSID')
                $ArrDTCols += @('DomainController')
                }

# Privileged Group Data Table Columns
            1
                {
                $ArrDTCols += @('ReportDate')
                $ArrDTCols += @('NestType')
                $ArrDTCols += @('PrivGrpScope')
                $ArrDTCols += @('ParentGrp')
                $ArrDTCols += @('ChildGrp')
                $ArrDTCols += @('Forest')
                $ArrDTCols += @('Domain')
                $ArrDTCols += @('DomainDN')
                $ArrDTCols += @('DomainController')
                $ArrDTCols += @('DomainSID')
                $ArrDTCols += @('PrivGrpName')
                $ArrDTCols += @('PrivGrpDN')
                $ArrDTCols += @('PrivGrpSID')
                $ArrDTCols += @('AdminCount')
                $ArrDTCols += @('InheritanceBroken')
                $ArrDTCols += @('NestedCompCnt')
                $ArrDTCols += @('NestedForeignPrinCnt')
                $ArrDTCols += @('NestedGMSACnt')
                $ArrDTCols += @('DirectUserCnt')
                $ArrDTCols += @('NestedUserCnt')
                $ArrDTCols += @('UniqueUserCnt')
                $ArrDTCols += @('%UserDups')
                $ArrDTCols += @('NestedGroupCnt')
                $ArrDTCols += @('NestedGroupsDN')
                $ArrDTCols += @('NestedGroupsName')
                }
            
# Privileged User Data Set Columns
            2
                {
                # Default Array Definition: DataTable Column List
                $ArrDTCols += @('ReportDate')
                $ArrDTCols += @('Grp_Forest')
                $ArrDTCols += @('Grp_Domain')
                $ArrDTCols += @('Grp_NestType')
                $ArrDTCols += @('Grp_Scope')
                $ArrDTCols += @('Grp_Parent')
                $ArrDTCols += @('Grp_Child')
                $ArrDTCols += @('Grp_DomainDN')
                $ArrDTCols += @('Grp_DomainController')
                $ArrDTCols += @('Grp_DomainSID')
                $ArrDTCols += @('Grp_Name')
                $ArrDTCols += @('Grp_DN')
                $ArrDTCols += @('Grp_SID')
                $ArrDTCols += @('Grp_AdminCount')
                $ArrDTCols += @('Grp_InheritanceBroken')
		        $ArrDTCols += @('Stale')
                $ArrDTCols += @('User_Forest')
                $ArrDTCols += @('User_Domain')
                $ArrDTCols += @('IsCriticalSystemObject')
		        $ArrDTCols += @('SamAccountName')
                $ArrDTCols += @('DisplayName')
                $ArrDTCols += @('Enabled')
                $ArrDTCols += @('Expired')
                $ArrDTCols += @('ExpireStatus')
                $ArrDTCols += @('ExpireDate')
                $ArrDTCols += @('ExpirationDate')
                $ArrDTCols += @('ExpirationDays')
                $ArrDTCols += @('AccountExpires')
                $ArrDTCols += @('LastLogonDaysAgo')
                $ArrDTCols += @('LastLogonTimestamp')
                $ArrDTCols += @('LastLogonDate')
                $ArrDTCols += @('LogonCount')
                $ArrDTCols += @('CanonicalName')
                $ArrDTCols += @('Department','Description')
                $ArrDTCols += @('Division')
                $ArrDTCols += @('ETypes')
                $ArrDTCols += @('EmailAddress','mail')
                $ArrDTCols += @('adminCount','adminDescription')
                $ArrDTCols += @('ProxyAddresses')
                $ArrDTCols += @('ProxySMTPAddr','ProxySIPAddr')
                $ArrDTCols += @('MemberOf','GroupCount','AdmGrpCnt','Organization')
                $ArrDTCols += @('pwdExpired')
                $ArrDTCols += @('pwdLastSet')
                $ArrDTCols += @('pwdLastSetDaysAgo')
                $ArrDTCols += @('CannotChangePwd')
                $ArrDTCols += @('pwdNotRequired')
                $ArrDTCols += @('pwdNeverExpires')
                $ArrDTCols += @('ScriptPath')
                $ArrDTCols += @('SIDHistory')
                $ArrDTCols += @('UserAccountControl')
                $ArrDTCols += @('UAC_PWNotRequired','UAC_PWCantChange')
                $ArrDTCols += @('UAC_PWDoesNotExpire','UAC_TrustedForDelegation')
                $ArrDTCols += @('UAC_UseDesKeyOnly','UserPrincipalName')
                $ArrDTCols += @('whenChanged','whenCreatedDays','whenCreated')
                $ArrDTCols += @('DistinguishedName')
                }
        }
    Return $ArrDTCols

}

Function Write-toTable {
    [cmdletbinding()]
        Param($ObjDCIn, $StrSIDIn)

    $Error.Clear()

    # LDAP Filter - SID
    $LDAPFilter  = "(objectsid=$($StrSIDIn))"

    # Assigns Variable Value
    $GrpScope = 'Local Domain'
    $StrDashes = '--'
    $Color = 'Yellow'

    # Checks if Nest Groups is an object
    if ($ObjNestedDomain -is [object])
        {
        # Checks if Group's Domain SID Matches Parent Domain being queried
        if ($ObjNestedDomain.DomainSID -ne $DomainSID)
            {
            # Queryies Foreign Domain Controller (Local Parent)
            $ObjDCIn = Get-ADDomainController `
                -DomainName $ObjNestedDomain.Domain -Discover `
                -Service ADWS -ForceDiscover

            $GrpScope = 'Foreign Domain'
            $DomainSID = $ObjNestedDomain.domainSID
            }
        # Captures instance of group in Domain
        $ObjGrp = Get-ADObject -LDAPFilter $LDAPFilter `
                        -Server $ObjDCIn.HostName[0] `
                            -Properties $GrpProps  | Select-Object $SelProps
        # Assigns Variable Value
        $NestType = ('Nested Group')
        $ChildGrp = ($ObjGrp.name)

        $StrDashes = '---'
        $Color = 'Green'
        }
    else
        {
        # Captures instance of group in Domain
        $ObjGrp = Get-ADObject -LDAPFilter $LDAPFilter `
                        -Server $ObjDCIn.HostName[0] `
                            -Properties $GrpProps  | Select-Object $SelProps
        
        $NestType = 'Parent Group'
        $Script:ParentGrp = ($ObjGrp.name)
        $ChildGrp = 'n/a'
        }
    
    Write-Host ($StrDashes + ' Querying Privileged ' + $NestType + ' Details: ' + $ObjGrp.Name + ' - ' + $GrpScope) `
                    -ForegroundColor $Color

    # LDAP Filter - Objects
    $LDAPFilter  = "(memberof:1.2.840.113556.1.4.1941:=$($ObjGrp.DistinguishedName))"
    $NestedObjIn = @(Get-ADObject -LDAPFilter $LDAPFilter `
                                    -Server ($ObjDCIn.HostName[0] + ":3268")`
                                    -Properties $NestedGrpProps | `
                                        Select-Object $NestedGrpProps | Sort-Object Objectclass)

    # Assigns Variable Value
    [Int32]$DirUserCnt = 0
    [Int32]$NestedUserCnt = 0
    [Int32]$TotalUniqueCnt = 0
    $TmpUsers = @()

    # LDAP Query
    $LDAPQuery = "(memberof=$($ObjGrp.DistinguishedName))"

    # Queries GC Cycles through forest datatable - Searches AD & counts (user objects) members of privileged group
    $TmpUsers += Get-ADUser -LDAPFilter $LDAPQuery `
                    -Server ($ObjDCIn.HostName[0] + ":3268")

    $DirUserCnt += ($TmpUsers | Measure-Object).count
    $NestedUserCnt += $DirUserCount

    # Queries LDAP - Cycles Through Nested Groups - counts (user objects) members of privileged group
    $NestedGrpsIn = $NestedObjIn | where {$_.objectclass -eq 'group'} 
    Foreach ($NestedGrp in $NestedGrpsIn)
        {
        $TmpUsers += Get-ADUser -LDAPFilter "(memberof:1.2.840.113556.1.4.1941:=$($NestedGrp.DistinguishedName))"  `
                -Server ($DT_DomainSIDs.where({$NestedGrp.objectSID.ToString() `
                            -match $_.DomainSID}).domaincontroller + ":389") 
        }

    $NestedUserCnt += ($TmpUsers | Measure-Object).count
    $TotalUniqueCnt = (($TmpUsers).DistinguishedName | Sort-Object {$_} | Get-Unique | Measure-Object).count

    # Creates Array Variable
    $NestedDetails = @()
    if (($NestedGrpsIn | Measure-Object).count -gt 0)
        {$NestedDetails = Get-NestDNs -ObjIn $NestedGrpsIn}

    # Creates New Datatable Row
    $ObjDTRow_PrivGrps = $DT_ForestPrivGrps.NewRow()

    # Adds Rows and Values to Datatable
    $ObjDTRow_PrivGrps.ReportDate        = ($Date).ToShortDateString()
    $ObjDTRow_PrivGrps.Forest            = $ObjDCIn.Forest
    $ObjDTRow_PrivGrps.Domain            = $ObjDCIn.Domain
    $ObjDTRow_PrivGrps.DomainDN          = [string](Convert-FQDN2DN ($ObjDCIn.Domain))
    $ObjDTRow_PrivGrps.DomainController  = $ObjDCIn.HostName[0]
    $ObjDTRow_PrivGrps.DomainSID         = $DomainSID
    $ObjDTRow_PrivGrps.NestType          = $NestType
    $ObjDTRow_PrivGrps.PrivGrpScope      = $GrpScope
    $ObjDTRow_PrivGrps.ParentGrp         = $ParentGrp
    $ObjDTRow_PrivGrps.ChildGrp          = $ChildGrp
    $ObjDTRow_PrivGrps.PrivGrpName       = $ObjGrp.Name
    $ObjDTRow_PrivGrps.PrivGrpDN         = $ObjGrp.DistinguishedName
    $ObjDTRow_PrivGrps.PrivGrpSID        = $ObjGrp.objectSID.ToString()
    $ObjDTRow_PrivGrps.AdminCount        = $ObjGrp.adminCount
    $ObjDTRow_PrivGrps.InheritanceBroken = $ObjGrp.'$_.nTSecurityDescriptor.AreAccessRulesProtected'
    $ObjDTRow_PrivGrps.NestedGroupCnt    = ($NestedGrpsIn | Measure-Object).count
    $ObjDTRow_PrivGrps.DirectUserCnt     = $DirUserCnt
    $ObjDTRow_PrivGrps.NestedForeignPrinCnt = ($NestedObjIn | where {$_.objectclass -eq 'foreignSecurityPrincipal'} | Measure-Object).count
    $ObjDTRow_PrivGrps.NestedCompCnt        = ($NestedObjIn | where {$_.objectclass -eq 'computer'} | Measure-Object).count
    $ObjDTRow_PrivGrps.NestedGMSACnt        = ($NestedObjIn | where {$_.objectclass -eq 'msDS-GroupManagedServiceAccount'} | Measure-Object).count
    
    $ObjDTRow_PrivGrps.NestedUserCnt      = $NestedUserCnt
    if ($NestedUserCnt -gt 0)
        {$ObjDTRow_PrivGrps.('%UserDups') = (($NestedUserCnt - $TotalUniqueCnt)/$NestedUserCnt).ToString("P")}
    else
        {$ObjDTRow_PrivGrps.('%UserDups') = (0).ToString("P")}
    $ObjDTRow_PrivGrps.UniqueUserCnt = $TotalUniqueCnt
    $ObjDTRow_PrivGrps.NestedGroupsDN    = if ($NestedDetails.Count -eq 0) {"None"} else {$NestedDetails[0]}
    $ObjDTRow_PrivGrps.NestedGroupsName  = if ($NestedDetails.Count -eq 0) {"None"} else {$NestedDetails[1]}
    $DT_ForestPrivGrps.Rows.Add($ObjDTRow_PrivGrps)

    # Iterative export to CSV
    # $ObjDTRow_PrivGrps | Export-Csv $Export -NoTypeInformation -Append

    if ($ObjNestedDomain -isnot [object])
        {Return ,$NestedGrpsIn}
}

Function Build-DataTable {
    [cmdletbinding()]
        Param (
            [Parameter(Mandatory=$True)]
                [String]$StrDTTitleIn,
            [Parameter(Mandatory=$True)]
                [Array]$ArrAttribsIn
            )

    # Creates DataTable
    $ObjDTOut = $Null
    $ObjDTOut = New-Object system.data.datatable $StrDTTitleIn

    # Cycles through & assigns Column-Names to DataTable
    Foreach ($DTColumn in $ArrAttribsIn)
        {
        # Checks and defines custom column & properties - Int32
        if ($DTColumn -eq 'Counter' `
            -or $DTColumn -eq 'NestedCompCnt' `
            -or $DTColumn -eq 'NestedForeignPrinCnt' `
            -or $DTColumn -eq 'NestedGMSACnt' `
            -or $DTColumn -eq 'NestedGroupCnt' `
            -or $DTColumn -eq 'DirectUserCnt' `
            -or $DTColumn -eq 'NestedUserCnt' `
            -or $DTColumn -eq 'UniqueUserCnt')
            {
            $DTColTmp = New-Object System.data.datacolumn $DTColumn,([Int32])
            
            # Custom Int32 - auto incrementing value
            if ($DTColumn -eq 'Counter')
                {
                $DTColTmp.AutoIncrement = $True
                $DTColTmp.AutoIncrementSeed = 1
                $DTColTmp.AutoIncrementStep = 1
                }
            }
        elseif (($DTColumn -eq 'Enabled') -or `
                    ($DTColumn -eq 'PasswordExpired') -or `
                    ($DTColumn -eq 'CannotChangePassword') -or `
                    ($DTColumn -eq 'PasswordNeverExpires') -or `
                    ($DTColumn -eq 'PasswordNotRequired') -or `
                    ($DTColumn -eq 'UAC_PWNotRequired') -or `
                    ($DTColumn -eq 'UAC_PWCantChange') -or `
                    ($DTColumn -eq 'UAC_PWDoesNotExpire') -or `
                    ($DTColumn -eq 'UAC_TrustedForDelegation') -or `
                    ($DTColumn -eq 'UAC_UseDesKeyOnly') -or `
                    ($DTColumn -eq 'CannotChangePassword'))
            {$DTColTmp =  new-object Data.DataColumn $DTColumn,([Boolean])}
        
        elseif (($DTColumn -eq 'UserAccountControl') -or `
                    ($DTColumn -eq 'GroupCount') -or `
                    ($DTColumn -eq 'AdmGrpCnt'))
            {$DTColTmp =  new-object Data.DataColumn $DTColumn,([Int32])}

        elseif (($DTColumn -eq 'whenCreated') -or `
                    ($DTColumn -eq 'whenChanged'))
            {$DTColTmp =  new-object Data.DataColumn $DTColumn,([DateTime])}
        else
            {$DTColTmp = New-Object System.data.datacolumn $DTColumn,([string])}
        
        $ObjDTOut.Columns.Add($DTColTmp) 
        }

    # Returns DataTable
    Return ,$ObjDTOut
}

Function Get-ADForestObjects {
    Param ([Parameter(Mandatory=$False)] [string]$ForestName,
           [Parameter(Mandatory=$False)] [System.Management.Automation.PsCredential]$Credential)

    #if forest variable is not specified, retrieve current forest
    If (!$ForestName)     
        {$ForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name.ToString()}        

    #if Credential specified
    If ($Credential)
        {        
        $credentialUser = $Credential.UserName.ToString()
        $credentialPassword = $Credential.GetNetworkCredential().Password.ToString()
        $ObjForest = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("forest", $ForestName, $credentialUser, $credentialPassword )
        }    
    Else     
        {$ObjForest = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("forest", $ForestName)}        

    Try {
        $ObjForestOut = ([System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ObjForest))
        }

    Catch {Log-Message "Unable to Locate Forest:$ForestName"
            Write-Warning "Unable to Locate Forest - $ForestName"}

    Return $ObjForestOut
}

Function Get-ADForestUsers {
    [cmdletbinding()]
        Param([string]$Forest)

    # Captures Forest Object
    $ObjForest = Get-ADForestObjects -ForestName $Forest

        # Retrieves Attributes for Datatable
        $ArrDTCol = Define-Attributes -IntGrp 0

        # Builds Forest/Domain SIDS Datatable 
        $DT_DomainSIDs = Build-DataTable -StrDTTitleIn 'DomainSIDs' -ArrAttribsIn $ArrDTCol

        # Builds (populates) Forest/Domain SID Datatable
        Build-ForestDomSIDDT -ObjForestIn $ObjForest

        # Retrieves Attributes for Datatable    
        $ArrDTCol = Define-Attributes -IntGrp 1
    
        # Creates Forest Privileged Group Datatable 
        $DT_ForestPrivGrps = Build-DataTable -StrDTTitleIn 'ForestPrivGroups' -ArrAttribsIn $ArrDTCol
    
        # Builds (populates) Forest Privileged Group Datatable 
        Build-ForestPrivGroupDT -ObjForestIn $ObjForest

        # Build Data View for Querying
        $DV_ForestPrivGrps = New-Object System.Data.Dataview($DT_ForestPrivGrps)

        #Write-Debug "Captured All Privileged Groups"

    $ArrDTCol = Define-Attributes -IntGrp 2

    $DT_ADUserObjs = Build-DataTable -StrDTTitleIn "ForestUsers" -ArrAttribsIn $ArrDTCol

    # Initial CSV Output
    $CSVOutFile = ("_" + $Forest + "_ForestPrivilegedUsers_" + "_$StrFileDateSuffix.csv")

    # Joins Export File/Path
    $CSVOut_FullPath = Join-Path $RootExportFolder $CSVOutFile

    # Define Array - Forest DCs Objects
    $ObjPrivUsers = @()

    # Cycle Through List of Forest Domains
    foreach ($ForestPrivGrp in $DV_ForestPrivGrps)
        {
        $StrLDAPFilterOut   = "(&"
        $StrLDAPFilterOut  +=  "(objectClass=user)"
        $StrLDAPFilterOut  +=  "(objectclass=person)"
        $StrLDAPFilterOut  +=  "(Memberof=$($ForestPrivGrp.PrivGrpDN))"
        $StrLDAPFilterOut  += ")"

        if ($SubsetCount -eq 0)
            {$SubsetCount = $Null}

        $ArrADUserObjs = @()

        # Try / Catch Statement
        Try {
            $ArrADUserObjs = Get-ADUser -LDAPFilter $StrLDAPFilterOut `
                                    -Properties SID `
                                    -Server ($ForestPrivGrp.domaincontroller + ":3268") `
                                    -ResultSetSize $SubsetCount `
                                    -ErrorAction Stop
            }
        Catch 
            {Write-Host "Error Connecting to DC:" + [string]$ForestPrivGrp.domaincontroller}

        $ArrADUserObjsOut = @()

        # Try / Catch Statement
        foreach ($ObjUser in $ArrADUserObjs)
            {
            $ArrADUserObjsOut += @(Get-ADUser -LDAPFilter "(DistinguishedName=$($ObjUser.DistinguishedName))" `
                                    -Properties $ADUserAttribs `
                                    -Server ($DT_DomainSIDs.where({$ObjUser.SID.ToString() -match $_.DomainSID}).domaincontroller + ":389") `
                                    -ResultSetSize $SubsetCount)
            }
                                   
        # Checks if query returned objects
        if ($ArrADUserObjsOut -is [object])
            {
            # Cycles through AD User Objects
            $ArrADUserObjsOut | & {
                    process
                        {
                        [User]$MyUser = [User]::New($_)

                        # Clears Error buffer
                        $Global:Error.Clear()

                        # Creates new Data Table Row
                        $ObjDTRow = $DT_ADUserObjs.NewRow()

                        $_ | Select @(@{n='Counter';e={([string]($ObjDTRow.Counter) + " of " + [string]($ArrADUserObjsOut.count))}},
                            @{n='Domain';e={$ObjDC.Domain}}
                            @{n='SamAcctName';e={$_.SamAccountName}})

                        # Populates values to new Datatable Row
                        $ObjDTRow.ReportDate            = ($Date).ToShortDateString()
                        $ObjDTRow.Grp_Forest            = $ForestPrivGrp.Forest
                        $ObjDTRow.Grp_Domain            = $ForestPrivGrp.Domain
                        $ObjDTRow.Grp_NestType          = $ForestPrivGrp.NestType
                        $ObjDTRow.Grp_Scope             = $ForestPrivGrp.PrivGrpScope
                        $ObjDTRow.Grp_Parent            = $ForestPrivGrp.ParentGrp
                        $ObjDTRow.Grp_Child             = $ForestPrivGrp.ChildGrp
                        $ObjDTRow.Grp_DomainDN          = $ForestPrivGrp.DomainDN
                        $ObjDTRow.Grp_DomainController  = $ForestPrivGrp.DomainController
                        $ObjDTRow.Grp_DomainSID         = $ForestPrivGrp.DomainSID
                        $ObjDTRow.Grp_Name              = $ForestPrivGrp.PrivGrpName
                        $ObjDTRow.Grp_DN                = $ForestPrivGrp.PrivGrpDN
                        $ObjDTRow.Grp_SID               = $ForestPrivGrp.PrivGrpSID
                        $ObjDTRow.Grp_AdminCount        = $ForestPrivGrp.AdminCount
                        $ObjDTRow.Grp_InheritanceBroken = $ForestPrivGrp.InheritanceBroken

                        $ObjDTRow.User_Forest           = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).Forest
                        $ObjDTRow.User_Domain           = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).Domain
                        $ObjDTRow.SamAccountName        = $_.SamAccountName
                        $ObjDTRow.DisplayName           = $_.DisplayName
                        $ObjDTRow.Enabled               = $_.enabled
                        $ObjDTRow.Expired               = $MyUser.Expired
                        $ObjDTRow.ExpireStatus          = $MyUser.ExpireStatus
                        $ObjDTRow.ExpireDate            = $MyUser.ExpireDate

                        if ($_.AccountExpirationDate -is [object])
                            {
                            $ObjDTRow.ExpirationDate  = $_.AccountExpirationDate.ToShortDateString()
                            $ObjDTRow.ExpirationDays  = $MyUser.GetDateDiff($_.AccountExpirationDate, $Date)
                            }
                        else
                            {$ObjDTRow.ExpirationDate  = $Null ; $ObjDTRow.ExpirationDays  = $Null}

                        $ObjDTRow.AccountExpires   = $_.accountExpires
                        
                        if (![string]::isnullorempty($MyUser.lastLogonDate))
                            {$ObjDTRow.LastLogonDaysAgo   = $MyUser.GetDateDiff($MyUser.lastLogonDate, $Date)}
                        $ObjDTRow.LastLogonTimestamp   = $MyUser.lastLogonTimestamp
                        $ObjDTRow.LastLogonDate        = $MyUser.lastLogonDate
                        $ObjDTRow.LogonCount           = $_.logonCount

                        $ObjDTRow.UserPrincipalName    = $_.UserPrincipalName
                        $ObjDTRow.CanonicalName        = $_.CanonicalName
                        $ObjDTRow.Department           = $_.Department
                        $ObjDTRow.Description          = $_.Description
                        $ObjDTRow.Division             = $_.Division
                        $ObjDTRow.ETypes               = $MyUser.ETypes
                        $ObjDTRow.EmailAddress         = $_.EmailAddress
                        $ObjDTRow.mail                 = $_.mail
                        $ObjDTRow.adminCount           = $_.adminCount
                        $ObjDTRow.adminDescription     = $_.adminDescription
                        $ObjDTRow.ProxySMTPAddr        = $MyUser.SMTPProxyAddr
                        $ObjDTRow.ProxySIPAddr         = $MyUser.SIPProxyAddr
                        $ObjDTRow.MemberOf             = $MyUser.MemberOf
                        $ObjDTRow.GroupCount           = $MyUser.GroupCount
                        
                        [Int32]$AdmGrpCnt = 0
                        $MyUser.ArrMemberof | foreach {
                                $DV_ForestPrivGrps.RowFilter = "PrivGrpDN = '$_'"
                                if ($DV_ForestPrivGrps.count -gt 0)
                                    {$AdmGrpCnt++}}

                        $ObjDTRow.AdmGrpCnt             = $AdmGrpCnt
                        $ObjDTRow.Organization          = $_.Organization


                        $ObjDTRow.pwdExpired             = $_.PasswordExpired
                        $ObjDTRow.pwdLastSet             = $_.PasswordLastSet
                        if (![string]::isnullorempty($_.PasswordLastSet))
                            {$ObjDTRow.pwdLastSetDaysAgo = $MyUser.GetDateDiff($_.PasswordLastSet, $Date)}
                        $ObjDTRow.pwdLastSet            = $_.pwdLastSet
                        $ObjDTRow.CannotChangePwd       = $_.CannotChangePassword
                        $ObjDTRow.pwdNotRequired        = $_.PasswordNotRequired
                        $ObjDTRow.pwdNeverExpires       = $_.PasswordNeverExpires
                        
                        $ObjDTRow.SIDHistory            = ($_.SIDHistory | Measure-Object).count
                        $ObjDTRow.UserAccountControl    = $_.UserAccountControl
                        
                        $ObjDTRow.UAC_PWNotRequired         = $MyUser.PWNotRequired
                        $ObjDTRow.UAC_PWCantChange          = $MyUser.PWCantChange
                        $ObjDTRow.UAC_PWDoesNotExpire       = $MyUser.PWDoesNotExpire
                        $ObjDTRow.UAC_TrustedForDelegation  = $MyUser.TrustedForDelegation
                        $ObjDTRow.UAC_UseDesKeyOnly         = $MyUser.UseDesKeyOnly

                        
                        $ObjDTRow.whenChanged           = $_.whenChanged.toshortdatestring()
                        $ObjDTRow.whenCreatedDays       = $MyUser.GetDateDiff($_.whenCreated, $Date)
                        $ObjDTRow.whenCreated           = $_.whenCreated.toshortdatestring()
                        
                        $ObjDTRow.DistinguishedName     = $_.DistinguishedName

                        $Stale = $Null
                        if (($ObjDTRow.Enabled) -and ($BolFilter))
                            {
                            if ([string]::IsNullOrEmpty($ObjDTRow.LastLogonDays))
                                {
                                if ([int32]($ObjDTRow.whenCreatedDays) -ge $Days)
                                    {$Stale = "Stale - Enabled & LastLogon Blank & WhenCreated > $Days Days"}
                                }
                            elseif ([Int32]($ObjDTRow.LastLogonDays) -ge $Days)
                                {$Stale = "Stale - Enabled & LastLogon > $Days Days"}
                            }
                                
                        $ObjDTRow.Stale                 = $Stale

                        $ObjDTRow | Export-Csv $CSVOut_FullPath -NoTypeInformation -Append
                        #Write-Debug "Pausing"
                        $ObjDTRow = $Null
                        $MyUser = $Null
                        }
                    }
        }
    }
    $DT_DomainSIDs = $Null
    $DT_ForestPrivGrps = $Null
}

# Generates File Date Suffix - e.g. 2020-8-23-23-49
$StrFileDateSuffix = "{0}-{1}-{2}-{3}-{4}" `
            -f $Date.year, $Date.month, $Date.Day, `
                $Date.Minute, $Date.Second

# Generates Export Path
$RootExportFolder =  $env:TEMP

#$RootExportFolder = Join-Path $RootDrive $RootFolder
$RootExportFolder = ("S:\UserData\ShawnMay\{0}{1}{2} - Data" -f $Date.month, $Date.Day, $Date.Year)

# Validate / Create Export Folder Structure
Validate-Folder $RootExportFolder

$ArrForests = @()
$ArrForests += 'dco.net'
#$ArrForests += 'blackbaud.net'
#$ArrForests += 'blackbaudhost.com'
#$ArrForests += 'production.local'
$ArrForests | Foreach {Get-ADForestUsers $_ -debug}

$DT_ADUserObjs = $Null
