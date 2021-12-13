[cmdletbinding()]
    Param (
            [Parameter(Mandatory=$False,
                        HelpMessage="Provide Forest Name(s)")]
                            [Array]$Forests,

            [Parameter(Mandatory=$False,
                        HelpMessage="Export Privileged Group(s)")]
                            [Switch]$ExportGroups,

            [Parameter(Mandatory=$False,
                        HelpMessage="File Export Path")]
                            [String]$AltExportPath = $Null
            )

    <#
    .Synopsis
        Script combs through a forest and collects detailed privileged groups and principals.

    .Description
        Script systematically combs through an AD forest and all domains to collect
            a. privileged groups
            b. privileged users
    
        Script Steps:
            1. Cycles through and captures all Forest Domains.
                - Forest
                - Domain
                - Domain SID
                - Domain Controller
                - Domain Distinguished Name (DN)

            2. Cycles through each forest domain and captures privileged & nest groups
                - Group Nest Type: Parent or Nested Group
                - Group Scope: Local Domain or Foreign Domain (e.g. nested from another domain)
                - Group | Parent Domain & Group Name
                - Group | Child Domain & Group Name
                - Group | Interitance Broken
                - Group Member:
                    - Computer Counts Only
                    - Foreign Principals Counts Only
                    - Group Managed Service Accounts (GMSA) Counts Only
                    - Nest Group Counts Only
                    - Direct & Nested Users Counts Only
                        - Percentage of User Duplicates
                - Group | Nested Group DNs and Display Names
                - Optional Output to file

            3. Cycles through each privileged & nested group
            3a. Queries each forest domain to obtain detailed user info
            3b. Exports Detailed Privileged Group and User Information to File (note: all attributes not included)
                - Group Details (see above)
                - User | Forest
                - User | Domain
                - User | Scope - i.e. whether user domain is local or foreign to privileged group
                - User | Expiration Details (custom code to include expired X days ago)
                - User | Enabled/Disabled
                - User | Last Logon (custom code to include logon on X days ago)
                - User | Kerberos Encryption Types
                - User | Memberof Groups
                - User | Privileged Group Count
                - User | Password Details
                - User | User Account Control (UAC) Details

            Default CSV Output: $env:TEMP\MMddyy-Data
            Example CSV Output: C:\Users\Shawn.May\AppData\Local\Temp\120321-Data

    .Notes:
        File Name: Get-ADPrivUser-Details.ps1
        Author   : Shawn May
        Email    : shawn@yourdts.com
        Requires : Powershell V3 or greater
        Version  : 1.0


    .PARAMETER Forests
        Optional: Specify list of Forests to query. If empty, queryies local forest

    .PARAMETER ExportGroups
        Optional: Specify whether to export privileged groups
        
    .PARAMETER AltExportPath
        Optional: Specify alternate CSV Output path

    .EXAMPLE
        .\Get-ADPrivUser-Details.ps1 -Forests acme.com, warnerbro.com

    .EXAMPLE
        .\Get-ADPrivUser-Details.ps1 -ExportGroups

    .EXAMPLE
        .\Get-ADPrivUser-Details.ps1 -AltExportPath 'C:\temp\Output'
    #>

    # Clears Host
    Clear-Host

    # Acquires Date
    $Date = Get-Date

    # Generates File Date Suffix - e.g. 2020-8-23-23-49
    $StrFileDateSuffix = "{0}-{1}-{2}-{3}-{4}" `
                -f $Date.year, $Date.month, $Date.Day, `
                    $Date.Minute, $Date.Second

    # Generates Export Path
    $RootExportFolder = Join-Path $env:TEMP ((Get-Date -format "MMddyy") + "-Data")

    # Checks Export path parameter was passed to Script
    if (![string]::IsNullOrEmpty($AltExportPath))
        {
        # Replaces variable with alternate export path
        $RootExportFolder = $AltExportPath
        }

    # Checks if export path exists
    if ((Test-Path $RootExportFolder) -eq $False)
        {
        # Try | Catch Statement
        Try {$a = New-Item -ItemType directory -Path $RootExportFolder -ErrorAction Stop}
        Catch {Write-Host "Specified Drive and/or Folder does not exist." `
            -ForegroundColor Yellow ; exit}
        }

# User Class
Class User {
    # Defines Class object attributes
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

    # Translates Kerb Encryption Type
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

    # Checks whether object is a critical system objects
    SetCriticalFlag([Bool]$IsCriticalIn)
        {
        if ($IsCriticalIn -is [object])
            {$this.IsCriticalSystemObject = $IsCriticalIn}
        else
            {$this.IsCriticalSystemObject = [DBNull]::Value}
        }

    # Translates Account Expiration Details
    GetADExpiration([Int64]$ExpirationIn)
        {
        # Populates Date Attribute
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

    # Translates Proxy Addresses
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

    # Translates Last Logon Details
    DecodeLastLogon($LastLogonTimeStampIn,$LastLogonDateIn)
        {
        # Checks if object
        if ($LastLogonTimeStampIn -is [object])
            {$this.LastLogonTimeStamp = [datetime]::FromFileTime($LastLogonTimeStampIn).toshortdatestring()}
        else
            {$this.LastLogonTimeStamp = $Null}

        # Checks if object
        if ($LastLogonDateIn -is [object])
            {$this.LastLogonDate = ($LastLogonDateIn).toshortdatestring()}
        else
            {$this.LastLogonDate = $Null}
        }

    # Captures MemberOf  Details
    GetMemberOf($MemberofIn)
        {
        # Cycles through array
        foreach ($Member in $MemberofIn)
            {
            # Checks if object is null or empty
            if ([string]::IsNullOrEmpty($this.Memberof))
                {$this.Memberof = $Member}
            else
                {$this.Memberof += ("`n" + $Member)}
            }
        # Measure Object Count
        $this.GroupCount = ($MemberofIn | Measure-Object).count

        # Assigns Values
        $MemberofIn | foreach {$this.ArrMemberof += @($_)}
        }

    # Translates UAC Details
    DecodeUAC($UserAccountControl)
        {
        $this.PWNotRequired = (($UserAccountControl -band 32) -eq 32)
        $this.PWCantChange = (($UserAccountControl -band 64) -eq 64)
        $this.PWDoesNotExpire = (($UserAccountControl -band 65536) -eq 65536)
        $this.TrustedForDelegation = (($UserAccountControl -band 524288) -eq 524288)
        $this.UseDesKeyOnly = (($UserAccountControl -band 2097152) -eq 2097152)
        }

    # Calculates time span
    [Int32]GetDateDiff([datetime]$DateIn, [datetime]$today)
        {Return (New-TimeSpan -Start $DateIn -End $today).Days}
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

# Function | Populates Forest Domains Datatable
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

# Function | Populates Forest Privileged Group Datatable
Function Build-ForestPrivGroupDT {
    [cmdletbinding()]
        Param($ObjForestIn)

    # Privileged Group Membership for the following groups:
    # Reference: http://support.microsoft.com/kb/243330

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

    if ($ExportGroups)
        {
        # GPO Full Report CSV File Name
        $CSVGrpFileName = ("_" + $ObjForestIn.name + "_Forest_PrivGroups_" + $StrFileDateSuffix + ".csv" `
                -f $Date.year, $Date.month, $Date.Day).ToUpper()

        # Join Path to create Export Variable
        $Export = Join-Path $RootExportFolder $CSVGrpFileName
    
        # Exports Datatable to CSV
        $DT_ForestPrivGrps | Export-Csv $Export -NoTypeInformation

        # Post Script: Writes Output to Screen
        $script:ArrOutputCSVs += @("Forest Groups:$($ObjForestIn.Rootdomain) | Output CSV File: $Export")
        }
    }

# Captures DNs
Function Get-NestDNs {
    [cmdletbinding()]
        Param($ObjIn)

    # Cycles through DNs
    foreach ($DN in $ObjIn)
        {
        # Checks if variables are empty
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

# Function Defines AD & Data Table Attributes    
Function Define-Attributes {
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
    $Script:ADUserAttribs += @('ObjectGUID')
    $Script:ADUserAttribs += @('PasswordLastSet','pwdLastSet')
    $Script:ADUserAttribs += @('PasswordExpired')
    $Script:ADUserAttribs += @('CannotChangePassword')
    $Script:ADUserAttribs += @('PasswordNeverExpires','PasswordNotRequired')
    $Script:ADUserAttribs += @('SamAccountName','ScriptPath')
    $Script:ADUserAttribs += @('SID')
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
                $ArrDTCols += @('Grp_NestType')
                $ArrDTCols += @('Grp_Scope')
                $ArrDTCols += @('Grp_Name')
                $ArrDTCols += @('AD_Forest')
                $ArrDTCols += @('Grp_Parent_Domain')
                $ArrDTCols += @('Grp_Parent')
                $ArrDTCols += @('Grp_Child_Domain')
                $ArrDTCols += @('Grp_Child')
                $ArrDTCols += @('AD_DC')
                $ArrDTCols += @('AD_DomainDN')
                $ArrDTCols += @('AD_DomainSID')
                $ArrDTCols += @('Grp_DN')
                $ArrDTCols += @('Grp_SID')
                $ArrDTCols += @('Grp_AdminCount')
                $ArrDTCols += @('Grp_InheritanceBroken')
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
                $ArrDTCols += @('Grp_NestType')
                $ArrDTCols += @('Grp_Scope')
                $ArrDTCols += @('Grp_Name')
                $ArrDTCols += @('AD_Forest')
                $ArrDTCols += @('Grp_Parent_Domain')
                $ArrDTCols += @('Grp_Parent')
                $ArrDTCols += @('Grp_Child_Domain')
                $ArrDTCols += @('Grp_Child')
                $ArrDTCols += @('AD_DC')
                $ArrDTCols += @('AD_DomainDN')
                $ArrDTCols += @('AD_DomainSID')
                $ArrDTCols += @('Grp_DN')
                $ArrDTCols += @('Grp_SID')
                $ArrDTCols += @('Grp_AdminCount')
                $ArrDTCols += @('Grp_InheritanceBroken')
		$ArrDTCols += @('Stale')
                $ArrDTCols += @('User_Forest')
                $ArrDTCols += @('User_Domain')
                $ArrDTCols += @('User_Scope')
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
                $ArrDTCols += @('MemberOf','GroupCount','PrivGrpCnt','Organization')
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

# Function cycles through and writes privileged group details to Data Table
Function Write-toTable {
    [cmdletbinding()]
        Param($ObjDCIn, $StrSIDIn)

    # Clears Errors
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

        $DomChildGrp = $ObjDCIn.domain
        $ChildGrp = $ObjGrp.name

        $StrDashes = '---'
        $Color = 'Green'
        }
    else
        {
        # Captures instance of group in Domain
        $ObjGrp = Get-ADObject -LDAPFilter $LDAPFilter `
                        -Server $ObjDCIn.HostName[0] `
                            -Properties $GrpProps  | Select-Object $SelProps
        
        # Populates variables
        $NestType = 'Parent Group'
        $Script:DomParentGrp = $ObjDCIn.domain
        $Script:ParentGrp = $ObjGrp.name
        $DomChildGrp = 'n/a'
        $ChildGrp = 'n/a'
        }
    
    # Writes output to screen
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

    # Measure User Count
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
    $ObjDTRow_PrivGrps.ReportDate            = ($Date).ToShortDateString()
    $ObjDTRow_PrivGrps.Grp_NestType          = $NestType
    $ObjDTRow_PrivGrps.Grp_Scope             = $GrpScope
    $ObjDTRow_PrivGrps.Grp_Name              = $ObjGrp.Name
    $ObjDTRow_PrivGrps.AD_Forest             = $ObjDCIn.Forest
    $ObjDTRow_PrivGrps.Grp_Parent_Domain     = $DomParentGrp
    $ObjDTRow_PrivGrps.Grp_Parent            = $ParentGrp
    $ObjDTRow_PrivGrps.Grp_Child_Domain      = $DomChildGrp
    $ObjDTRow_PrivGrps.Grp_Child             = $ChildGrp
    $ObjDTRow_PrivGrps.AD_DC                 = $ObjDCIn.HostName[0]
    $ObjDTRow_PrivGrps.AD_DomainDN           = [string](Convert-FQDN2DN ($ObjDCIn.Domain))
    $ObjDTRow_PrivGrps.AD_DomainSID          = $DomainSID
    $ObjDTRow_PrivGrps.Grp_DN                = $ObjGrp.DistinguishedName
    $ObjDTRow_PrivGrps.Grp_SID               = $ObjGrp.objectSID.ToString()
    $ObjDTRow_PrivGrps.Grp_AdminCount        = $ObjGrp.adminCount
    $ObjDTRow_PrivGrps.Grp_InheritanceBroken = $ObjGrp.'$_.nTSecurityDescriptor.AreAccessRulesProtected'
    $ObjDTRow_PrivGrps.NestedGroupCnt        = ($NestedGrpsIn | Measure-Object).count
    $ObjDTRow_PrivGrps.DirectUserCnt         = $DirUserCnt
    $ObjDTRow_PrivGrps.NestedForeignPrinCnt  = ($NestedObjIn | where {$_.objectclass -eq 'foreignSecurityPrincipal'} | Measure-Object).count
    $ObjDTRow_PrivGrps.NestedCompCnt         = ($NestedObjIn | where {$_.objectclass -eq 'computer'} | Measure-Object).count
    $ObjDTRow_PrivGrps.NestedGMSACnt         = ($NestedObjIn | where {$_.objectclass -eq 'msDS-GroupManagedServiceAccount'} | Measure-Object).count
    $ObjDTRow_PrivGrps.NestedUserCnt         = $NestedUserCnt
    if ($NestedUserCnt -gt 0)
        {$ObjDTRow_PrivGrps.('%UserDups')    = (($NestedUserCnt - $TotalUniqueCnt)/$NestedUserCnt).ToString("P")}
    else
        {$ObjDTRow_PrivGrps.('%UserDups')    = (0).ToString("P")}
    $ObjDTRow_PrivGrps.UniqueUserCnt         = $TotalUniqueCnt
    $ObjDTRow_PrivGrps.NestedGroupsDN        = if ($NestedDetails.Count -eq 0) {"None"} else {$NestedDetails[0]}
    $ObjDTRow_PrivGrps.NestedGroupsName      = if ($NestedDetails.Count -eq 0) {"None"} else {$NestedDetails[1]}
    $DT_ForestPrivGrps.Rows.Add($ObjDTRow_PrivGrps)

    if ($ObjNestedDomain -isnot [object])
        {Return ,$NestedGrpsIn}
}

# Function builds Datatable
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
                    ($DTColumn -eq 'PrivGrpCnt'))
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

# Function Captures Forest Object
Function Get-ADForestObjects {
    Param ([Parameter(Mandatory=$False)] [string]$ForestNameIn)

    $StrError = "Unable to Locate Forest - $ForestNameIn `n`Exiting Script"

    #if forest variable is not specified, retrieve current forest
    If (!$ForestNameIn)     
        {
        Try {$ObjForestOut = Get-ADForest}
        Catch {Write-Warning $StrError}
        }
    else
        {
        Try {$ObjForestOut = Get-ADForest -Server $ForestNameIn}
        Catch {Write-Warning $StrError}
        }
    Return $ObjForestOut
}

# Function obtains user privileged group
Function Get-ADPrivUsers {
    [cmdletbinding()]
        Param([string]$ForestIn)
    
    # Clears Host
    Clear-Host

    # Captures Forest Object
    $ObjForest = Get-ADForestObjects -ForestName $ForestIn

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

    # Retrieves Attributes for Datatable
    $ArrDTCol = Define-Attributes -IntGrp 2

    # Builds User Datatable
    $DT_ADUserObjs = Build-DataTable -StrDTTitleIn "ForestUsers" -ArrAttribsIn $ArrDTCol

    #################################
    # GPO Full Report CSV File Name
        $CSVFileName = ("_" + $ObjForest.rootDomain + "_Forest_PrivUsers_" + $StrFileDateSuffix + ".csv").ToUpper()
        $Export = Join-Path $RootExportFolder $CSVFileName

    # Cycle Through Forest Privilaged Groups (i.e. Data Table)
    foreach ($ForestPrivGrp in $DV_ForestPrivGrps)
        {

        # Builds LDAP Query - Filters for:
        # - User Objects
        # - MemberOf attribute Contains Privileged Group DN
        $StrLDAPFilterOut   = "(&"
        $StrLDAPFilterOut  +=  "(objectClass=user)"
        $StrLDAPFilterOut  +=  "(objectclass=person)"
        $StrLDAPFilterOut  +=  "(Memberof=$($ForestPrivGrp.Grp_DN))"
        $StrLDAPFilterOut  += ")"

        if ($SubsetCount -eq 0)
            {$SubsetCount = $Null}

        # Create Temporary Array Variable - Forest Privileged Users
        $ArrADUserObjs = @()

        # Properties Array
        $TmpADUserAttribs = @()
        $TmpADUserAttribs += @('SID')
        $TmpADUserAttribs += @('DistinguishedName')

        # Try / Catch Statement
        Try {
            # Query 1 of 2 - Initial forest wide query (first pass to obtain limited user details)
            #  - Privileged Users' SID & DistinguishedName
            $ForestADUserObjs = Get-ADUser -LDAPFilter $StrLDAPFilterOut `
                                            -Properties $TmpADUserAttribs `
                                            -Server ($ForestPrivGrp.AD_DC + ":3268") `
                                            -ResultSetSize $SubsetCount -ErrorAction Stop `
                                                | Select-Object $TmpADUserAttribs
                                    
            }
        Catch 
            {# Throws Error
            Write-Host "Error Connecting to DC:" $ForestPrivGrp.AD_DC -ForegroundColor Red
            }

        # Select Array
        $GrpSelect = @()
        $GrpSelect += @{n='Grp_NestType'         ; e={$ForestPrivGrp.Grp_NestType} }
        $GrpSelect += @{n='Grp_Scope'            ; e={$ForestPrivGrp.Grp_Scope} }
        $GrpSelect += @{n='Grp_Name'             ; e={$ForestPrivGrp.Grp_Name} }
        $GrpSelect += @{n='AD_Forest'            ; e={$ForestPrivGrp.AD_Forest} }
        $GrpSelect += @{n='Grp_Parent_Domain'    ; e={$ForestPrivGrp.Grp_Parent_Domain} }
        $GrpSelect += @{n='Grp_Parent'           ; e={$ForestPrivGrp.Grp_Parent} }
        $GrpSelect += @{n='Grp_Child_Domain'     ; e={$ForestPrivGrp.Grp_Child_Domain} }
        $GrpSelect += @{n='Grp_Child'            ; e={$ForestPrivGrp.Grp_Child} }
        $GrpSelect += @{n='AD_DC'                ; e={$ForestPrivGrp.AD_DC} }
        $GrpSelect += @{n='AD_DomainDN'          ; e={$ForestPrivGrp.AD_DomainDN} }
        $GrpSelect += @{n='AD_DomainSID'         ; e={$ForestPrivGrp.AD_DomainSID} }
        $GrpSelect += @{n='Grp_DN'               ; e={$ForestPrivGrp.Grp_DN} }
        $GrpSelect += @{n='Grp_SID'              ; e={$ForestPrivGrp.Grp_SID} }
        $GrpSelect += @{n='Grp_AdminCount'       ; e={$ForestPrivGrp.Grp_AdminCount} }
        $GrpSelect += @{n='Grp_InheritanceBroken'; e={$ForestPrivGrp.InheritanceBroken} }
        $GrpSelect += $ADUserAttribs # appends Previously defined user attributes.

        # Creates Array Variable - Forest Privileged Users
        if ($ArrADUserObjsOut -isnot [object])
            {
            # Create new array variable
            $ArrADUserObjsOut = @()
            }

        # Try / Catch Statement
        foreach ($ObjUser in $ForestADUserObjs)
            {
            # Queryies Domain Datatable for User's home domain DC
            $PrefDC = ($DT_DomainSIDs.where({$ObjUser.SID.ToString() -match $_.DomainSID}).domaincontroller + ":389")
            
            # Builds LDAP Query - Filters for specific users
            $StrLDAPFilterOut = "(DistinguishedName=$($ObjUser.DistinguishedName))"

            # Query 2 of 2 - Domain query - Specific Privileged Users Details
            $ArrADUserObjsOut += @(Get-ADUser -LDAPFilter $StrLDAPFilterOut `
                                    -Properties $ADUserAttribs `
                                    -Server $PrefDC `
                                    -ResultSetSize $SubsetCount | `
                                        Select-Object $GrpSelect)
            }
        }
                                   
    # Checks if query returned objects
    if ($ArrADUserObjsOut -is [object])
        {
        # Cycles through AD User Objects
        $ArrADUserObjsOut | & `
                {
                process
                    {
                        # Clears Error buffer
                        $Global:Error.Clear()

                        # Generates User Class Object
                        [User]$MyUser = [User]::New($_)

                        # Queryies Domain Data Table for User Forest & Domain
                        $TmpUserForest = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).Forest
                        $TmpUserDomain = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).Domain

                        $UserScope = 'Local to Group'
                        if ($_.Grp_Child_Domain -eq 'n/a')
                            {if ($_.Grp_Parent_Domain -ne $TmpUserDomain) {$UserScope = 'Foreign to Group'}}
                        elseif ($_.Grp_Child_Domain -ne $TmpUserDomain) {$UserScope = 'Foreign to Group'}

                        # Creates new Data Table Row
                        $ObjDTRow = $DT_ADUserObjs.NewRow()

                        # Populates group details/values to Datatable Row
                        $ObjDTRow.ReportDate            = ($Date).ToShortDateString()
                        $ObjDTRow.Grp_NestType          = $_.Grp_NestType
                        $ObjDTRow.Grp_Scope             = $_.Grp_Scope
                        $ObjDTRow.Grp_Name              = $_.Grp_Name
                        $ObjDTRow.AD_Forest             = $_.AD_Forest
                        $ObjDTRow.Grp_Parent_Domain     = $_.Grp_Parent_Domain
                        $ObjDTRow.Grp_Parent            = $_.Grp_Parent
                        $ObjDTRow.Grp_Child_Domain      = $_.Grp_Child_Domain
                        $ObjDTRow.Grp_Child             = $_.Grp_Child 
                        $ObjDTRow.AD_DC                 = $_.AD_DC
                        $ObjDTRow.AD_DomainDN           = $_.AD_DomainDN
                        $ObjDTRow.AD_DomainSID          = $_.AD_DomainSID
                        $ObjDTRow.Grp_DN                = $_.Grp_DN
                        $ObjDTRow.Grp_SID               = $_.Grp_SID
                        $ObjDTRow.Grp_AdminCount        = $_.Grp_AdminCount
                        $ObjDTRow.Grp_InheritanceBroken = $_.Grp_InheritanceBroken

                        # Populates user details/values to Datatable Row
                        $ObjDTRow.User_Forest           = $TmpUserForest
                        $ObjDTRow.User_Domain           = $TmpUserDomain
                        $ObjDTRow.User_Scope            = $UserScope
                        $ObjDTRow.IsCriticalSystemObject= $MyUser.IsCriticalSystemObject
                        $ObjDTRow.SamAccountName        = $_.SamAccountName
                        $ObjDTRow.DisplayName           = $_.DisplayName
                        $ObjDTRow.Enabled               = $_.enabled
                        $ObjDTRow.Expired               = $MyUser.Expired
                        $ObjDTRow.ExpireStatus          = $MyUser.ExpireStatus
                        $ObjDTRow.ExpireDate            = $MyUser.ExpireDate

                        # Calculates Account Expiration Details
                        if ($_.AccountExpirationDate -is [object])
                            {
                            $ObjDTRow.ExpirationDate    = $_.AccountExpirationDate.ToShortDateString()
                            $ObjDTRow.ExpirationDays    = $MyUser.GetDateDiff($_.AccountExpirationDate, $Date)
                            }
                        else
                            {$ObjDTRow.ExpirationDate   = $Null ; $ObjDTRow.ExpirationDays  = $Null}

                        $ObjDTRow.AccountExpires   = $_.accountExpires
                        
                        # Calculates number of days ago the user logged on
                        if (![string]::isnullorempty($MyUser.lastLogonDate))
                            {$ObjDTRow.LastLogonDaysAgo = $MyUser.GetDateDiff($MyUser.lastLogonDate, $Date)}

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
                        
                        # Cycles through memberof - counts number of privileged groups
                        [Int32]$PrivGrpCnt = 0
                        $MyUser.ArrMemberof | foreach {
                                $DV_ForestPrivGrps.RowFilter = "Grp_DN = '$_'"
                                if ($DV_ForestPrivGrps.count -gt 0)
                                    {$PrivGrpCnt++}}

                        $ObjDTRow.PrivGrpCnt                = $PrivGrpCnt
                        $ObjDTRow.Organization              = $_.Organization
                        $ObjDTRow.pwdExpired                = $_.PasswordExpired
                        $ObjDTRow.pwdLastSet                = $_.PasswordLastSet
                        
                        if (![string]::isnullorempty($_.PasswordLastSet))
                            {$ObjDTRow.pwdLastSetDaysAgo    = $MyUser.GetDateDiff($_.PasswordLastSet, $Date)}

                        $ObjDTRow.pwdLastSet                = $_.pwdLastSet
                        $ObjDTRow.CannotChangePwd           = $_.CannotChangePassword
                        $ObjDTRow.pwdNotRequired            = $_.PasswordNotRequired
                        $ObjDTRow.pwdNeverExpires           = $_.PasswordNeverExpires
                        
                        $ObjDTRow.SIDHistory                = ($_.SIDHistory | Measure-Object).count
                        $ObjDTRow.UserAccountControl        = $_.UserAccountControl
                        
                        $ObjDTRow.UAC_PWNotRequired         = $MyUser.PWNotRequired
                        $ObjDTRow.UAC_PWCantChange          = $MyUser.PWCantChange
                        $ObjDTRow.UAC_PWDoesNotExpire       = $MyUser.PWDoesNotExpire
                        $ObjDTRow.UAC_TrustedForDelegation  = $MyUser.TrustedForDelegation
                        $ObjDTRow.UAC_UseDesKeyOnly         = $MyUser.UseDesKeyOnly
                        $ObjDTRow.whenChanged               = $_.whenChanged.toshortdatestring()
                        $ObjDTRow.whenCreatedDays           = $MyUser.GetDateDiff($_.whenCreated, $Date)
                        $ObjDTRow.whenCreated               = $_.whenCreated.toshortdatestring()
                        $ObjDTRow.DistinguishedName         = $_.DistinguishedName

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

                        # Hash Table
                        $TempdataOut = [ordered]@{}
                        $TempdataOut += @{'#'=([string]($ObjDTRow.Counter) + " of " + [string]($ArrADUserObjsOut.count))}
                        $TempdataOut += @{'Forest' = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).Forest}
                        $TempdataOut += @{'Domain' = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).Domain}
                        $TempdataOut += @{'Domain Conroller' = $DT_DomainSIDs.where({$MyUser.UserSID -match $_.DomainSID}).DomainController}
                        $TempdataOut += @{'SamAcctName' = $_.SamAccountName}
                        $TempdataOut += @{'User Scope' = $UserScope}

                        # Writes Hash Table to Screen Output
                        Write-Output (New-Object -TypeName PSObject -Property $TempdataOut)

                        $ObjDTRow | Export-Csv $Export -NoTypeInformation -Append
                        
                        $ObjDTRow = $Null
                        $MyUser = $Null
                        }
                }

        # Post Script: Writes Output to Screen
        $script:ArrOutputCSVs += @("Forest Users:$($ObjForest.Rootdomain) | Output CSV File: $Export")
        }
    
    # Nulls Datatables
    $DT_DomainSIDs = $Null
    $DT_ForestPrivGrps = $Null
    $DT_ADUserObjs = $Null
}

    # Creates Arrau Variable
    $Script:ArrOutputCSVs = @()

    # Cycles through Forest Array
    $Forests | Foreach {Get-ADPrivUsers $_}

    # Cycles through text output
    Foreach ($StrOutput in $ArrOutputCSVs)
        {
        Write-Host "-------------------------"
        Write-Host $StrOutput `n
        }
