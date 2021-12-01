<#
.Synopsis
    Script pulls list of forest/domain GPO and identifies their differing statuses.

.Description
    Script provides high level details concerning Domain GPO details. User/Computer node status,
    whether nodes are populated with settings, VAS information, linked OUs, etc.

    The “GPO Detail” script has been updated with additional elements providing nearly
    all details needed to determine whether a GPO could stay or perhaps be removed:
        - GPO Status – Computer / User settings are enabled / disabled
        - GPT Check – Checks the GPO version is in Sync
        - GPO Computer Settings Populated - True/False
        - GPO User Settings Populated - True/False
        - GPO VAS/QAS Computer Settings Populated - True/False
        - GPO VAS/QAS User Settings Populated - True/False
        - Number of Links to Domain, OU and/or sites
        - Count of both user & computer objects within and beneath the OU
        - GPO Link Status (enabled/disabled)
        - GPO Link Enforcement Status
        - GPO Link Block Inheritance
        - GPO WMI Filters
        - GPO Security Settings (Kerberos Encryption Types & LM Compatibility Level)

    Script writes output the screen:
        - GPO Link Count
        - GPO Display Name
        - GPO CN
        - GPO DN
        - Linked Object Class (e.g. OU, Site, etc.)
        - Linked Name (simple name)
        - Linked DN
        - InScope User Count
        - InScope Computer Count

.Notes:
    File Name: Get-ADGPO-Details.ps1
    Author   : Shawn May
    Email    : shawn@yourdts.com
    Requires : Powershell V3 or greater
    Version  : 2.5

.PARAMETER Forests
    Specify a list of Forests to query. If empty, queries local (home) forest
        
.PARAMETER GPONameFilter
    Specify List of GPOs to Gather Details on

.PARAMETER ExportPath
    Specify an alternate output path for CSV

.EXAMPLE
    .\Get-ADGPO-Details.ps1 -GPONameFilter "ACME GPO - Workstation Settings"

.EXAMPLE
    .\Get-ADGPO-Details.ps1 -Forests 'acme.com'

.EXAMPLE
    .\Get-ADGPO-Details.ps1 -ExportPath 'C:\temp\Output'
#>
[cmdletbinding()]
    Param (
            [Parameter(Mandatory=$False,
                        HelpMessage="Provide Forest Name(s)")]
                        [Array]$Forests,

            [Parameter(Mandatory=$False,
                        HelpMessage="Provide GPO Name")]
                        [String]$GPONameFilter,

            [Parameter(Mandatory=$False,
                        HelpMessage="File Export Path")]
                        [String]$ExportPath = $Null
            )

    # Clears Host
    Clear-Host

    # Acquires Date
    $Date = Get-Date

    # Generates File Date Suffix - e.g. 2020-8-23-23-49
    $StrFileDateSuffix = "{0}-{1}-{2}-{3}-{4}" `
                -f $Date.year, $Date.month, $Date.Day, `
                    $Date.Minute, $Date.Second

    # Generates Export Path
    $RootExportFolder = $env:TEMP

    # Checks Export path parameter was passed to Script
    if (![string]::IsNullOrEmpty($ExportPath))
        {
        # Replaces variable with alternate export path
        $RootExportFolder = $ExportPath
        }

    # Checks if export path exists
    if ((Test-Path $RootExportFolder) -eq $False)
        {
        # Try | Catch Statement
        Try {$a = New-Item -ItemType directory -Path $RootExportFolder -ErrorAction Stop}
        Catch {Write-Host "Specified Drive and/or Folder does not exist." `
            -ForegroundColor Yellow ; exit}
        }

# GPO Class
Class GPOSettings {
    # Class Variables
    [string] $StreTypes
             $InteTypes
    [string] $StrLMC
             $IntLMC
    [string] $StrUserNode
    [string] $StrCompNode
    [Bool]   $BolUserQAS
    [Bool]   $BolCompQAS
    [string] $StrGPOSettings
             $ObjWMIFilter 

    # Constructor
    GPOSettings() {}

    # Constructor
    GPOSettings($GPOIn, $ObjDCIn)
        {
        # Queries for GPO XML
        [xml]$gRpt = Get-GPOReport -GUID $GPOIn.CN -ReportType XML -Domain $ObjDCIn.domain

        # Calls method - Kerberose Encrpytion Type
        $this.GetETypes($gRpt)
        
        # Calls method - LM Compatibility Level (NTLM)
        $this.GetLMC($gRpt)

        # Calls method - GPO Node Populated State (Computer / User)
        $this.CheckNodePopulatedSettings($gRpt)

        # Calls method - GPO Node Populated State (Computer / User)
        $this.CheckQAS($GPOIn.CN, $GPOIn.gPCFileSysPath)

        $this.GetWMIFilter($GPOIn, $ObjDCIn)
        }

    # Class method captures and translates GPO Kerberos Encrpytion Level
    GetETypes($ObjXMLGPOIn)
        {
        # String Text Filter
        $FilterText = 'SupportedEncryptionTypes'
        
        # Checks for match of XML path
        if ($ObjXMLGPOIn.DocumentElement.Computer.ExtensionData.Extension.SecurityOptions.KeyName -match $FilterText)
            {
            # Assigns Value
            $this.InteTypes = ($ObjXMLGPOIn.DocumentElement.Computer.ExtensionData.Extension.SecurityOptions | `
                where {$_.Keyname -match $FilterText}).settingnumber
            }

        # Switch Statement
        Switch ($this.InteTypes)
            {
            0 {$this.StreTypes = 'RC4-HMAC'}

            {($this.InteTypes -band 1) -eq 1}
                {if ($this.StreTypes -isnot [object])
                    {$this.StreTypes = 'DES-CBC-CRC'} else {$this.StreTypes += ', DES-CBC-CRC'}}

            {($this.InteTypes -band 2) -eq 2}
                {if ($this.StreTypes -isnot [object]) 
                    {$this.StreTypes = 'DES-CBC-MD5'} else {$this.StreTypes += ', DES-CBC-MD5'}}

            {($this.InteTypes -band 4) -eq 4}
                {if ($this.StreTypes -isnot [object]) {$this.StreTypes = 'RC4-HMAC'} else {$this.StreTypes += ', RC4-HMAC'}}

            {($this.InteTypes -band 8) -eq 8}
                {if ($this.StreTypes -isnot [object]) {$this.StreTypes = 'AES128'} else {$this.StreTypes += ', AES128'}}

            {($this.InteTypes -band 16) -eq 16}
                {if ($this.StreTypes -isnot [object]) {$this.StreTypes = 'AES256'} else {$this.StreTypes += ', AES256'}}

            {($this.InteTypes -band 2147483616) -eq 2147483616}
                {if ($this.StreTypes -isnot [object])
                    {$this.StreTypes = 'Future'} else {$this.StreTypes += ', Future'}}
            Default
                {$this.StreTypes += 'RC4-HMAC (Default Value)'; $this.InteTypes = 'Undefined'}
            }
        }

    # Class method captures and translates GPO LM Compatibility (NTLM)
    GetLMC($ObjXMLGPOIn)
        {
        $FilterText = 'LmCompatibilityLevel'
        if ($ObjXMLGPOIn.DocumentElement.Computer.ExtensionData.Extension.SecurityOptions.KeyName -match $FilterText)
            {
            $this.IntLMC = ($ObjXMLGPOIn.DocumentElement.Computer.ExtensionData.Extension.SecurityOptions | `
                where {$_.Keyname -match $FilterText}).settingnumber
            }

        Switch ($this.IntLMC)
            {
            0 {$this.StrLMC = 'Send LM & NTLM responses'}
            1 {$this.StrLMC = 'Send LM & NTLM - use NTLMv2 session security if negotiated'}
            2 {$this.StrLMC = 'Send NTLM responses only'}
            3 {$this.StrLMC = 'Send NTLMv2 responses only'}
            4 {$this.StrLMC = 'Send NTLMv2 responses only. Refuse LM'}
            5 {$this.StrLMC = 'Send NTLMv2 responses only. Refuse LM & NTLM'}
            Default {$this.StrLMC = 'Undefined (Default O/S Value)'; $this.IntLMC = 'Undefined'}
            }
        }

    # Class Method checks node populated status
    CheckNodePopulatedSettings($ObjXMLGPOIn)
        {
        # Checks if User node setting(s) exists
        if ($ObjXMLGPOIn.gpo.user.extensiondata -is [object])
            {$this.StrUserNode = "Populated"} else {$this.StrUserNode = "Undefined"}

        if ($ObjXMLGPOIn.gpo.computer.extensiondata -is [object])
            {$this.StrCompNode = "Populated"} else {$this.StrCompNode = "Undefined"}

        if (($this.StrUserNode -eq "Populated") -or `
                ($this.StrCompNode -eq "Populated") -or `
                ($this.BolUserQAS -eq $True) -or `
                ($this.BolCompQAS -eq $True))
            {$this.StrGPOSettings = "GPO Populated"}
        else
            {$this.StrGPOSettings = "GPO Empty"}  
        }

    # Class Method checks node populated status
    CheckQAS($GPOGUIDIn, $StrGPOSysVolPathIn)
        {
        # Joins SysVol Folder path with GPO GUID & QAS folder
        $LeafFolder = "\User\VGP"
        $GPOSysVolPath = Join-Path $StrGPOSysVolPathIn $LeafFolder

        if (Test-Path $GPOSysVolPath)
            {
            # Beneath QAS folder, checks if an instance of an XML setting file exists - returns whether it is an object
            $this.BolUserQAS = (Get-ChildItem -path $GPOSysVolPath -File -Recurse -Include *.xml) -is [object]
            }

        # Joins SysVol Folder path with GPO GUID & QAS folder
        $LeafFolder = "\machine\VGP"
        $GPOSysVolPath = Join-Path $StrGPOSysVolPathIn $LeafFolder

        if (Test-Path $GPOSysVolPath)
            {
            # Beneath QAS folder, checks if an instance of an XML setting file exists - returns whether it is an object
            $this.BolCompQAS = (Get-ChildItem -path $GPOSysVolPath -File -Recurse -Include *.xml) -is [object]
            }
        }

    # Class Method checks node populated status
    GetWMIFilter ($GPOIn, $ObjDCIn)
        {
        $this.ObjWMIFilter = New-Object WMIFilter

        $StrTmp = 'n/a'
        $this.ObjWMIFilter.WMIFiltered  = $False
        $this.ObjWMIFilter.WMIName      = $StrTmp
        $this.ObjWMIFilter.WMIDesc      = $StrTmp
        $this.ObjWMIFilter.WMINameSpace = $StrTmp
        $this.ObjWMIFilter.WMIQuery     = $StrTmp

        if ($GPOIn.gPCWQLFilter -is [object])
            {
            $WMIFilterCN = $GPOIn.gPCWQLFilter.split(';')[1]
            $ObjmsWMISom = Get-ADObject -LDAPFilter "(&(objectclass=msWMI-som)(cn=$WMIFilterCN))" `
                                -Properties msWMI-Name, msWMI-Parm1, msWMI-Parm2 `
                                -Server $ObjDCIn.hostname[0]
        
            $this.ObjWMIFilter.WMIFiltered  = $True 
            $this.ObjWMIFilter.WMIName      = $ObjmsWMISom.'msWMI-Name'
            $this.ObjWMIFilter.WMIDesc      = $ObjmsWMISom.'msWMI-Parm1'
            $this.ObjWMIFilter.WMINameSpace = $ObjmsWMISom.'msWMI-Parm2'.split(';')[5]
            $this.ObjWMIFilter.WMIQuery     = $ObjmsWMISom.'msWMI-Parm2'.split(';')[6]
            }
        }
}

# GPO Link Class
Class GPOLinkSettings {
# Class Variables
    $GPOLink_Enabled    = 'unlinked'
    $GPOLink_Enforced   = 'unlinked'
    $GPOLink_BlockInher = 'unlinked'
    $GPOLink_UserCnt    = 'n/a'
    $GPOLink_CmptCnt    = 'n/a'
    $GPOLink_OUCnt      = 'n/a'
    $GPOLink_ObjClass   = 'unlinked'
    $GPOLink_DN         = 'unlinked'
    $GPOLink_CN         = 'unlinked'
    $GPOLink_OUName     = 'unlinked'

    # Constructor
    GPOLinkSettings() {}

    # Constructor
    GPOLinkSettings($GPOLinkIn, $GPO, $ObjDCIn)
        {
        $this.GPOLink_OUName = $GPOLinkIn.Name
        $this.GPOLink_DN     = $GPOLinkIn.DistinguishedName
        $this.GPOLink_CN     = $GPOLinkIn.CanonicalName
        
        $this.GetLinkStatus($GPOLinkIn, $GPO.DistinguishedName)
        $this.GetObjCounts($GPOLinkIn, $ObjDCIn)
        $this.GetObjClass($GPOLinkIn)
        }

    GetLinkStatus($GPOLinkIn, $GPODNIn)
        {
        # Splits concatenated string, places into Array Variable
        #   Example:
        #      String = [LDAP://cn={8D9B6CCB-5724-439B-8100-DEBBEE532C05},cn=policies,cn=system,DC=acme,DC=com;0][LDAP://cn={DEA18BD8-EC0A-4F0E-9BDD-8CA87E74B12B},cn=policies,cn=system,DC=acme,DC=com;0]
        # Array = 
        #    LDAP://cn={8D9B6CCB-5724-439B-8100-DEBBEE532C05},cn=policies,cn=system,DC=acme,DC=com;0
        #    LDAP://cn={DEA18BD8-EC0A-4F0E-9BDD-8CA87E74B12B},cn=policies,cn=system,DC=acme,DC=com;0

        [string]$OUGPLink = $Null

        $Links = @($GPOLinkIn.gplink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_})

        # Cycles through array to match GPOs
        $Links | foreach {if ($_ -match $GPODNIn) {$OUGPLink = $_}}
        
        # Splits string and returns value
        $GPOLinkStatus = [int]($OUGPLink -split {$_ -eq '/' -or $_ -eq ';'})[3]

        # Bit Opperator check if GPO is Enabled
        $this.GPOLink_Enabled  = ([bool](!($GPOLinkStatus -band 1)))

        # Bit Opperator check if GPO is Enforced
        $this.GPOLink_Enforced = ([bool]($GPOLinkStatus -band 2))

        # Bit Opperator check if Block Inheritance is enabled
        $this.GPOLink_BlockInher = ([bool]($GPOLinkIn.gPOptions -band 1))
        }

    GetObjCounts($GPOLinkIn, $ObjDCIn)
        {
        # Checks if Object class is OrgUnit or Domain
        If (($GPOLinkIn.ObjectClass -eq "organizationalUnit") `
                    -or ($GPOLinkIn.ObjectClass -eq "domainDNS"))
            {
            # Queries AD Objects within a scope
            $ADObj = Get-ADObject -Filter * -Server $ObjDCIn.hostname[0] `
                                    -SearchBase $GPOLinkIn.DistinguishedName `
                                    -SearchScope subtree 

            # Counts number of Inscope Users beneath OU
            $this.GPOLink_UserCnt = ($ADObj | where {$_.objectclass -eq 'user'} | `
                                    Measure-Object).count

            # Counts number of Inscope Computers beneath OU
            $this.GPOLink_CmptCnt = ($ADObj | where {$_.objectclass -eq 'computer'} | `
                                    Measure-Object).count

            # Counts number of Inscope Computers beneath OU
            $this.GPOLink_OUCnt = ($ADObj | where {$_.objectclass -eq 'organizationalUnit'} | `
                                    Measure-Object).count
            }
        }

    GetObjClass($GPOLinkIn)
        {
        # Captures objectclass the GPO is linked to
        if ($GPOLinkIn.ObjectClass -eq "domainDNS")
            {$this.GPOLink_ObjClass = "DomainRoot"}
        elseif ($GPOLinkIn.ObjectClass -eq "organizationalUnit")
            {$this.GPOLink_ObjClass = "OrgUnit"}
        elseif ($GPOLinkIn.ObjectClass -eq "site")
            {$this.GPOLink_ObjClass = "Site"}
        }
}

# GPO WMIFilter Class (custom WMI Filter)
Class WMIFilter {
# Class Variables
    [Bool]   $WMIFiltered
    [String] $WMIName
    [String] $WMIDesc
    [String] $WMINameSpace
    [String] $WMIQuery
}

Function Get-ADForestObjects {
    Param ([Parameter(Mandatory=$False)] [string]$ForestNameIn)

    $StrError = "Unable to Locate Forest - $ForestNameIn `n`Exiting Script"

    #if forest variable is not specified, retrieve current forest
    If (!$ForestNameIn)     
        {
        Try {$ObjForestOut = Get-ADForest | Select-Object Domains, rootDomain}
        Catch {Write-Warning $StrError}
        }
    else
        {
        Try {$ObjForestOut = Get-ADForest -Server $ForestNameIn | Select-Object Domains, rootDomain}
        Catch {Write-Warning $StrError}
        }
    Return $ObjForestOut
}

Function CheckGPOVersion {
    [cmdletbinding()]
    Param ([Parameter(Mandatory=$True)] $GPOVersionIn, 
            [Parameter(Mandatory=$True)] $GPOSysVolFolderIn)

    # GPT.ini located with each GPO sysVol Folder
    $File = "GPT.ini"

    # Retrieves GPO Sysvol Folder path with GPO.ini file
    Try {
        $GPTFullPath = (Get-ChildItem $GPOSysVolFolderIn | `
                        where {$_.name -eq $File}).fullname
        }
    Catch {} 

    # Validates Folder & File is an object
    if ($GPTFullPath -is [object])
        {
        # Cycles through each Row within the GPT.ini file
        foreach ($Row in Get-Content $GPTFullPath)
            {
            # Checks for Match - Version
            if ($Row -Match "version") 
                {
                # Splits the line, and compares second value
                Return $Row.Split("=")[1] -eq $GPOVersionIn
                }
            }
        }
    else
        {
        # Returns error if Folder/File do not exist
        Return "Error: $File Not Found"
        }
    }

Function PopulateGPOLinkData {
    [cmdletbinding()]
        Param (
                [Parameter(Mandatory=$False)] 
                    $GPOLinkDataIn,
                [Parameter(Mandatory=$True)]
                    $StrDCIn
                )

    # Checks if Variable is an object
    if ($GPOLinkDataIn -is [object])
        {
        # Generates GPO Link Settings Class Object
        [GPOLinkSettings]$MyGPOLink = [GPOLinkSettings]::New($GPOLinkDataIn, $GPO, $StrDCIn)
        }
    else
        {
        # Generates GPO Link Settings Class Object
        $MyGPOLink = [GPOLinkSettings]::New()
        }

    # Defines Hash table variable
    $ArrGPOLinkDetails = [Ordered]@{}

    # Writes Common (top) hash table containing generic GPO details
    $ArrGPOLinkDetails += $ArrTopGPOCSVData 

    $ArrGPOLinkDetails += @{'AD_LinkedObjectClass' = $MyGPOLink.GPOLink_ObjClass}
    $ArrGPOLinkDetails += @{'AD_LinkedOUName'      = $MyGPOLink.GPOLink_OUName}
    $ArrGPOLinkDetails += @{'AD_UserObjCnt'        = $MyGPOLink.GPOLink_UserCnt} 
    $ArrGPOLinkDetails += @{'AD_ComputerObjCnt'    = $MyGPOLink.GPOLink_CmptCnt} 
    $ArrGPOLinkDetails += @{'AD_OrgUnitObjCnt'     = $MyGPOLink.GPOLink_OUCnt} 
    $ArrGPOLinkDetails += @{'GPO_LinkEnabled'      = $MyGPOLink.GPOLink_Enabled} 
    $ArrGPOLinkDetails += @{'GPO_LinkEnforced'     = $MyGPOLink.GPOLink_Enforced} 
    $ArrGPOLinkDetails += @{'GPO_LinkBlockInher'   = $MyGPOLink.GPOLink_BlockInher} 
    $ArrGPOLinkDetails += @{'GPO_LinkedCN'         = $MyGPOLink.GPOLink_CN}
    $ArrGPOLinkDetails += @{'GPO_LinkedDN'         = $MyGPOLink.GPOLink_DN} 

    # Write Common (bottom) hash table containing generic GPO details        
    $ArrGPOLinkDetails += $ArrBottomGPOCSVData

    # Exports GPO to CSV
    New-Object -TypeName PSObject -Property $ArrGPOLinkDetails | `
        Export-Csv $Export -NoTypeInformation -Append

    # Function performs output to screen
    WriteToScreen $ArrGPOLinkDetails.AD_LinkedOUName `
                    $ArrGPOLinkDetails.AD_LinkedObjectClass `
                    $ArrGPOLinkDetails.AD_UserObjCnt `
                    $ArrGPOLinkDetails.AD_ComputerObjCnt `
                    $ArrGPOLinkDetails.GPO_LinkedDN
    }

Function WriteToScreen {
    [cmdletbinding()]
        Param ([Parameter(Mandatory=$False)] $GPOLink_SimpleNameIn,
                    [Parameter(Mandatory=$False)] $GPOLink_ObjClassIn,
                    [Parameter(Mandatory=$False)] $GPOLink_UserCntIn,
                    [Parameter(Mandatory=$False)] $GPOLink_CmptCntIn,
                    [Parameter(Mandatory=$False)] $GPOLink_DNIn)

    $TempdataOut = [ordered]@{}
    $TempdataOut += @{'GPO Link(s)'=([string]$IntLinkCnt + ' of ' + $IntLinkedOUsCnt)}
    $TempdataOut += @{'Forest'=$ObjDC.Forest}
    $TempdataOut += @{'Domain'=$ObjDC.Domain}
    $TempdataOut += @{'ADC'=$ObjDC.Hostname[0]}
    $TempdataOut += @{'Site'=$ObjDC.Site}
    $TempdataOut += @{'GPO Display Name'=$GPO.DisplayName}
    $TempdataOut += @{'GPO CN'=$GPO.CN}
    $TempdataOut += @{'GPO DN'=$GPO.DistinguishedName}
    $TempdataOut += @{'Linked Obj Class'=$GPOLink_ObjClassIn}
    $TempdataOut += @{'Linked Obj Name'=$GPOLink_SimpleNameIn}
    $TempdataOut += @{'Linked Obj DN'=$GPOLink_DNIn}
    $TempdataOut += @{'InScope User Cnt'=$GPOLink_UserCntIn}
    $TempdataOut += @{'InScope Comp Cnt'=$GPOLink_CmptCntIn}

    # Writes Data to Screen Output
    Write-Output (New-Object -TypeName PSObject -Property $TempdataOut)
    }

Function GetGPOExtLinks {
    [cmdletbinding()]
    Param ([Parameter(Mandatory=$True)] $ObjDNCN)

    $ObjProps = @('name', 'ObjectClass', 'distinguishedName', 'gPLink', 'gPOptions', 'CanonicalName')
    $gpLinkLDAPFilter = "(gplink=*$ObjDNCN*)"

    # Defines array variable
    $ArrGPlinks = @()

    # Queries and returns Domain Root matching gpLink filter
    $ArrGPlinks += @(Get-ADObject -LDAPFilter $gpLinkLDAPFilter `
            -Server $ObjDC.hostname[0] `
            -Properties $ObjProps `
            -SearchBase $StrDNRoot `
            -SearchScope Base | `
                select-object $ObjProps)

    # Queries and returns all OUs matching gpLink filter
    $ArrGPlinks += @(Get-ADOrganizationalUnit -LDAPFilter $gpLinkLDAPFilter `
            -Server $ObjDC.hostname[0] `
            -Properties $ObjProps | `
                select-object $ObjProps)

    # Queries configuration NC and returns all sites matching gpLink filter
    $ArrGPlinks += @(Get-ADObject -LDAPFilter $gpLinkLDAPFilter `
            -Server $ObjDC.hostname[0] `
            -Properties $ObjProps `
            -SearchBase "CN=Sites,$((Get-ADRootDSE -Server $objDC.forest).configurationNamingContext)" `
            -SearchScope OneLevel | `
                Select-Object $ObjProps)
        
    Return $ArrGPlinks
    }

Function Get-ADForestGPOs {
    [cmdletbinding()]
        Param([string]$ForestIn)

    # Capture Forest Objects
    $ObjForest = Get-ADForestObjects -ForestName $ForestIn

    # Define Array - Forest DCs Objects
    $ObjsForestDC = @()

    # Cycles through each Domain in the forest
    foreach ($ObjDomains in $ObjForest.Domains)
        {
        # Discovers single domain controller (PDCe) from each domain in the forest
        $ObjsForestDC += Get-ADDomainController `
                -DomainName $ObjDomains `
                -Discover `
                -Service ADWS, PrimaryDC `
                -ForceDiscover
        }

    # Defines String Variable (for defining file name output)
    $StrRPTType = "Full_"

    #################################
    # Generate LDAP Filter (GPO)

        $StrLDAPFilterOut   = "(&"
        $StrLDAPFilterOut  +=  "(objectClass=groupPolicyContainer)"
    
        # Custom LDAP Filter (GPO)
        if (![String]::IsNullOrEmpty($GPONameFilter)) 
            {
            # Defines String Variable (for defining file name output)
            $StrRPTType = "Filtered_"

            # Generate Custom LDAP Filter (GPO)
            $StrLDAPFilterOut  += "(|"
            $StrLDAPFilterOut  += "(displayname=$GPONameFilter)"
            $StrLDAPFilterOut  += ")"
            }

        # Generate closing LDAP Filter (GPO)
        $StrLDAPFilterOut  += ")"

    #################################
    # GPO Full Report CSV File Name
        $CSVFileName = ("_" + $ObjForest.rootDomain + "_GPO_" + $StrRPTType + $StrFileDateSuffix + ".csv").ToUpper()
        $Export = Join-Path $RootExportFolder $CSVFileName

    #################################
    # Array | Define AD Properties (attribs) to return

        $ADObjProps = @('cn','DisplayName')
        $ADObjProps += @('gPCFileSysPath','gPCMachineExtensionNames')
        $ADObjProps += @('gPCWQLFilter','objectGUID')
        $ADObjProps += @('versionNumber','whenCreated','whenChanged','whenCreated')
    
    #################################
    # Cycle Through Domain Controller Objects (in each Domain of Forest)
    Foreach ($ObjDC in $ObjsForestDC)
        {
        # Captures Domain Distinguished Name
        $StrDNRoot = (Get-ADDomain -Server $ObjDC).distinguishedName

        # Nulls GPO Variable
        $ArrDomGPOData = $Null

        # Performs try/catch statement (Supresses errors)
        Try {
            # Queries list of Filtered GPO specified via script input arguments
            $ArrDomGPOData = Get-ADObject -LDAPFilter $StrLDAPFilterOut `
                -Server $ObjDC `
                -SearchBase ("CN=Policies,CN=System," + $StrDNRoot) `
                -Properties $ADObjProps | `
                    Sort-Object DisplayName
            }
        Catch {}

        # Checks if Array has data
        if (($ArrDomGPOData | Measure-Object).count -gt 0)
            {
            # GPO Total Counter
            $IntGPOCounter = 1

            # Cycles through GPO Array Object
            Foreach ($GPO in $ArrDomGPOData)
                {
                # Defines Array Variable
                $Results = @()

                # Queries all locations where GPO can be linked matching
                # specific gpLink filter (array of OU objects)
                # In short, pulls all OU where GPO is linked (domain root, OUs, & sites)
                # Returns only DistinguishedName
                $LinkedOUs = $Null
                $LinkedOUs = GetGPOExtLinks $GPO.DistinguishedName

                # Populates count of OU Links
                $IntLinkedOUsCnt = 0

                # Return the total count of linked objects
                $IntLinkedOUsCnt = ($LinkedOUs.DistinguishedName | Measure-Object).count

                # Generates GPO Class Object
                [GPOSettings]$MyGPO = [GPOSettings]::New($GPO, $ObjDC)

                # Retrieves specific GPO details:
                #   GPO Node enabled/disabeled Status, GPO Description, GPO Owner
                $ObjGPO = Get-GPO -Guid $GPO.CN -domain $ObjDC.domain | `
                        Select-Object GPOStatus, Description, Owner

                # Checks whether owner value exists
                if ($ObjGPO.Owner -isnot [object])
                    {$StrGPOOwner = "Unresolved SID"}
                else
                    {$StrGPOOwner = $ObjGPO.Owner}

                # Checks Domain GPO Version against SysVol GTP.ini Version
                $GPOVerCheck = CheckGPOVersion -GPOVersionIn $GPO.versionNumber `
                                    -GPOSysVolFolderIn $GPO.gPCFileSysPath

                # Writes Output to Screen
                Write-Host "-------------------------"
                Write-Host ("GPO: " + [string]$IntGPOCounter + " of " + ($ArrDomGPOData | Measure-Object).count + " - " + $GPO.DisplayName) -ForegroundColor Yellow
                Write-Host "-------------------------"

                # Populates TOP hash table with generic GPO details
                $ArrTopGPOCSVData = [ordered]@{}
                    # Hash Table | Forest, Domain and Site Information
                    $ArrTopGPOCSVData += @{'AD_Forest' = $ObjDC.Forest}
                    $ArrTopGPOCSVData += @{'AD_Domain' = $ObjDC.Domain}
                    $ArrTopGPOCSVData += @{'AD_DC'     = $ObjDC.HostName[0]}
                    $ArrTopGPOCSVData += @{'AD_DCIPv4' = $ObjDC.IPv4Address}
                    $ArrTopGPOCSVData += @{'AD_Site'   = $ObjDC.Site}

                    # Hash Table | Basic GPO Information
                    $ArrTopGPOCSVData += @{'GPO_LinkedCnt'            = $IntLinkedOUsCnt} 
                    $ArrTopGPOCSVData += @{'GPO_DisplayName'          = $GPO.DisplayName}
                    $ArrTopGPOCSVData += @{'GPT_PassCheck'            = $GPOVerCheck}
                    $ArrTopGPOCSVData += @{'GPO_CN'                   = $GPO.CN}
                    $ArrTopGPOCSVData += @{'GPO_Owner'                = $StrGPOOwner}
                    $ArrTopGPOCSVData += @{'GPO_Description'          = $ObjGPO.Description}
                    $ArrTopGPOCSVData += @{'GPO_NodeStatus'           = $ObjGPO.GPOStatus}
                    $ArrTopGPOCSVData += @{'GPO_UserSettings'         = $MyGPO.StrUserNode}
                    $ArrTopGPOCSVData += @{'GPO_CompSettings'         = $MyGPO.StrCompNode}

                # Populates BOTTOM hash table with generic GPO details
                $ArrBottomGPOCSVData = [ordered]@{}

                    # Hash Table | Captures Defined Kerberos Encryption Types
                    $ArrBottomGPOCSVData += @{'GPO_EncrpytionVal'        = $MyGPO.InteTypes}
                    $ArrBottomGPOCSVData += @{'GPO_EncrpytionTypes'      = $MyGPO.StreTypes}

                    # Hash Table | Captures Defined LMC Info
                    $ArrBottomGPOCSVData += @{'GPO_LMCompatVal'          = $MyGPO.IntLMC}
                    $ArrBottomGPOCSVData += @{'GPO_LMCompatDesc'         = $MyGPO.StrLMC}

                    # Hash Table | Captures Defined QAS Info
                    $ArrBottomGPOCSVData += @{'GPO_QASMachSettings'      = $MyGPO.BolCompQAS}
                    $ArrBottomGPOCSVData += @{'GPO_QASUserSettings'      = $MyGPO.BolUserQAS}
                    $ArrBottomGPOCSVData += @{'GPO_SummarySettingStatus' = $MyGPO.StrGPOSettings}

                    # Hash Table | Captures Defined WMI Filter Info
                    $ArrBottomGPOCSVData += @{'GPO_WMIFiltered'          = $MyGPO.objwmifilter.WMIFiltered}
                    $ArrBottomGPOCSVData += @{'GPO_WMIFilterName'        = $MyGPO.objwmifilter.WMIName}
                    $ArrBottomGPOCSVData += @{'GPO_WMIFilterDesc'        = $MyGPO.objwmifilter.WMIDesc}
                    $ArrBottomGPOCSVData += @{'GPO_WMIFilterNameSpace'   = $MyGPO.objwmifilter.WMINameSpace}
                    $ArrBottomGPOCSVData += @{'GPO_WMIFilterQuery'       = $MyGPO.objwmifilter.WMIQuery}

                    $ArrBottomGPOCSVData += @{'GPO_objectGUID'           = $GPO.objectGUID}
                    $ArrBottomGPOCSVData += @{'GPO_gPCFileSysPath'       = $GPO.gPCFileSysPath}
                    $ArrBottomGPOCSVData += @{'GPO_WhenChanged'          = ($GPO.WhenChanged).ToShortDateString()}
                    $ArrBottomGPOCSVData += @{'GPO_WhenCreated'          = ($GPO.WhenCreated).ToShortDateString()}
                    $ArrBottomGPOCSVData += @{'GPO_DistinguishedName'    = $GPO.DistinguishedName}

                # Link Counter
                $IntLinkCnt = 0

                # Checks if Linked OU variable is object
                if ($LinkedOUs -is [object])
                    {
                    # Increment Link Counter
                    $IntLinkCnt++

                    # Checks if Linked OU variable isnot array (single GPO link)
                    if ($LinkedOUs -isnot [array])
                        {
                        # GPO - Captures and export GPO Link Details
                        PopulateGPOLinkData $LinkedOUs -StrDCIn $ObjDC
                        }
                    else # Cycles through array (multiple GPO links)
                        {
                        Foreach ($LinkedOU in $LinkedOUs)
                            {
                            # GPO - Captures and export GPO Link Details
                            PopulateGPOLinkData $LinkedOU -StrDCIn $ObjDC
                                
                            # Increments GPO Link Counter
                            $IntLinkCnt++
                            }
                        }
                    }
                else
                    {
                    # GPO - Captures and export GPO Details (unlinked GPOs)
                    PopulateGPOLinkData -StrDCIn $ObjDC
                    }
                    
                # Increment GPO Counter
                $IntGPOCounter++
                }
            }
        else
            {Write-Host ("Querying Domain: " + $ObjDC.Domain + " - $GPONameFilter - No GPO(s) Found") -ForegroundColor Yellow}
        }

    # Writes Output to Screen
    Write-Host "-------------------------"
    Write-Host " - Output CSV File: $Export"
}

# Forest Array
$Forests | Foreach {Get-ADForestGPOs $_}
