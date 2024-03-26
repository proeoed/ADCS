[cmdletbinding()] 
param(
    [Parameter(Mandatory=$false, HelpMessage='Define the look ahead window',Position = 0)]
    [int]
    $eDays = 60,
    [AllowNull()]
    [Parameter(Mandatory=$false, HelpMessage='Define the Templates to exclude (use Get-AllTemplateNames to determine the Names)',Position = 1)]
    [string[]]
    $templatestoExclude = @("OCSPResponseSigning","KerberosAuthentication"),
    [Parameter(Mandatory=$true, HelpMessage='Define the SMTP Server to send the mails to',Position = 2)]
    [string]
    $SMTPServer = "yoursmtpserver.fqdn.tld",
    [Parameter(Mandatory=$true, HelpMessage='Define the SMTP From address',Position = 3)]
    [string]
    $SMTPFrom,
    [Parameter(Mandatory=$true, HelpMessage='Define the SMTP To address',Position = 4)]
    [string[]]
    $SMTPTo,
    [Parameter(Mandatory=$false, HelpMessage='Define the Subject of the Mail',Position = 5)]
    [string]
    $SMTPSubject = "ADCS Expiration Report",
    [Parameter(Mandatory=$false, HelpMessage='Define the Title of the Report',Position = 6)]
    [string]
    $Title = "ADCS Certificate Expirations Report",
    [Parameter(Mandatory=$false, HelpMessage='Define the UNC of the Reportfile (e.g. C:\temp\ADCS\)',Position = 6)]
    [string]
    $ReportFilePath = "C:\temp\ADCS\",
    [Parameter(Mandatory=$false, HelpMessage='Define the UNC of the Reportfile (e.g. C:\temp\ADCS\)',Position = 7)]
    [string]
    $ReportFile = "Report.html",
    [AllowNull()]
    [Parameter(Mandatory=$false, HelpMessage='Define the CA Configs to access <ServerName>\<CAName>',Position = 8)]
    [string[]]
    $CAConfigs,
    [Parameter(Mandatory=$false, HelpMessage='Define Domain to Query - broken',Position = 9)]
    [String]
    $Domain

)

function Search-ADwithADSI {
    param (
        [string] $dn,
        [string] $LDAPFilter,
        [ValidateSet("Base","OneLevel","Subtree")]
        [string] $SearchScope = "Subtree",
        [string[]] $Properties,
        [switch] $FindOne = $false
    )
    $QueryDN = "LDAP://$dn" 
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.Filter = $LDAPFilter
    $Searcher.SearchRoot = $QueryDN
    $Searcher.SearchScope = $SearchScope
    foreach($prop in $Properties) {
        $Searcher.PropertiesToLoad.Add($prop) | Out-Null
    }
    try {
        if($FindOne) {
            return $Searcher.FindOne()
        } else {
            return $Searcher.FindAll()
        }
    }
    catch {
        Throw "FindAll Operation Failed - Check input"
    }
}
function Get-CertificatAuthority {
<#
        .Synopsis
        Get list of Certificate Authorities from Active directory
        .DESCRIPTION
        Queries Active Directory for Certificate Authorities with Enrollment Services enabled
        .EXAMPLE
        Get-CertificatAuthority 
        .EXAMPLE
        Get-CertificatAuthority -CaName 'MyCA'
        .EXAMPLE
        Get-CertificatAuthority -ComputerName 'CA01' -Domain 'Contoso.com'
        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
#>
    [CmdletBinding()]
    [OutputType([adsi])]
    Param
    (
        # Name given when installing Active Directory Certificate Services 
        [string[]]
        $CAName = $null,

        # Name of the computer with Active Directory Certificate Services Installed
        [string[]]
        $ComputerName = $null,

        # Domain to Search
        [String]
        $Domain = (Get-Domain).Name 
    )
    Write-Verbose $Domain
    ## If the DN path does not exist error message set as valid object 
    $CaEnrolmentServices = Get-ADPKIEnrollmentServers -Domain $Domain 
    $CAList = $CaEnrolmentServices.Children

    if($CAName)
    {
        $CAList = $CAList | Where-Object -Property Name -In  -Value $CAName
    }
    if ($ComputerName)
    {
        # Make FQDN
        [Collections.ArrayList]$List = @() 
        foreach ($Computer in $ComputerName) 
        { 
            if ($Computer -like "*.$Domain") 
            {
                $null = $List.add($Computer)
            } else {
                $null = $List.add("$($Computer).$Domain")
            }
        } # end foreach
        $CAList = $CAList | Where-Object -Property DNSHostName -In -Value $List
    }
    
    $CAList
}
function Get-CaLocationString {
    <#
        .SYNOPSIS
        Gets the Certificate Authority Location String from active directory

        .DESCRIPTION
        Certificate Authority Location Strings are in the form of ComputerName\CAName This info is contained in Active Directory

        .PARAMETER CAName
        Name given when installing Active Directory Certificate Services

        .PARAMETER ComputerName
        Name of the computer with Active Directory Certificate Services Installed

        .PARAMETER Domain
        Domain to retreve data from

        .EXAMPLE
        get-CaLocationString -CAName MyCA
        Gets only the CA Location String for the CA named MyCA

        .EXAMPLE
        get-CaLocationString -ComputerName ca.contoso.com
        Gets only the CA Location String for server with the DNS name of ca.contoso.com

        .EXAMPLE
        get-CaLocationString -Domain contoso.com
        Gets all CA Location Strings for the domain contoso.com

        .NOTES
        Location string are used to connect to Certificate Authority database and extract data.

        .OUTPUTS
        [STRING[]]
    #>


    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Name given when installing Active Directory Certificate Services 
        [string[]]
        $CAName = $null,

        # Name of the computer with Active Directory Certificate Services Installed
        [string[]]
        $ComputerName = $null,

        # Domain to Search
        [String]
        $Domain = (Get-Domain).Name 
    )
    $CAList = Get-CertificatAuthority @PSBoundParameters
    foreach ($ca in $CAList) 
    {
        ('{0}\{1}' -f $($ca.dNSHostName), $($ca.name))
    }
}
function Get-Domain {
    <#
    .Synopsis
    Return the current domain
    .DESCRIPTION
    Use .net to get the current domain
    .EXAMPLE
    Get-Domain
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    Param
    (
    [ValidateSet("LocalComputer","LoggedOnUser")]
    [string] 
    $Current = "LocalComputer"
    )
    if ($Current -eq "LocalComputer") {
        Write-Verbose -Message 'Calling GetComputerDomain()' 
        return ([DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain())
    } else {
        Write-Verbose -Message 'Calling GetCurrentDomain()' 
        return ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
    }
}
function Get-ADPKIEnrollmentServers {
    <#
            .Synopsis
            Return the Active Directory objects of the Certificate Authorites
            .DESCRIPTION
            Use .net to get the current domain
            .EXAMPLE
            Get-PKIEnrollmentServers
    #>
    [CmdletBinding()]
    [OutputType([adsi])]
    Param
    (
        [Parameter(Mandatory,HelpMessage='Domain To Query',Position = 0)]
        [string]
        $Domain
    )
    $QueryDN = 'LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=' + $Domain -replace '\.', ',DC=' 
    Write-Verbose -Message "Querying [$QueryDN]"
    $result = [ADSI]$QueryDN
    if (-not ($result.Name)) 
    {
        Throw "Unable to find any Certificate Authority Enrollment Services Servers on domain : $Domain" 
    }
    $result
}
function Get-TemplateOIDfromName {
    [CmdletBinding()]
    [OutputType([adsi])]
    Param
    (
        [Parameter(Mandatory,HelpMessage='Template Name',Position = 0)]
        [string]
        $TemplateName,
        [Parameter(Mandatory=$false,HelpMessage='Domain To Query',Position = 1)]
        [string]
        $Domain = (Get-Domain).Name
    )
    $QueryDN = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=" + $Domain -replace '\.', ',DC=' 
    $result = Search-ADwithADSI -dn $QueryDN -SearchScope Subtree -Properties Name,msPKI-Cert-Template-OID -FindOne
    if (-not ($result.properties.'mspki-cert-template-oid')) 
    {
        Throw "Unable to find any Certificate Authority Enrollment Services Servers on domain : $Domain" 
    }
    return $result.properties.'mspki-cert-template-oid'
}
function Get-TemplateNameFromOID {
	param(
        [Parameter(Mandatory,HelpMessage='Template OID',Position = 0)]
        [string]
        $TemplateOID,
        [Parameter(Mandatory=$false,HelpMessage='Domain To Query',Position = 1)]
        [string]
        $Domain = ((Get-Domain).Name)
	)
    Write-Verbose "TemplateOID: $TemplateOID"
    if(!($TemplateOID -match "\d")) {
        $TemplateOID = Get-TemplateOIDfromName -Domain $Domain -TemplateName $TemplateOID
        Write-Verbose "TemplateOID is not a OID : Changed to : $TemplateOID"
    }
    $QueryDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=" + $Domain -replace '\.', ',DC=' 
    $result = Search-ADwithADSI -dn $QueryDN -SearchScope Subtree -Properties Name -LDAPFilter "(msPKI-Cert-Template-OID=$TemplateOID)" -FindOne
    try {
        $retval = $result.Properties.name
    }
    catch {
        $retval = $TemplateOID
    }
    if([string]::IsNullOrEmpty($retval)) {
        $retval = $TemplateOID
    }
    Write-Verbose "Retval: $retval"
    return $retval
}
function Get-TemplateDisplayNameFromOID {
	param(
        [Parameter(Mandatory,HelpMessage='Template OID',Position = 0)]
        [string]
        $TemplateOID,
        [Parameter(Mandatory=$false,HelpMessage='Domain To Query',Position = 1)]
        [string]
        $Domain = ((Get-Domain).Name)
	)
    Write-Verbose "TemplateOID: $TemplateOID"
    if(!($TemplateOID -match "\d")) {
        $TemplateOID = Get-TemplateOIDfromName -Domain $Domain -TemplateName $TemplateOID
        Write-Verbose "TemplateOID is not a OID : Changed to : $TemplateOID"
    }
    $QueryDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=" + $Domain -replace '\.', ',DC=' 
    $result = Search-ADwithADSI -dn $QueryDN -SearchScope Subtree -Properties Name,displayName -LDAPFilter "(msPKI-Cert-Template-OID=$TemplateOID)" -FindOne
    try{
        $retval = $result.Properties.displayname
    }
    catch {
        $retval = $TemplateOID
    }
    if([string]::IsNullOrEmpty($retval)) {
        $retval = $TemplateOID
    }
    Write-Verbose "Retval: $retval"
    return $retval
}
function Get-AllTemplateNames {
    param(
        [Parameter(Mandatory=$false,HelpMessage='Domain To Query',Position = 0)]
        [string]
        $Domain = ((Get-Domain).Name)
	)

    $QueryDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=" + $Domain -replace '\.', ',DC=' 
    $result = Search-ADwithADSI -dn $QueryDN -SearchScope Subtree -Properties cn -LDAPFilter "(objectClass=pKICertificateTemplate)"
    return $result.Properties.cn
}
function Get-AllTemplates {
    param(
        [Parameter(Mandatory=$false,HelpMessage='Domain To Query',Position = 0)]
        [string]
        $Domain = ((Get-Domain).Name)
	)
    $QueryDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=" + $Domain -replace '\.', ',DC=' 
    $result = Search-ADwithADSI -dn $QueryDN -SearchScope Subtree -Properties name,displayname,msPKI-Cert-Template-OID,DistinguishedName -LDAPFilter "(objectClass=pKICertificateTemplate)"
    $retval =@()
    $publishedTemplates = Get-PublishedTemplateNames -Domain $Domain
    foreach($res in $result) {
        $retval += [PSCustomObject]@{
            DistinguishedName = $res.Properties.distinguishedname
            Name = $res.Properties.name
            DisplayName = $res.Properties.displayname
            OID = $res.Properties.'mspki-cert-template-oid'
            Published = if($publishedTemplates -contains $res.Properties.name) { $true } else { $false }
        }
    }
    return $retval
}
function Get-PublishedTemplateNames {
    param(
        [Parameter(Mandatory=$false,HelpMessage='Domain To Query',Position = 0)]
        [string]
        $Domain = ((Get-Domain).Name)
	)
    $CAs = (Get-CertificatAuthority -Domain $Domain).distinguishedName
    $templates = @()
    foreach($ca in $CAs) {
        $QueryDN = $ca
        $result = Search-ADwithADSI -dn $QueryDN -SearchScope Subtree -Properties certificateTemplates
        $templates += $result.Properties.certificatetemplates
    }

    return $templates | Select-Object -Unique
}
function Get-CAIssuedCertificates {
    # Derived from PKITools (David Jones) - https://www.powershellgallery.com/packages/PKITools/1.6
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            <#
    .Synopsis
    Get list of Certificates issued by Certificate Authorities

    .PARAMETER ExpireInDays
    Maximum number of days from now that a certificate will expire. (Default: 21900 = 60 years)

    .PARAMETER Properties
    Fields in the Certificate Authority Database to Export

    -Default Fields Exported
        Issued Common Name
        Certificate Expiration Date
        Certificate Effective Date
        Certificate Template
        Issued Email Address
        Issued Request ID
        Certificate Hash
        Request Disposition
        Request Disposition Message
        Requester Name
    

    -Available Fields
        Archived Key
        Attestation Challenge
        Binary Certificate
        Binary Precertificate
        Binary Public Key
        Binary Request
        Caller Name
        Certificate Effective Date
        Certificate Expiration Date
        Certificate Hash
        Certificate Template
        Effective Revocation Date
        Endorsment Certificate Hash
        Endorsement Key Hash
        Issued Binary Name
        Issued City
        Issued Common Name
        Issued Country/Region
        Issued Device Serial Number
        Issued Distinguished Name
        Issued Domain Coupon
        Issued Email Address
        Issued First Name
        Issued Initials
        Issued Last Name
        Issued Organization
        Issued Organization Unit
        Issued Request ID
        Issued Street Address
        Issued State
        Issued Subject Key Identifier
        Issued Title
        Issued Unstructured Address
        Issued Unstructured Name
        Issuer Name ID
        Key Recovery Agent Hashes
        Officer
        Old Certificate
        Public Key Algorithm
        Public Key Algorithm Parameters
        Public Key Length
        Publish expired Certificate in CRL
        Request Attributes
        Request Binary Name
        Request City
        Request Common Name
        Request Country/Region
        Request Device Serial Number
        Request Disposition
        Request Disposition Message
        Request Distinguished Name
        Request Domain Component
        Request Email Address
        Request First Name
        Request Flags
        Request ID
        Request Initials
        Request Last Name
        Request Organization
        Request Organization Unit
        Request Resolution Date
        Request State
        Request Status Code
        Request Street Address
        Request Submission Date
        Request Title
        Request Type
        Request Unstructured Address
        Request Unstructured Name
        Requestor Name
        Revocation Date
        Revocation Reason
        Serial Number
        Signer Application Policies
        Signer Policies
        Template Enrollment Flags
        Template General Flags
        Template Private Key Flags
        User Principal Name

    .PARAMETER CALocation
    Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)

    .PARAMETER CertificateTemplateToInclude
    Filter on Certificate Template Name to include in the lookup (Get-PublishedTemplateNames or Get-AllTemplateNames)

    .PARAMETER CommonName
    Filter by Issued Common Name

    .PARAMETER ShowIssuer
    Switch to include Issuer DN in output, default is True
    
    .EXAMPLE
    Get-CAIssuedCertificates.ps1
    This will collect all issued certificates from local CA  
        
    .EXAMPLE
    Get-CAIssuedCertificates.ps1 -CALocation "computername\CAName"

    Get-CAIssuedCertificates.ps1 -CALocation CASVR01\ORG-CA

    This will collect all issued certificates from the ORG-CA instance located on the CASVR01 server
        
    .OUTPUTS
    PSObject
    #>
    [CmdletBinding()]
    Param (
        
    # Maximum number of days from now that a certificate will expire. (Default: 21900 = 60 years)
    [Int]
    $ExpireInDays = 21900,

    # Fields in the Certificate Authority Database to Export
    [String[]]
    $Properties = (
        'Issued Common Name', 
        'Certificate Expiration Date', 
        'Certificate Effective Date', 
        'Certificate Template', 
        'Issued Email Address',
        'Issued Request ID', 
        'Certificate Hash', 
        'Request Disposition',
        'Request Disposition Message', 
        'Requester Name' ),


    [AllowNull()]
    # Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)
    [String[]]
    $CAlocation,

    # Filter on Certificate Template Name to Include (use Get-PublishedTemplateNames)
    [AllowNull()]
    [String]
    $CertificateTemplateToInclude,

    # Filter by Issued Common Name
    [AllowNull()]
    [String]
    $CommonName,
    
    [string]
    $Domain,

    # Extract Subject Alternative Names
    [Switch]
    $ExtractSAN=$True,

    # Show Issuer DN
    [Switch]
    $ShowIssuer=$True
    ) 

    if(-not $CAlocation){

        $CAlocation =  (get-CaLocationString -Domain $Domain)
    }
   
    foreach ($Location in $CAlocation) 
    {
        $CaView = New-Object -ComObject CertificateAuthority.View
        try {
            $null = $CaView.OpenConnection($Location)
        }
        catch {
            Throw "Unable to open Connection to: $location"            
        }
        if($ExtractSAN -eq $true -and (($Properties -contains "Binary Certificate") -eq $false)) {
            $CaView.SetResultColumnCount($Properties.Count+1)
            $index = $CaView.GetColumnIndex($false, 'Binary Certificate')
            $CaView.SetResultColumn($index)
        } else {
            $CaView.SetResultColumnCount($Properties.Count)
        }        
    
        #region SetOutput Colum
        foreach ($item in $Properties)
        {
            $index = $CaView.GetColumnIndex($false, $item)
            $CaView.SetResultColumn($index)
        }
        #endregion

        #region Filters
        $CVR_SEEK_EQ = 1
        $CVR_SEEK_LT = 2
        $CVR_SEEK_GT = 16
    
        #region filter expiration Date
        $index = $CaView.GetColumnIndex($false, 'Certificate Expiration Date')
        $now = Get-Date
        $expirationdate = $now.AddDays($ExpireInDays)
        if ($ExpireInDays -gt 0)
        { 
            $CaView.SetRestriction($index,$CVR_SEEK_GT,0,$now)
            $CaView.SetRestriction($index,$CVR_SEEK_LT,0,$expirationdate)
        } else {
            $CaView.SetRestriction($index,$CVR_SEEK_LT,0,$now)
            $CaView.SetRestriction($index,$CVR_SEEK_GT,0,$expirationdate)
        }
        #endregion filter expiration date

        #region Filter Template
        if ($CertificateTemplateToInclude)
        {
            $oid = Get-TemplateOIDfromName -TemplateName $CertificateTemplateToInclude
            $index = $CaView.GetColumnIndex($false, 'Certificate Template')
            $CaView.SetRestriction($index,$CVR_SEEK_EQ,0,$oid)
        }

        #endregion


        #region Filter Issued Common Name
        if ($CommonName)
        {
            $index = $CaView.GetColumnIndex($false, 'Issued Common Name')
            $CaView.SetRestriction($index,$CVR_SEEK_EQ,0,$CommonName)
        }
        #endregion

        #region Filter Only issued certificates
        # 20 - issued certificates
        $CaView.SetRestriction($CaView.GetColumnIndex($false, 'Request Disposition'),$CVR_SEEK_EQ,0,20)
        #endregion

        #endregion

        #region output each retuned row
        $CV_OUT_BASE64HEADER = 0 
        $CV_OUT_BASE64 = 1 
        $RowObj = $CaView.OpenView()
    
        $IssuerDN = (Get-CertificatAuthority).cACertificateDN

        while ($RowObj.Next() -ne -1)
        {
            $Cert = New-Object -TypeName PsObject
            $ColObj = $RowObj.EnumCertViewColumn()
            $null = $ColObj.Next()
            do 
            {
                $displayName = $ColObj.GetDisplayName()
                switch($displayName)
                {
                    "Binary Certificate" { 
                        if($ExtractSAN) {
                            try {
                                $rawcert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($($ColObj.GetValue($CV_OUT_BASE64))))
                                if($rawcert.Extensions.oid.friendlyname -contains "Subject Alternative Name") { 
                                    $sans = ($rawcert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}).Format(1)
                                } else {
                                    $sans = $null
                                }
                                $Cert | Add-Member -MemberType NoteProperty -Name "SubjectAlternativeName" -Value $sans -Force
                                Write-Verbose "SubjectAlternativeName : $sans"
                            }
                            catch {
                                Write-host "Failed to extract SANs from Binary Certificate"
                            }
                        }
                        if($Properties -contains "Binary Certificate") {
                            # format Binary Certificate in a savable format.
                            $Cert | Add-Member -MemberType NoteProperty -Name $displayName.ToString().Replace(" ", "") -Value $($ColObj.GetValue($CV_OUT_BASE64HEADER)) -Force
                            Write-Verbose "BinaryCertificate : $($ColObj.GetValue($CV_OUT_BASE64HEADER).substring(0,20))"
                        }
                    }

                    "Certificate Template" {
                        # format Certificate Template DisplayName from AD
                        $Cert | Add-Member -MemberType NoteProperty -Name "CertificateTemplateName" -Value (Get-TemplateNameFromOID -TemplateOID $($ColObj.GetValue($CV_OUT_BASE64))) -Force
                        $Cert | Add-Member -MemberType NoteProperty -Name "CertificateTemplateDisplayName" -Value (Get-TemplateDisplayNameFromOID -TemplateOID $($ColObj.GetValue($CV_OUT_BASE64))) -Force
                        Write-Verbose "CertificateTemplateName : $(Get-TemplateNameFromOID -TemplateOID $($ColObj.GetValue($CV_OUT_BASE64)))"
                        Write-Verbose "CertificateTemplateDisplayName : $(Get-TemplateDisplayNameFromOID -TemplateOID $($ColObj.GetValue($CV_OUT_BASE64)))"
                        Write-Verbose "TemplateOID : $($ColObj.GetValue($CV_OUT_BASE64))"
                    }
                    "Certificate Expiration Date" {
                        $Cert | Add-Member -MemberType NoteProperty -Name $displayName.ToString().Replace(" ", "") -Value $($ColObj.GetValue($CV_OUT_BASE64)) -Force
                        $diff = New-TimeSpan -Start $now -End $($ColObj.GetValue($CV_OUT_BASE64))
                        if($diff.Days -eq 0) { 
                            if ($diff.Hours -eq 0) { $exp = "$($diff.Minutes) [min]" } else { $exp = "$($diff.Hours) [h]" }
                        } else { $exp = "$($diff.Days) [d]" }
                        $Cert | Add-Member -MemberType NoteProperty -Name "ExpiresIn" -Value $exp -Force
                        $Cert | Add-Member -MemberType NoteProperty -Name "ExpiresInDays" -Value $diff.Days -Force
                        Write-Verbose "ExpiresIn : $exp"
                        Write-Verbose "ExpiresInDays : $($diff.Days)"
                    }
                    "Certificate Hash" {
                        $Cert | Add-Member -MemberType NoteProperty -Name "Thumbprint" -Value ($($ColObj.GetValue($CV_OUT_BASE64)) -replace " ","" ) -Force
                        Write-Verbose "Thumbprint : $($ColObj.GetValue($CV_OUT_BASE64))"
                    }
                    "Issued Common Name" {
                        if([string]::IsNullOrEmpty(($ColObj.GetValue($CV_OUT_BASE64)))) { $subject = $null
                        } else { $subject = ($ColObj.GetValue($CV_OUT_BASE64)).ToLower() }
                        $Cert | Add-Member -MemberType NoteProperty -Name "Subject" -Value $subject -Force
                        Write-Verbose "Subject : $subject"
                    }
                    default {
                        $Cert | Add-Member -MemberType NoteProperty -Name $displayName.ToString().Replace(" ", "") -Value $($ColObj.GetValue($CV_OUT_BASE64)) -Force
                        Write-VErbose ("{0} : {1}" -f $displayName.ToString().Replace(" ", ""),$($ColObj.GetValue($CV_OUT_BASE64)))
                    }
                }


            }
            until ($ColObj.Next() -eq -1)
            Clear-Variable -Name ColObj

            if($ShowIssuer){$Cert | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $IssuerDN}
        
            $Cert

        }
    }
}

if(!(Test-Path $ReportFilePath)) {
    New-Item -ItemType Directory -Path $ReportFilePath -Force
}
$Report = Join-Path $ReportFilePath -ChildPath $ReportFile
$Domain = (Get-Domain).Name

$certs = Get-CAIssuedCertificates -ExpireInDays $eDays -ExtractSAN:$true -CAlocation $CAConfigs -Domain $Domain `
    -Properties "Issued Request ID",
                "Caller Name",
                "Request Common Name",
                "User Principal Name",
                "Issued Common Name",
                "Issued Distinguished Name",
                "Issued Email Address",
                "Certificate Effective Date",
                "Certificate Expiration Date",
                "Certificate Hash",
                "Serial Number",
                "Revocation Date",
                "Revocation Reason",
                "Effective Revocation Date",
                "Certificate Template" | Where-Object {$templatestoExclude -notcontains $_.CertificateTemplateName} | Sort-Object CertificateExpirationDate

$Data2Report = $certs | Select-Object ExpiresIn,CertificateExpirationDate,CallerName,Subject,SubjectAlternativeName,Thumbprint,CertificateTemplateDisplayName,IssuedDistinguishedName

$HTMLHead = @"
<style>
body { background-color:#f6f6f6; font-family:calibri; margin:0px;}
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #34495e; color:#ffffff}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
TR:Nth-Child(Even) {Background-Color: #dddddd;}
</style>
"@

$HTMLexcludedTemplates = foreach($t in $templatestoExclude) { "<li>$t</li>"}

$HTMLPreContent = @"
<h1>$Title</h1>
<p>For more details about the certificates please open the Attached HTML Report!</p>
<p>The query looked for certificates expiering in the next $eDays days. </br>
The following Templates were excluded:</br>
<ul>$HTMLexcludedTemplates</ul>
</p>
"@

if(($Data2Report | Measure-Object).Count -gt 0) {

    $HTMLBody = $Data2Report | ConvertTo-Html -Head $HTMLHead -Title $Title -PreContent $HTMLPreContent -Property ExpiresIn,CallerName,Subject,Thumbprint,CertificateTemplateDisplayName
    $Data2Report | ConvertTo-Html -Head $HTMLHead  -Title $Title -PreContent $HTMLPreContent | Out-File $Report

    Send-MailMessage -SmtpServer $SMTPServer -From $SMTPFrom -To $SMTPTo -Attachments $Report -BodyAsHtml ([string]$HTMLBody) -Subject $SMTPSubject -Priority High
} else {
    Write-host "No Certificates expire in the quried time frame"
}
