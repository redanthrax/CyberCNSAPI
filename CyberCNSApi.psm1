
$CyberCNSApiSession = @{
    Url = $null
    Session = $null
}

function Get-PublicKey {
    <#
        .SYNOPSIS
            Gets the Base64 encoded public key from CyberCNS used to encrypt the password for login in a text format.
        
        .EXAMPLE
            $publicKey = Get-PublicKey

        .OUTPUTS
            Returns string formatted version of the Public Key from CyberCNS.
    #>

    $base64CertResponse = Invoke-RestMethod "https://$($CyberCNSApiSession.Url)/vulnerability/api/utils/dummy/getEncryptionKey"
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64CertResponse.msg))
}

function Connect-CyberCNSApi {
    <#
        .SYNOPSIS
            Connects to the CyberCNS API and stores the session.

        .EXAMPLE
            Connect-CyberCNSApi -Credential (Get-Credential) -MFACode 123456

        .OUTPUTS
            Returns a string or error depending on successful login.

    #>
    param(
        #The base url for cybercns. Ex. company.mycybercns.com
        [String]
        [Parameter(Mandatory)]
        $Url,

        #The email username and password used to login to the mycybercns.com site.
        [System.Management.Automation.PSCredential]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        $Credential,

        #A current MFA code if MFA is enabled for the account.
        [String]
        $MFACode
    )

    $CyberCNSApiSession.url = $Url
    $publicKey = Get-PublicKey
    $pubkey = $publicKey -replace "-----BEGIN PUBLIC KEY-----","" -replace "-----END PUBLIC KEY-----","" -replace "`r`n",""
    $pubKeyBytes = [System.Convert]::FromBase64String($pubKey)
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Credential.GetNetworkCredential().Password)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportSubjectPublicKeyInfo($pubKeyBytes, [ref]$null)
    $encBytes = $rsa.Encrypt($passwordBytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $encBase64 = [System.Convert]::ToBase64String($encBytes)

    $json = @{
        "email" = $Credential.UserName
        "password" = $encBase64
        "redirect_uri" = "https://$($CyberCNSApiSession.Url)/login/oauth2_authorization_code_grant_callback?method=LocalAuth"
    }

    $login = Invoke-RestMethod "https://$($CyberCNSApiSession.Url)/usermgmt/api/auth" `
        -Method "POST" -Body ($json | ConvertTo-Json) -ContentType "application/json" -SessionVariable session

    
    $CyberCNSApiSession.Session = $session

    if($login.requiredMFA) {
        $MFACode = Read-Host "MFA Code"
        $json += @{ mfa = $MFACode }
        $login = Invoke-RestMethod "https://$($CyberCNSApiSession.Url)/usermgmt/api/auth" `
            -Method "POST" -Body ($json | ConvertTo-Json) -ContentType "application/json" -WebSession $CyberCNSApiSession.Session
    }

    if($login.status -and $login.status -eq "error") {
        Write-Error "Error: $($login.msg)"
        return
    }

    $authUrl = [System.Uri]$login.location
    $parsed = [System.Web.HttpUtility]::ParseQueryString($authUrl)
    $code = $parsed[1]

    $json = @{
        code = $code
        method = "LocalAuth"
    }

    $response = Invoke-RestMethod "https://$($CyberCNSApiSession.Url)/usermgmt/api/o_auth2_authorization_code_grant_client/dummy/handleAuthcode" `
        -Method "POST" -Body ($json | ConvertTo-Json) -ContentType "application/json" -WebSession $CyberCNSApiSession.Session
    if($response.status -eq "ok") {
        Write-Output "Login complete."
    }
    else {
        Write-Error "Error: $($response.msg)"
    }
}

function Get-CyberCNSQuery {
    <#
        .SYNOPSIS
            Builds the CyberCNS query in order to query the API.
        .EXAMPLE
            $companyQuery = Get-CyberCNSQuery -Family "company" -Species "company"
        .OUTPUTS
            Returns a query needed for the API query.
    #>
    param(
        #The query family
        [String]
        [Parameter(Mandatory)]
        $Family,
        #The query species
        [String]
        [Parameter(Mandatory)]
        $Species,
        #The query Company ID
        [String]
        $CompanyID
    )

    $query = @{
        "query" = @{
            "bool" = @{ 
                "must" = @(
                    @{
                        "match" = @{
                            "family.keyword" = $Family
                        }
                    },
                    @{
                        "bool" = @{
                            "should" = @(
                                @{ 
                                    "match" = @{
                                        "species.keyword" = $Species
                                    }
                                }
                            )
                        }
                    }
                )
            }
        }
    }

    if($CompanyID) {
        $query.query.bool.must += @{
            "match" = @{
                "companyid.keyword" = $CompanyID
            }
        }
    }

    return $query
}

function Get-CyberCNSCompany {
    <#
        .SYNOPSIS
            Gets all CyberCNS Companies or specify the Company with -Name
        .EXAMPLE
            $companies = Get-CyberCNSCompany
            $company = Get-CyberCNSCompany -Name ACME
        .OUTPUTS
            Returns a Company with Name and Id or list of Company with Name and Id
    #>
    param(
        #The name of the Company in CyberCNS
        [String]
        $Name
    )

    if(-Not($CyberCNSApiSession.Session)) {
        Write-Error "Please use Connect-CyberCNSApi first."
    }
    else {
        $query = Get-CyberCNSQuery -Family "company" -Species "company"
        $queryJson = ($query | ConvertTo-Json -Depth 10 -Compress)
        $params = @{
            skip = 0
            limit = 200
            query = $queryJson
        }

        $response = Invoke-RestMethod "https://$($CyberCNSApiSession.Url)/vulnerability/api/company" `
            -Method "GET" -Body $params -ContentType "application/json" -WebSession $CyberCNSApiSession.Session
        if($response.status -and $response.status -ne "ok") {
            Write-Error "Error: $($response.msg)"
        }
        else {
            $companies = @()
            $companiesData = $response.msg.data
            foreach($company in $companiesData) {
                $newCompany = @{
                    Name = $company.name
                    Id = $company._id
                }

                if($Name -eq $newCompany.Name) {
                    return $newCompany
                }

                $companies += $newCompany
            }

            if($Name) {
                Write-Error "Could not find $Name"
                return
            }

            return $companies
        }
    }
}

function Get-CyberCNSAsset {
    <#
        .SYNOPSIS
            Gets all CyberCNS Assets or gets all CyberCNS Assets based on company
        .EXAMPLE
            $assets = Get-CyberCNSAsset
            $assets = Get-CyberCNSCompany -Name ACME | Get-CyberCNSAsset
            $assets = Get-CyberCNSAsset -CompanyId $company.Id
        .OUTPUTS
            Returns a list of Assets
    #>
    [CmdletBinding()]
    param(
        #A Company from the pipeline
        [Parameter(ValueFromPipeline)]
        $Company,
        #The Id of the Company
        [String]
        $CompanyId,
        #The name of the Asset
        [String]
        $Name
    )

    $query = $null
    if($Company) {
        $query = Get-CyberCNSQuery -Family "assets" -Species "assets" -CompanyID $Company.Id
    }
    elseif($CompanyId) {
        $query = Get-CyberCNSQuery -Family "assets" -Species "assets" -CompanyID $CompanyId
    }
    else {
        $query = Get-CyberCNSQuery -Family "assets" -Species "assets"
    }

    $queryJson = ($query | ConvertTo-Json -Depth 10 -Compress)
    $params = @{
        skip = 0
        limit = 200
        query = $queryJson
    }

    $response = Invoke-RestMethod "https://$($CyberCNSApiSession.Url)/vulnerability/api/assets" `
        -Method "GET" -Body $params -ContentType "application/json" -WebSession $CyberCNSApiSession.Session

    if($response.status -ne "ok") {
        Write-Error "Error: $($response.msg)"
    }
    else {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $assets = @()
        $assetsData = $response.msg.data
        foreach($asset in $assetsData) {
            $newAsset = @{
                Id = $asset._id
                Name = $asset.assetName
                Ports = $asset.ports
                Created = $origin.AddSeconds($asset.created)
                Updated = $origin.AddSeconds($asset.updated)
                Risk = $asset.vulnerability_risk
                OS = $asset.os
                Vulnerabilities = $asset.vulnerabilities
                IP = $asset.ip_addr
            }

            

            $assets += $newAsset
        }

        return $assets
    }
}

Export-ModuleMember -Function Connect-CyberCNSApi
Export-ModuleMember -Function Get*