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
        [Parameter(Mandatory = $true)][PSCredential]
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

    $RestParams = @{
        "Uri" = [System.Uri]"https://$($CyberCNSApiSession.Url)/usermgmt/api/auth"
        "Method" = "POST"
        "Body" = ($json | ConvertTo-Json)
        "ContentType" = "application/json"
    }

    $login = Invoke-RestMethod @RestParams -SessionVariable session
    $CyberCNSApiSession.Session = $session
    if($login.requiredMFA) {
        $MFACode = Read-Host "MFA Code"
        $json.Add('mfa', $MFACode)
        $RestParams = @{
            "Uri" = [System.Uri]"https://$($CyberCNSApiSession.Url)/usermgmt/api/auth"
            "Method" = "POST"
            "Body" = ($json | ConvertTo-Json)
            "ContentType" = "application/json"
        }

        $login = Invoke-RestMethod @RestParams -WebSession $CyberCNSApiSession.Session
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

    $RestParams = @{
        "Uri" = [System.Uri]"https://$($CyberCNSApiSession.Url)/usermgmt/api/o_auth2_authorization_code_grant_client/dummy/handleAuthcode"
        "Method" = "POST"
        "Body" = ($json | ConvertTo-Json)
        "ContentType" = "application/json"
    }

    $response = Invoke-RestMethod @RestParams -WebSession $CyberCNSApiSession.Session
    if($response.status -eq "ok") {
        Write-Output "Login complete."
    }
    else {
        Write-Error "Error: $($response.msg)"
    }
}