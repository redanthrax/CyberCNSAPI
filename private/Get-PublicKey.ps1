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