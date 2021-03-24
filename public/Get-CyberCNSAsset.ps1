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

    $RestParams = @{
        "Uri" = [System.Uri]"https://$($CyberCNSApiSession.Url)/vulnerability/api/assets"
        "Method" = "GET"
        "Body" = $params
        "ContentType" = "application/json"
    }
    $response = Invoke-RestMethod @RestParams -WebSession $CyberCNSApiSession.Session

    if($response.status -ne "ok") {
        Write-Error "Error: $($response.msg)"
    }
    else {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $assets = @()
        $assetsData = $response.msg.data
        $assets = foreach($asset in $assetsData) {
            [pscustomobject]@{
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
        }

        return $assets
    }
}