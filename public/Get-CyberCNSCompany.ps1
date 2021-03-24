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

        $RestParams = @{
            "Uri" = [System.Uri]"https://$($CyberCNSApiSession.Url)/vulnerability/api/company"
            "Method" = "GET"
            "Body" = $params
            "ContentType" = "application/json"
        }
        
        $response = Invoke-RestMethod @RestParams -WebSession $CyberCNSApiSession.Session
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