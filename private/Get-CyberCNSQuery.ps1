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