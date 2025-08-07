function New-GithubSession {
    [OutputType('GitHound.Session')] 
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory = $true)]
        [string]
        $OrganizationName,

        [Parameter(Position=1, Mandatory = $false)]
        [string]
        $ApiUri = 'https://api.github.com/',

        [Parameter(Position=2, Mandatory = $false)]
        [string]
        $Token,

        [Parameter(Position=3, Mandatory = $false)]
        [string]
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',

        [Parameter(Position=4, Mandatory = $false)]
        [HashTable]
        $Headers = @{},

        [Parameter(Mandatory = $false)]
        [int]
        $AppId,

        [Parameter(Mandatory = $false)]
        [int]
        $InstallationId,

        [Parameter(Mandatory = $false)]
        [string]
        $SigningKeyPEM
    )

    if($Headers['Accept']) {
        throw "User-Agent header is specified in both the UserAgent and Headers parameter"
    } else {
        $Headers['Accept'] = 'application/vnd.github+json'
    }

    if($Headers['X-GitHub-Api-Version']) {
        throw "User-Agent header is specified in both the UserAgent and Headers parameter"
    } else {
        $Headers['X-GitHub-Api-Version'] = '2022-11-28'
    }

    if($UserAgent) {
        if($Headers['User-Agent']) {
            throw "User-Agent header is specified in both the UserAgent and Headers parameter"
        } else {
            $Headers['User-Agent'] = $UserAgent
        }
    }

    # Check if multiple authentication methods are provided
    $authMethodCount = 0
    if ($Token) { $authMethodCount++ }
    if ($Headers['Authorization']) { $authMethodCount++ }
    if ($AppId -and $InstallationId -and $SigningKeyPEM) { $authMethodCount++ }

    if ($authMethodCount -gt 1) {
        throw "Multiple authentication methods provided. Please use only one: Token parameter, Authorization header, or GitHub App credentials (AppId, InstallationId, and SigningKeyPEM)"
    }

    if ($authMethodCount -eq 0) {
        throw "No authentication method provided. Please provide one of: Token parameter, Authorization header, or GitHub App credentials (AppId, InstallationId, and SigningKeyPEM)"
    }

    # Check if GitHub App credentials are partially provided
    if (($AppId -and (!$InstallationId -or !$SigningKeyPEM)) -or 
        ($InstallationId -and (!$AppId -or !$SigningKeyPEM)) -or 
        ($SigningKeyPEM -and (!$AppId -or !$InstallationId))) {
        throw "Incomplete GitHub App credentials. All three parameters are required: AppId, InstallationId, and SigningKeyPEM"
    }

    if($Token) {
        $Headers['Authorization'] = "Bearer $Token"

        $session = [PSCustomObject]@{
            PSTypeName = 'GitHound.Session'
            Uri = $ApiUri
            Headers = $Headers
            OrganizationName = $OrganizationName
        }
    }

    if ($AppId -and $InstallationId -and $SigningKeyPEM) {
        try {
            $generatedToken = Invoke-GeneratePATForApp -AppId $AppId -InstallationId $InstallationId -SigningKeyPEM $SigningKeyPEM
            $Headers['Authorization'] = "Bearer $generatedToken"
        }
        catch {
            throw "Failed to generate token from GitHub App credentials: $_"
        }

        $session = [PSCustomObject]@{
            PSTypeName = 'GitHound.Session'
            Uri = $ApiUri
            Headers = $Headers
            OrganizationName = $OrganizationName
            AppId = $AppId
            InstallationId = $InstallationId
            SigningKeyPEM = $SigningKeyPEM
        }
    }

    Write-Verbose "GitHub session created for organization '$OrganizationName'"
    return $session
}

function Invoke-GeneratePATForApp {
    Param(
        [Parameter(Mandatory=$true)]
        [int]
        $AppId,

        [Parameter(Mandatory=$true)]
        [int]
        $InstallationId,

        [Parameter(Mandatory=$true)]
        [string]
        $SigningKeyPEM
    )

    Add-Type -AssemblyName System.Security

    # Current time in Unix timestamp format
    $iat = [int][double]::Parse((Get-Date -UFormat %s))
    $exp = $iat + 600  

    $payload = @{
        'iat' = $iat
        'exp' = $exp
        'iss' = $AppId
    } | ConvertTo-Json -Compress

    # Create JWT using RS256 algorithm
    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        
        # Remove header/footer and decode from Base64
        $pemContent = $SigningKeyPEM -replace "-----BEGIN RSA PRIVATE KEY-----", "" -replace "-----END RSA PRIVATE KEY-----", "" -replace '\s', ""
        $keyBytes = [Convert]::FromBase64String($pemContent)
        
        $rsa.ImportPkcs8PrivateKey($keyBytes, [ref]$null)
        
        $header = @{
            'alg' = 'RS256'
            'typ' = 'JWT'
        } | ConvertTo-Json -Compress
        
        $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)) -replace '\+', '-' -replace '/', '_' -replace '='
        $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)) -replace '\+', '-' -replace '/', '_' -replace '='
        
        $toSign = [System.Text.Encoding]::UTF8.GetBytes("$headerBase64.$payloadBase64")
        $signature = $rsa.SignData($toSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signatureBase64 = [Convert]::ToBase64String($signature) -replace '\+', '-' -replace '/', '_' -replace '='
        
        $jwt = "$headerBase64.$payloadBase64.$signatureBase64"
    }
    catch {
        throw "Failed to create JWT: $_"
    }

    $headers = @{
        'Accept' = 'application/vnd.github+json'
        'Authorization' = "Bearer $jwt"
        'X-GitHub-Api-Version' = '2022-11-28'
    }

    # Request installation access token
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/app/installations/$InstallationId/access_tokens" `
                                     -Method Post `
                                     -Headers $headers `
                                     -ErrorAction Stop

        return $response.token
    }
    catch {
        Write-Error "Failed to get installation token: $_"
        throw
    }
}

function Invoke-GithubRestMethod {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Method = 'GET',

        [Parameter()]
        [switch]
        $TokenRenewalAttempted
    )

    $LinkHeader = $Null;
    try {
        do {
            if($LinkHeader) {
                $Response = Invoke-WebRequest -Uri "$LinkHeader" -Headers $Session.Headers -Method Get -ErrorAction Stop
            } else {
                Write-Verbose "$($Session.Uri)$($Path)"
                $Response = Invoke-WebRequest -Uri "$($Session.Uri)$($Path)" -Headers $Session.Headers -Method $Method -ErrorAction Stop
            }

            $Response.Content | ConvertFrom-Json | ForEach-Object { $_ }

            $LinkHeader = $null
            if($Response.Headers['Link']) {
                $Links = $Response.Headers['Link'].Split(',')
                foreach($Link in $Links) {
                    if($Link.EndsWith('rel="next"')) {
                        $LinkHeader = $Link.Split(';')[0].Trim() -replace '[<>]',''
                        break
                    }
                }
            }

        } while($LinkHeader)
    } catch {
        # Check if this is a 401 Unauthorized error (maybe token expired)
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 401 -and 
            $Session.AppId -and 
            $Session.InstallationId -and 
            $Session.SigningKeyPEM -and 
            -not $TokenRenewalAttempted) {
            
            Write-Verbose "Received 401 Unauthorized, attempting to regenerate token..."
            try {
                $newToken = Invoke-GeneratePATForApp -AppId $Session.AppId -InstallationId $Session.InstallationId -SigningKeyPEM $Session.SigningKeyPEM
                $Session.Headers['Authorization'] = "Bearer $newToken"
                
                # Retry the request with the new token
                return Invoke-GithubRestMethod -Session $Session -Path $Path -Method $Method -TokenRenewalAttempted
            }
            catch {
                Write-Error "Failed to regenerate PAT after 401 error: $_"
                throw
            }
        }
        else {
            Write-Error $_
        }
    }
} 

function Get-Headers
{
    param(
        [Parameter (Mandatory = $TRUE)]
        $GitHubPat
    )

    $headers = @{'Authorization' = "Bearer $($GitHubPat)" }
    return $headers
}

function Invoke-GitHubGraphQL
{
    param(
        [Parameter()]
        [string]
        $Uri = "https://api.github.com/graphql",

        [Parameter()]
        [hashtable]
        $Headers,

        [Parameter()]
        [string]
        $Query,

        [Parameter()]
        [hashtable]
        $Variables
    )

    $Body = @{
        query = $Query
        variables = $Variables
    } | ConvertTo-Json -Depth 100 -Compress

    $fparams = @{
        Uri = $Uri
        Method = 'Post'
        Headers = $Headers
        Body = $Body
    }

    Invoke-RestMethod @fparams
}

function New-GitHoundNode
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $Id,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $Kind,

        [Parameter(Position = 2, Mandatory = $true)]
        [PSObject]
        $Properties
    )

    $props = [pscustomobject]@{
        id = $Id
        kinds = @($Kind, 'GHBase')
        properties = $Properties
    }

    Write-Output $props
}

function New-GitHoundEdge
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $Kind,

        [Parameter(Position = 1, Mandatory = $true)]
        [PSObject]
        $StartId,

        [Parameter(Position = 2, Mandatory = $true)]
        [PSObject]
        $EndId
    )

    $edge = [PSCustomObject]@{
        kind = $Kind
        start = [PSCustomObject]@{
            value = $StartId
        }
        end = [PSCustomObject]@{
            value = $EndId
        }
        properties = @{}
    }

    Write-Output $edge
}

function Normalize-Null
{
    param($Value)
    if ($null -eq $Value) { return "" }
    return $Value
}

function Git-HoundOrganization
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session
    )

    $org = Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Session.OrganizationName)"

    $properties = [pscustomobject]@{
        login                                          = Normalize-Null $org.login
        id                                             = Normalize-Null $org.id
        node_id                                        = Normalize-Null $org.node_id
        name                                           = Normalize-Null $org.name
        blog                                           = Normalize-Null $org.blog
        is_verified                                    = Normalize-Null $org.is_verified
        public_repos                                   = Normalize-Null $org.public_repos
        followers                                      = Normalize-Null $org.followers
        html_url                                       = Normalize-Null $org.html_url
        created_at                                     = Normalize-Null $org.created_at
        updated_at                                     = Normalize-Null $org.updated_at
        total_private_repos                            = Normalize-Null $org.total_private_repos
        owned_private_repos                            = Normalize-Null $org.owned_private_repos
        collaborators                                  = Normalize-Null $org.collaborators
        default_repository_permission                  = Normalize-Null $org.default_repository_permission
        two_factor_requirement_enabled                 = Normalize-Null $org.two_factor_requirement_enabled
        advanced_security_enabled_for_new_repositories = Normalize-Null $org.advanced_security_enabled_for_new_repositories
    }

    Write-Output (New-GitHoundNode -Id $org.node_id -Kind 'GHOrganization' -Properties $properties)
}

function Git-HoundTeam
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Organization
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    foreach($team in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Session.OrganizationName)/teams"))
    {
        $properties = [pscustomobject]@{
            id                = Normalize-Null $team.id
            node_id           = Normalize-Null $team.node_id
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null $team.name
            slug              = Normalize-Null $team.slug
            description       = Normalize-Null $team.description
            privacy           = Normalize-Null $team.privacy
            permission        = Normalize-Null $team.permission
        }
        $null = $nodes.Add((New-GitHoundNode -Id $team.node_id -Kind 'GHTeam' -Properties $properties))
        
        if($null -ne $team.parent)
        {
            $null = $edges.Add((New-GitHoundEdge -Kind GHMemberOf -StartId $team.node_id -EndId $team.Parent.node_id))
        }
    }

    $output = [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }

    Write-Output $output
}

function Git-HoundUser
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Organization
    )

    $nodes = New-Object System.Collections.ArrayList

    foreach($user in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.Properties.login)/members"))
    {
        Write-Verbose "Fetching user details for $($user.login)"

        try {
            $user_details = Invoke-GithubRestMethod -Session $Session -Path "user/$($user.id)"
        } catch {
            Write-Verbose "User $($user.login) could not be found via api"
            continue
        }

        $properties = @{
            id                  = Normalize-Null $user.id
            node_id             = Normalize-Null $user.node_id
            organization_name   = Normalize-Null $Organization.properties.login
            organization_id     = Normalize-Null $Organization.properties.node_id
            login               = Normalize-Null $user.login
            name                = Normalize-Null $user.login
            full_name           = Normalize-Null $user_details.name
            company             = Normalize-Null $user_details.company
            email               = Normalize-Null $user_details.email
            twitter_username    = Normalize-Null $user_details.twitter_username
            type                = Normalize-Null $user.type
            site_admin          = Normalize-Null $user.site_admin
        }
        
        $null = $nodes.Add((New-GitHoundNode -Id $user.node_id -Kind 'GHUser' -Properties $properties))
    }

    Write-Output $nodes
}

function Git-HoundRepository
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Organization
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    foreach($repo in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.Properties.login)/repos"))
    {
        $properties = @{
            id                          = Normalize-Null $repo.id
            node_id                     = Normalize-Null $repo.node_id
            organization_name           = Normalize-Null $Organization.properties.login
            organization_id             = Normalize-Null $Organization.properties.node_id
            name                        = Normalize-Null $repo.name
            full_name                   = Normalize-Null $repo.full_name
            private                     = Normalize-Null $repo.private
            owner_id                    = Normalize-Null $repo.owner.id
            owner_node_id               = Normalize-Null $repo.owner.node_id
            owner_name                  = Normalize-Null $repo.owner.login
            html_url                    = Normalize-Null $repo.html_url
            description                 = Normalize-Null $description
            created_at                  = Normalize-Null $repo.created_at
            updated_at                  = Normalize-Null $repo.updated_at
            pushed_at                   = Normalize-Null $repo.pushed_at
            archived                    = Normalize-Null $repo.archived
            disabled                    = Normalize-Null $repo.disabled
            open_issues_count           = Normalize-Null $repo.open_issues_count
            allow_forking               = Normalize-Null $repo.allow_forking
            web_commit_signoff_required = Normalize-Null $repo.web_commit_signoff_required
            visibility                  = Normalize-Null $repo.visibility
            forks                       = Normalize-Null $repo.forks
            open_issues                 = Normalize-Null $repo.open_issues
            watchers                    = Normalize-Null $repo.watchers
            default_branch              = Normalize-Null $repo.default_branch
            secret_scanning             = Normalize-Null $repo.security_and_analysis.secret_scanning.status
        }
        $nodes.Add((New-GitHoundNode -Id $repo.node_id -Kind 'GHRepository' -Properties $properties)) | Out-Null
        $edges.Add((New-GitHoundEdge -Kind 'GHOwns' -StartId $repo.owner.node_id -EndId $repo.node_id)) | Out-Null
    }

    $output = [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }

    Write-Output $output
}

function Git-HoundBranch
{
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline)]
        [psobject[]]
        $Repository
    )
    
    begin
    {
        $list = [System.Collections.Generic.List[pscustomobject]]::new()
        $nodes = New-Object System.Collections.ArrayList
        $edges = New-Object System.Collections.ArrayList
    }

    process
    {
        foreach($repo in $Repository.nodes)
        {
            foreach($branch in (Invoke-GithubRestMethod -Session $Session -Path "repos/$($repo.properties.full_name)/branches"))
            {
                $BranchProtections = [pscustomobject]@{}
                $BranchProtectionProperties = [ordered]@{}
                if ($branch.protection.enabled -and $branch.protection_url) {
                    $Protections = Invoke-GithubRestMethod -Session $Session -Path "repos/$($repo.Properties.full_name)/branches/$($branch.name)/protection"

                    $BranchProtections | Add-Member -MemberType NoteProperty -Name "EnforceAdmins" -Value $Protections.enforce_admins.enabled
                    $BranchProtections | Add-Member -MemberType NoteProperty -Name "LockBranch" -Value $Protections.lock_branch.enabled
                    $BranchProtectionProperties["protection_enforce_admins"] = $Protections.enforce_admins.enabled
                    $BranchProtectionProperties["protection_lock_branch"] = $Protections.lock_branch.enabled

                    if ($Protections.required_pull_request_reviews) {
                        # pull requests are required before merging

                        $BranchProtectionProperties["protection_required_pull_request_reviews"] = $False
                        
                        $BranchProtections | Add-Member -MemberType NoteProperty -Name "RequiredApprovingReviewCount" -Value $Protections.required_pull_request_reviews.required_approving_review_count
                        $BranchProtections | Add-Member -MemberType NoteProperty -Name "RequireCodeOwnerReviews" -Value $Protections.required_pull_request_reviews.require_code_owner_reviews
                        $BranchProtections | Add-Member -MemberType NoteProperty -Name "RequireLastPushApproval" -Value $Protections.required_pull_request_reviews.require_last_push_approval
                        if ($Protections.required_pull_request_reviews.required_approving_review_count) {
                            $BranchProtectionProperties["protection_required_approving_review_count"] = $Protections.required_pull_request_reviews.required_approving_review_count
                            $BranchProtectionProperties["protection_required_pull_request_reviews"] = $True
                        }
                        else {
                            $BranchProtectionProperties["protection_required_approving_review_count"] = 0
                        }
                        if ($Protections.required_pull_request_reviews.require_code_owner_reviews > 0) {
                            $BranchProtectionProperties["protection_require_code_owner_reviews"] = $Protections.required_pull_request_reviews.require_code_owner_reviews
                            $BranchProtectionProperties["protection_required_pull_request_reviews"] = $True
                        }
                        else {
                            $BranchProtectionProperties["protection_require_code_owner_reviews"] = $False
                        }
                        if ($Protections.required_pull_request_reviews.require_last_push_approval) {
                            $BranchProtectionProperties["protection_require_last_push_approval"] = $Protections.required_pull_request_reviews.require_last_push_approval
                            $BranchProtectionProperties["protection_required_pull_request_reviews"] = $True
                        }
                        else {
                            $BranchProtectionProperties["protection_require_last_push_approval"] = $False
                        }

                        $BypassPrincipals = [System.Collections.Generic.List[pscustomobject]]::new()

                        # We need an edge here
                        foreach($user in $Protections.required_pull_request_reviews.bypass_pull_request_allowances.users) {
                            $principal = [pscustomobject]@{
                                ObjectIdentifier = $user.node_id
                                ObjectType = 'GHUser'
                            }
                            $BypassPrincipals.Add($principal)
                            $null = $edges.Add((New-GitHoundEdge -Kind GHBypassPullRequestAllowances -StartId $user.node_id -EndId $branch.commit.sha))
                        }

                        # We need an edge here
                        foreach($team in $Protections.required_pull_request_reviews.bypass_pull_request_allowances.teams) {
                            $principal = [pscustomobject]@{
                                ObjectIdentifier = $team.node_id
                                ObjectType = 'GHTeam'
                            }
                            $BypassPrincipals.Add($principal)
                            $null = $edges.Add((New-GitHoundEdge -Kind GHBypassPullRequestAllowances -StartId $team.node_id -EndId $branch.commit.sha))
                        }

                        # TODO: handle apps?

                        if ($BypassPrincipals) {
                            $BranchProtections | Add-Member -MemberType NoteProperty -Name "BypassPullRequestAllowances" -Value $BypassPrincipals
                            $BranchProtectionProperties["protection_bypass_pull_request_allowances"] = $BypassPrincipals.Count
                        }
                        else {
                            $BranchProtectionProperties["protection_bypass_pull_request_allowances"] = 0
                        }
                    }
                    else {
                        $BranchProtectionProperties["protection_required_pull_request_reviews"] = $False
                    }

                    if ($Protections.restrictions) {
                        $RestrictionPrincipals = [System.Collections.Generic.List[pscustomobject]]::new()
                        foreach($user in $Protections.restrictions.users) {
                            $principal = [pscustomobject]@{
                                ObjectIdentifier = $user.node_id
                                ObjectType = 'GHUser'
                            }
                            $RestrictionPrincipals.Add($principal)
                            $null = $edges.Add((New-GitHoundEdge -Kind GHRestrictionsCanPush -StartId $user.node_id -EndId $branch.commit.sha))
                        }

                        foreach($team in $Protections.restrictions.team) {
                            $principal = [pscustomobject]@{
                                ObjectIdentifier = $team.node_id
                                ObjectType = 'GHTeam'
                            }
                            $RestrictionPrincipals.Add($principal)
                            $null = $edges.Add((New-GitHoundEdge -Kind GHRestrictionsCanPush -StartId $team.node_id -EndId $branch.commit.sha))
                        }

                        # TODO: handle apps?

                        if ($RestrictionPrincipals) {
                            $BranchProtections | Add-Member -MemberType NoteProperty -Name "Restrictions" -Value $RestrictionPrincipals
                            $BranchProtectionProperties["protection_push_restrictions"] = $RestrictionPrincipals.Count
                        }
                    }
                    else {
                        $BranchProtectionProperties["protection_push_restrictions"] = 0
                    }
                }

                $props = [pscustomobject]@{
                    organization    = Normalize-Null $repo.properties.organization_name
                    organization_id = Normalize-Null $repo.properties.organization_id
                    short_name      = Normalize-Null $branch.name
                    name            = Normalize-Null "$($repo.properties.name)\$($branch.name)"
                    commit_hash     = Normalize-Null $branch.commit.sha
                    commit_url      = Normalize-Null $branch.commit.url
                    protected       = Normalize-Null $branch.protected
                }

                foreach ($BranchProtectionProperty in $BranchProtectionProperties.GetEnumerator()) {
                    $props | Add-Member -MemberType NoteProperty -Name $BranchProtectionProperty.Key -Value $BranchProtectionProperty.Value
                }

                $null = $nodes.Add((New-GitHoundNode -Id $branch.commit.sha -Kind GHBranch -Properties $props))
                $null = $edges.Add((New-GitHoundEdge -Kind GHHasBranch -StartId $repo.id -EndId $branch.commit.sha))
            }
        }

        $output = [PSCustomObject]@{
            Nodes = $nodes
            Edges = $edges
        }
    
        Write-Output $output
    }

    end
    {
        Write-Output $list.ToArray()
    }
}

function Git-HoundOrganizationRole
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Organization
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    $orgAllRepoReadId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_read"))
    $orgAllRepoTriageId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_triage"))
    $orgAllRepoWriteId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_write"))
    $orgAllRepoMaintainId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_maintain"))
    $orgAllRepoAdminId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_admin"))

    foreach($customrole in (Invoke-GithubRestMethod -Session $session -Path "orgs/$($Organization.Properties.login)/organization-roles").roles)
    {
        $customRoleId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_$($customrole.name)"))
        $customRoleProps = [pscustomobject]@{
            id                = Normalize-Null $customRoleId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($Organization.Properties.login)/$($customrole.name)"
            short_name        = Normalize-Null $customrole.name
            type              = Normalize-Null 'organization'
        }
        $nodes.Add((New-GitHoundNode -Id $customRoleId -Kind 'GHOrgRole' -Properties $customRoleProps)) | Out-Null

        foreach($team in (Invoke-GithubRestMethod -Session $session -Path "orgs/$($Organization.Properties.login)/organization-roles/$($customRole.id)/teams"))
        {
            $edges.Add((New-GitHoundEdge -Kind GHHasRole -StartId $team.node_id -EndId $customRoleId)) | Out-Null
        }

        foreach($user in (Invoke-GithubRestMethod -Session $session -Path "orgs/$($Organization.Properties.login)/organization-roles/$($customRole.id)/users"))
        {
            $edges.Add((New-GitHoundEdge -Kind GHHasRole -StartId $user.node_id -EndId $customRoleId)) | Out-Null
        }

        if($null -ne $customrole.base_role)
        {
            switch($customrole.base_role)
            {
                'read' {$baseId = $orgAllRepoReadId}
                'triage' {$baseId = $orgAllRepoTriageId}
                'write' {$baseId = $orgAllRepoWriteId}
                'maintain' {$baseId = $orgAllRepoMaintainId}
                'admin' {$baseId = $orgAllRepoAdminId}
            }
            $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $customRoleId -EndId $baseId))
        }

        # Need to add support for custom permissions here
    }

    $orgOwnersId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($organization.id)_owners"))
    $ownersProps = [pscustomobject]@{
        id                = Normalize-Null $orgOwnersId
        organization_name = Normalize-Null $Organization.properties.login
        organization_id   = Normalize-Null $Organization.properties.node_id
        name              = Normalize-Null "$($Organization.Properties.login)/owners"
        short_name        = Normalize-Null 'owners'
        type              = Normalize-Null 'organization'
    }
    $null = $nodes.Add((New-GitHoundNode -Id $orgOwnersId -Kind 'GHOrgRole' -Properties $ownersProps))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateRepository' -StartId $orgOwnersId -EndId $Organization.id))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHInviteMember' -StartId $orgOwnersId -EndId $Organization.id))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHAddCollaborator' -StartId $orgOwnersId -EndId $Organization.id))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateTeam' -StartId $orgOwnersId -EndId $Organization.id))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHTransferRepository' -StartId $orgOwnersId -EndId $Organization.id))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgOwnersId -EndId $orgAllRepoAdminId))

    $orgMembersId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($organization.id)_members"))
    $membersProps = [pscustomobject]@{
        id                = Normalize-Null $orgMembersId
        organization_name = Normalize-Null $Organization.properties.login
        organization_id   = Normalize-Null $Organization.properties.node_id
        name              = Normalize-Null "$($Organization.Properties.login)/members"
        short_name        = Normalize-Null 'members'
        type              = Normalize-Null 'organization'
    }
    $null = $nodes.Add((New-GitHoundNode -Id $orgMembersId -Kind 'GHOrgRole' -Properties $membersProps))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateRepository' -StartId $orgMembersId -EndId $Organization.id))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateTeam' -StartId $orgMembersId -EndId $Organization.id))

    if($Organization.Properties.default_repository_permission -ne 'none')
    {
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgMembersId -EndId ([Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_$($Organization.properties.default_repository_permission)")))))
    }

    # Need to add custom role membership here
    foreach($user in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($organization.Properties.login)/members"))
    {
        switch((Invoke-GithubRestMethod -Session $Session -Path "orgs/$($organization.Properties.login)/memberships/$($user.login)").role)
        {
            'admin' { $destId = $orgOwnersId}
            'member' { $destId = $orgMembersId }
            #'moderator' { $orgmoderatorsList.Add($m) }
            #'security admin' { $orgsecurityList.Add($m) }
        }
        $null = $edges.Add($(New-GitHoundEdge -Kind 'GHHasRole' -StartId $user.node_id -EndId $destId))
    }

    $output = [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }

    Write-Output $output
}

function Git-HoundTeamRole
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Organization
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    foreach($team in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.Properties.login)/teams"))
    {
        $memberId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($team.node_id)_members"))
        $memberProps = [pscustomobject]@{
            id                = Normalize-Null $memberId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($Organization.Properties.login)/$($team.slug)/members"
            short_name        = Normalize-Null 'members'
            type              = Normalize-Null 'team'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $memberId -Kind 'GHTeamRole' -Properties $memberProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHMemberOf' -StartId $memberId -EndId $team.node_id))

        $maintainerId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($team.node_id)_maintainers"))
        $maintainerProps = [pscustomobject]@{
            id                = Normalize-Null $maintainerId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($Organization.Properties.login)/$($team.slug)/maintainers"
            short_name        = Normalize-Null 'maintainers'
            type              = Normalize-Null 'team'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $maintainerId -Kind 'GHTeamRole' -Properties $maintainerProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHMemberOf' -StartId $maintainerId -EndId $team.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHAddMember' -StartId $maintainerId -EndId $team.node_id))

        foreach($member in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.Properties.login)/teams/$($team.slug)/members"))
        {
            switch((Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.Properties.login)/teams/$($team.slug)/memberships/$($member.login)").role)
            {
                'member' { $targetId = $memberId }
                'maintainer' { $targetId = $maintainerId }
            }
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $member.node_id -EndId $targetId))
        }
    }

    $output = [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }

    Write-Output $output
}

function Git-HoundRepositoryRole
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Organization
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    $orgAllRepoReadId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_read"))
    $orgAllRepoTriageId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_triage"))
    $orgAllRepoWriteId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_write"))
    $orgAllRepoMaintainId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_maintain"))
    $orgAllRepoAdminId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_all_repo_admin"))

    $customRepoRoles = (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.Properties.login)/custom-repository-roles").custom_roles

    foreach($repo in (Invoke-GithubRestMethod -Session $Session -Path "orgs/$($Organization.properties.login)/repos"))
    {
        # Create $repo Read Role
        $repoReadId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_read"))
        $repoReadProps = [pscustomobject]@{
            id                = Normalize-Null $repoReadId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($repo.full_name)/read"
            short_name        = Normalize-Null 'read'
            type              = Normalize-Null 'repository'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoReadId -Kind 'GHRepoRole' -Properties $repoReadProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHCanPull' -StartId $repoReadId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHReadRepoContents' -StartId $repoReadId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoReadId -EndId $repoReadId))

        # Create $repo Write Role
        $repoWriteId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_write"))
        $repoWriteProps = [pscustomobject]@{
            id                = Normalize-Null $repoWriteId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($repo.full_name)/write"
            short_name        = Normalize-Null 'write'
            type              = Normalize-Null 'repository'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoWriteId -Kind 'GHRepoRole' -Properties $repoWriteProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHCanPush' -StartId $repoWriteId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHCanPull' -StartId $repoWriteId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHReadRepoContents' -StartId $repoWriteId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoContents' -StartId $repoWriteId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoPullRequests' -StartId $repoWriteId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoWriteId -EndId $repoWriteId))

        # Create $repo Admin Role
        $repoAdminId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_admin"))
        $repoAdminProps = [pscustomobject]@{
            id                = Normalize-Null $repoAdminId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($repo.full_name)/admin"
            short_name        = Normalize-Null 'admin'
            type              = Normalize-Null 'repository'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoAdminId -Kind 'GHRepoRole' -Properties $repoAdminProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHAdminTo' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHCanPush' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHCanPull' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHReadRepoContents' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoContents' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoPullRequests' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHManageWebhooks' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHManageDeployKeys' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHPushProtectedBranch' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHDeleteAlertsCodeScanning' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHViewSecretScanningAlerts' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHRunOrgMigration' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHBypassProtections' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHManageSecurityProducts' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHManageRepoSecurityProducts' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHEditProtections' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHJumpMergeQueue' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateSoloMergeQueueEntry' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHEditRepoCustomPropertiesValues' -StartId $repoAdminId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoAdminId -EndId $repoAdminId))

        # Create $repo Triage Role
        $repoTriageId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_triage"))
        $repoTriageProps = [pscustomobject]@{
            id                = Normalize-Null $repoTriageId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($repo.full_name)/triage"
            short_name        = Normalize-Null 'triage'
            type              = Normalize-Null 'repository'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoTriageId -Kind 'GHRepoRole' -Properties $repoTriageProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $repoTriageId -EndId $repoReadId))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoTriageId -EndId $repoTriageId))

        # Create $repo Maintain Role
        $repoMaintainId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_maintain"))
        $repoMaintainProps = [pscustomobject]@{
            id                = Normalize-Null $repoMaintainId
            organization_name = Normalize-Null $Organization.properties.login
            organization_id   = Normalize-Null $Organization.properties.node_id
            name              = Normalize-Null "$($repo.full_name)/maintain"
            short_name        = Normalize-Null 'maintain'
            type              = Normalize-Null 'repository'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoMaintainId -Kind 'GHRepoRole' -Properties $repoMaintainProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHPushProtectedBranch' -StartId $repoMaintainId -EndId $repo.node_id))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $repoMaintainId -EndId $repoWriteId))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoMaintainId -EndId $repoMaintainId))

        # Custom Organization Roles (Setting Base Roles)
        # I wonder if this should be adapted to point to the relevant all_repo_* org role
        <#
        foreach($customOrgRole in $customOrgRoles)
        {
            if($null -ne $customOrgRole.base_role)
            {
                $customOrgRoleStartId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Organization.id)_$($customOrgRole.name)"))
                $customOrgRoleEndId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_$($customOrgRole.base_role)"))
                $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $customOrgRoleStartId -EndId $customOrgRoleEndId)) | Out-Null
            }
        }
        #>

        # Custom Repository Roles
        foreach($customRepoRole in $customRepoRoles)
        {
            $customRepoRoleId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_$($customRepoRole.name)"))
            $customRepoRoleProps = [pscustomobject]@{
                id                = Normalize-Null $customRepoRoleId
                organization_name = Normalize-Null $Organization.properties.login
                organization_id   = Normalize-Null $Organization.properties.node_id
                name              = Normalize-Null "$($repo.full_name)/$($customRepoRole.name)"
                short_name        = Normalize-Null $customRepoRole.name
                type              = Normalize-Null 'repository'
            }
            $null = $nodes.Add((New-GitHoundNode -Id $customRepoRoleId -Kind 'GHRepoRole' -Properties $customRepoRoleProps))
            
            if($null -ne $customRepoRole.base_role)
            {
                $targetBaseRoleId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_$($customRepoRole.base_role)"))
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $customRepoRoleId -EndId $targetBaseRoleId))
            }
            
            foreach($permission in $customRepoRole.permissions)
            {
                switch($permission)
                {
                    'manage_webhooks' {$edges.Add((New-GitHoundEdge -Kind GHManageWebhooks -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'manage_deploy_keys' {$edges.Add((New-GitHoundEdge -Kind GHManageDeployKeys -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'push_protected_branch' {$edges.Add((New-GitHoundEdge -Kind GHPushProtectedBranch -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'delete_alerts_code_scanning' {$edges.Add((New-GitHoundEdge -Kind GHDeleteAlertsCodeScanning -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'view_secret_scanning_alerts' {$edges.Add((New-GitHoundEdge -Kind GHViewSecretScanningAlerts -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'bypass_branch_protection' {$edges.Add((New-GitHoundEdge -Kind GHBypassProtections -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'edit_repo_protections' {$edges.Add((New-GitHoundEdge -Kind GHEditProtections -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'jump_merge_queue' {$edges.Add((New-GitHoundEdge -Kind GHJumpMergeQueue -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'create_solo_merge_queue_entry' {$edges.Add((New-GitHoundEdge -Kind GHCreateSoloMergeQueueEntry -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                    'edit_repo_custom_properties_values' {$edges.Add((New-GitHoundEdge -Kind GHEditRepoCustomPropertiesValues -StartId $customRepoRoleId -EndId $repo.node_id)) | Out-Null}
                }
            }
        }

        # Finding Members...
        ## GHUser Members
        foreach($collaborator in (Invoke-GithubRestMethod -Session $Session -Path "repos/$($Organization.Properties.login)/$($repo.name)/collaborators?affiliation=direct"))
        {
            switch($collaborator.role_name)
            {
                'admin' { $repoRoleId = $repoAdminId }
                'maintain' { $repoRoleId = $repoMaintainId }
                'write' { $repoRoleId = $repoWriteId }
                'triage' { $repoRoleId = $repoTriageId }
                'read' { $repoRoleId = $repoReadId }
                default { $repoRoleId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_$($collaborator.role_name)"))}
            }
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $collaborator.node_id -EndId $repoRoleId))
        }

        ## GHTeam Members
        foreach($team in (Invoke-GithubRestMethod -Session $Session -Path "repos/$($Organization.Properties.login)/$($repo.name)/teams"))
        {
            switch($team.permission)
            {
                'admin' { $repoRoleId =  $repoAdminId }
                'maintain' { $repoRoleId =  $repoMaintainId }
                'push' { $repoRoleId = $repoWriteId }
                'triage' { $repoRoleId = $repoTriageId }
                'pull' { $repoRoleId = $repoReadId }
                default { $repoRoleId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.node_id)_$($team.permission)")) }
            }
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $team.node_id -EndId $repoRoleId))
        }
    }

    $output = [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }

    Write-Output $output
}

function Git-HoundGraphQlSamlProvider
{
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session
    )

    $Query = @'
query SAML($login: String!, $count: Int = 100, $after: String = null) {
    organization(login: $login) {
        id
        name
        samlIdentityProvider
        {
            digestMethod
            externalIdentities(first: $count, after: $after)
            {
                nodes
                {
                    guid
                    id
                    samlIdentity
                    {
                        attributes
                        {
                            metadata
                            name
                            value
                        }
                        familyName
                        givenName
                        groups
                        nameId
                        username
                    }
                    user
                    {
                        id
                        login
                    }
                }
                pageInfo
                {
                    endCursor
                    hasNextPage
                }
                totalCount
            }
            id
            idpCertificate
            issuer
            signatureMethod
            ssoUrl
        }
    }
}
'@

    $Variables = @{
        login = $Session.OrganizationName
        count = 100
        after = $null
    }
    
    $edges = New-Object System.Collections.ArrayList

    do{
        $result = Invoke-GitHubGraphQL -Headers $Session.Headers -Query $Query -Variables $Variables

        foreach($identity in $result.data.organization.samlIdentityProvider.externalIdentities.nodes)
        {
            foreach($attribute in $identity.samlIdentity.attributes)
            {
                if($attribute.name -eq "http://schemas.microsoft.com/identity/claims/objectidentifier")
                {
                    $null = $edges.Add((New-GitHoundEdge -Kind SyncedToGHUser -StartId $attribute.value -EndId $identity.user.id))
                }
            }
        }

        $Variables['after'] = $result.data.organization.samlIdentityProvider.externalIdentities.pageInfo.endCursor
    }
    while($result.data.organization.samlIdentityProvider.externalIdentities.pageInfo.hasNextPage)

    Write-Output $edges
}

function Invoke-GitHound
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]
        $Session
    )

    $edges = New-Object System.Collections.ArrayList
    $nodes = New-Object System.Collections.ArrayList

    $org = Git-HoundOrganization -Session $Session
    $nodes.Add($org) | Out-Null

    $users = $org | Git-HoundUser -Session $Session
    if($users) { $nodes.AddRange(@($users)) }

    $teams = $org | Git-HoundTeam -Session $Session
    if($teams.nodes) { $nodes.AddRange(@($teams.nodes)) }
    if($teams.edges) { $edges.AddRange(@($teams.edges)) }

    $repos = $org | Git-HoundRepository -Session $Session
    if($repos.nodes) { $nodes.AddRange(@($repos.nodes)) }
    if($repos.edges) { $edges.AddRange(@($repos.edges)) }

    $branches = $repos | Git-HoundBranch -Session $Session
    if($branches.nodes) { $nodes.AddRange(@($branches.nodes)) }
    if($branches.edges) { $edges.AddRange(@($branches.edges)) }

    $teamroles = $org | Git-HoundTeamRole -Session $Session
    if($teamroles.nodes) { $nodes.AddRange(@($teamroles.nodes)) }
    if($teamroles.edges) { $edges.AddRange(@($teamroles.edges)) }

    $orgroles = $org | Git-HoundOrganizationRole -Session $Session
    if($orgroles.nodes) { $nodes.AddRange(@($orgroles.nodes)) }
    if($orgroles.edges) { $edges.AddRange(@($orgroles.edges)) }

    $reporoles = $org | Git-HoundRepositoryRole -Session $Session
    if($reporoles.nodes) { $nodes.AddRange(@($reporoles.nodes)) }
    if($reporoles.edges) { $edges.AddRange(@($reporoles.edges)) }

    $saml = Git-HoundGraphQlSamlProvider -Session $Session
    if($saml) { $edges.AddRange(@($saml)) }

    $payload = [PSCustomObject]@{
        metadata = [PSCustomObject]@{
            source_kind = "GHBase"
        }
        graph = [PSCustomObject]@{
            nodes = $nodes.ToArray()
            edges = $edges.ToArray()
        }
    } | ConvertTo-Json -Depth 10 | Out-File -FilePath "./githound_$($org.id).json"

    #$payload | BHDataUploadJSON
}
