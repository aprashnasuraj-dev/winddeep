<#
.SYNOPSIS
Configures main-branch protection through the GitHub REST API.
.DESCRIPTION
Requires a fine-grained token with repository Administration write permission.
The connected GitHub app used for automated repository work does not expose
branch-protection mutation, so this script provides a reproducible repository-
owned configuration path.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Repository = 'aprashnasuraj-dev/winddeep',
    [string]$Branch = 'main'
)

$ErrorActionPreference = 'Stop'
$headers = @{
    Authorization = "Bearer $Token"
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
}
$body = @{
    required_status_checks = @{
        strict = $true
        contexts = @('test', 'build-windows')
    }
    enforce_admins = $true
    required_pull_request_reviews = @{
        dismiss_stale_reviews = $true
        require_code_owner_reviews = $false
        required_approving_review_count = 1
    }
    restrictions = $null
    required_linear_history = $false
    allow_force_pushes = $false
    allow_deletions = $false
    block_creations = $false
    required_conversation_resolution = $true
    lock_branch = $false
    allow_fork_syncing = $true
} | ConvertTo-Json -Depth 8

$uri = "https://api.github.com/repos/$Repository/branches/$Branch/protection"
Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $body -ContentType 'application/json' | Out-Null
Write-Host "Branch protection configured for ${Repository}:${Branch}"
