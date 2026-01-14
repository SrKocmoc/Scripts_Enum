<#
.SYNOPSIS
  Enumera possíveis credenciais em arquivos (inclui sem extensão), inclusive em paths UNC de rede,
  com opção de exibir os valores completos dos segredos.

.EXAMPLE
  # Exibe valores completos (sem máscara), CSV
  .\enum-cloud-creds-path.ps1 -Path "\\dcB\Temp\" -Recurse -ShowFull -Output ".\creds_full.csv" -Format csv -NoExtensionNames "credentials","config",".env"

.EXAMPLE
  # Mantém máscara (ofusca)
  .\enum-cloud-creds-path.ps1 -Path "C:\Repos" -Recurse -Mask -Output ".\creds_masked.json" -Format json

.EXAMPLE
  # Enumera contendo qualquer arquivo sem extensão
  .\enum-cloud-creds-path.ps1 -Path "\\dcAB\Temp\" -Recurse -ShowFull -Output ".\creds_full.csv" -Format csv `
  -IncludeNoExtension


OBS: Ao utilizar o script algumas credenciais/keys não irão retornar o valor por inteiro sendo necessário você acessar o arquivo manualmente para obter a saída.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$Path,

    [switch]$Recurse = $true,

    # Extensões típicas de configs/segredos
    [string[]]$IncludeExtensions = @("*.json","*.yaml","*.yml","*.ini","*.env","*.config","*.txt","*.tfvars","*.tfstate","*.ps1","*.bat","*.cmd","*.conf","*.properties","*.xml",".npmrc",".git-credentials"),

    # Incluir arquivos sem extensão por nome
    [string[]]$NoExtensionNames = @("credentials","config",".env",".aws",".azure",".gcloud",".docker",".kube",".gitconfig",".git-credentials"),

    # Incluir todos sem extensão (cautela em shares grandes)
    [switch]$IncludeNoExtension,

    [string[]]$ExcludePaths = @("C:\Windows","C:\Program Files","C:\Program Files (x86)","C:\ProgramData","C:\$Recycle.Bin","C:\PerfLogs",".git","node_modules","bin","obj","_archive","_old"),

    [int]$MaxFileSizeMB = 25,

    [string]$Output,

    [ValidateSet("csv","json")]
    [string]$Format = "csv",

    # Ofuscar trechos (se passado)
    [switch]$Mask,

    # NOVO: Forçar mostrar valores completos (sem ofuscação)
    [switch]$ShowFull
)

$ErrorActionPreference = "SilentlyContinue"

# -------- Padrões de busca --------
$KeywordPatterns = @(
    # Genéricos
    'password','pass','pwd','token','secret','key','apikey','api_key',
    'Authorization','Bearer','Basic','connectionString','dsn','sas',
    'SharedAccessKey','SharedAccessSignature','AccountKey','EndpointSuffix',
    # AWS
    'aws_access_key_id','aws_secret_access_key',
    # Azure / AAD / Storage
    'client_id','tenant','client_secret','subscriptionId','accessToken','refreshToken',
    'DefaultEndpointsProtocol','AccountName','AccountKey','SharedAccessSignature',
    # GCP
    '"type": "service_account"','"private_key": "-----BEGIN PRIVATE KEY-----"','project_id','client_email','client_id',
    # Kubernetes
    'client-certificate-data','client-key-data','token:',
    # Terraform
    'access_key','secret_key','subscription_id','tenant_id','client_id','client_secret',
    # Docker
    '"auths"','"auth"','credsStore','credStore','credsHelpers',
    # npm
    '_authToken','npmToken','//registry.npmjs.org/:_authToken'
)

# Regex (cobrem vários provedores)
$RegexPatterns = @(
    # AWS
    'AKIA[0-9A-Z]{16}',                                          # Access key ID
    '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',   # Secret (heurístico)
    # Azure Storage (conn string)
    'DefaultEndpointsProtocol=https;AccountName=.*;AccountKey=.*;EndpointSuffix=.*',
    # SAS (heurístico)
    'SharedAccessSignature=sv=.*?&ss=.*?&srt=.*?&sp=.*?&se=.*?&st=.*?&spr=.*?&sig=.*',
    # GCP service account key
    '-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----',
    # JWT/Bearer (genérico, curta)
    'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    # GUIDs (client_id/Azure tenant etc. – muita ocorrência, mas útil)
    '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b'
)

# -------- Utilidades --------
function Test-IsExcluded {
    param([string]$itemPath, [string[]]$excludes)
    foreach ($ex in $excludes) {
        if ([string]::IsNullOrWhiteSpace($ex)) { continue }
        $normItem = $itemPath.TrimEnd('\')
        $normEx   = $ex.TrimEnd('\')
        if ($normItem.StartsWith($normEx, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

# Se ShowFull estiver ativo, não aplica máscara; se Mask ativo, aplica; caso contrário, não mascara.
function Mask-Line {
    param([string]$line)

    if ($ShowFull) { return $line }
    if (-not $Mask) { return $line }

    $masked = $line
    # Heurísticas de ofuscação
    $masked = $masked -replace '(AKIA[0-9A-Z]{8})([0-9A-Z]{8})', '$1********'
    $masked = $masked -replace '([A-Za-z0-9/+=]{8})([A-Za-z0-9/+=]{32})', '$1********************************'
    $masked = $masked -replace '(AccountKey=)([^;]{6})[^;]*', '$1$2******'
    $masked = $masked -replace '(SharedAccessSignature=)([^&]{6})[^&]*', '$1$2******'
    $masked = $masked -replace '("private_key"\s*:\s*")(.{10}).*(")', '$1$2***$3'
    $masked = $masked -replace '(_authToken=)([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]*', '$1$2******'
    return $masked
}

function Get-FileList {
    param(
        [string[]]$Roots,
        [string[]]$IncludeExtensions,
        [string[]]$NoExtensionNames,
        [switch]$IncludeNoExtension,
        [string[]]$ExcludePaths,
        [switch]$Recurse,
        [int]$MaxFileSizeMB
    )

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        # Se for arquivo, adiciona direto
        if (Test-Path $root -PathType Leaf) {
            try {
                $fi = Get-Item -LiteralPath $root -ErrorAction SilentlyContinue
                if ($fi -and ($fi.Length -le ($MaxFileSizeMB*1MB))) { $files.Add($fi) }
            } catch {}
            continue
        }

        # Pasta → enumera
        try {
            $enum = if ($Recurse) {
                Get-ChildItem -Path $root -File -Force -Recurse -ErrorAction SilentlyContinue
            } else {
                Get-ChildItem -Path $root -File -Force -ErrorAction SilentlyContinue
            }
        } catch { continue }

        foreach ($f in $enum) {
            try {
                if (Test-IsExcluded -itemPath $f.FullName -excludes $ExcludePaths) { continue }
                if ($f.Length -gt ($MaxFileSizeMB*1MB)) { continue }

                $ext = [IO.Path]::GetExtension($f.Name)
                $name = $f.Name
                $match = $false

                if ([string]::IsNullOrEmpty($ext)) {
                    if ($IncludeNoExtension) {
                        $match = $true
                    } else {
                        foreach ($n in $NoExtensionNames) {
                            if ([string]::IsNullOrEmpty($n)) { continue }
                            if ($name -ieq $n -or $name -ilike "*$n*") { $match = $true; break }
                        }
                    }
                } else {
                    foreach ($pattern in $IncludeExtensions) {
                        if ($name -like $pattern) { $match = $true; break }
                    }
                }

                if (-not $match) { continue }
                $files.Add($f)
            } catch {}
        }
    }
    return $files
}

# Leitura segura (strip BOM), retorna objetos com linha/número
function Read-LinesSafe {
    param([string]$Path)
    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
        if ($null -eq $text) { return @() }
        # Remove BOM U+FEFF
        $text = $text -replace "^\uFEFF", ""
        $lines = $text -split "`r`n|`n|`r"
        $out = New-Object System.Collections.Generic.List[object]
        for ($i=0; $i -lt $lines.Count; $i++) {
            $out.Add([pscustomobject]@{
                LineNumber = ($i + 1)
                Line       = $lines[$i]
            })
        }
        return $out
    } catch {
        return @()
    }
}

function Search-InFiles {
    param(
        [System.IO.FileInfo[]]$Files,
        [string[]]$KeywordPatterns,
        [string[]]$RegexPatterns
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($file in $Files) {
        $lines = Read-LinesSafe -Path $file.FullName
        if ($lines.Count -eq 0) { continue }

        # Keywords (como SimpleMatch)
        foreach ($pat in $KeywordPatterns) {
            foreach ($ln in $lines) {
                if ($ln.Line -like "*$pat*") {
                    $snippet = $ln.Line -replace "^\uFEFF", ""
                    $results.Add([pscustomobject]@{
                        Tipo     = "Keyword"
                        Padrao   = $pat
                        Caminho  = $file.FullName
                        Linha    = $ln.LineNumber
                        Trecho   = (Mask-Line ($snippet.Substring(0, [Math]::Min($snippet.Length, 500))).Trim())
                    })
                }
            }
        }

        # Regex (AllMatches)
        foreach ($r in $RegexPatterns) {
            foreach ($ln in $lines) {
                try {
                    $m = [regex]::Matches($ln.Line, $r)
                    if ($m.Count -gt 0) {
                        $snippet = $ln.Line -replace "^\uFEFF", ""
                        $results.Add([pscustomobject]@{
                            Tipo     = "Regex"
                            Padrao   = $r
                            Caminho  = $file.FullName
                            Linha    = $ln.LineNumber
                            Trecho   = (Mask-Line ($snippet.Substring(0, [Math]::Min($snippet.Length, 500))).Trim())
                        })
                    }
                } catch {}
            }
        }
    }

    return $results
}

# -------- Execução --------
Write-Host "[+] Preparando lista de arquivos..." -ForegroundColor Cyan
$roots = $Path | Where-Object { $_ -and ($_ -notmatch '^\s*$') }
$files = Get-FileList -Roots $roots -IncludeExtensions $IncludeExtensions -NoExtensionNames $NoExtensionNames -IncludeNoExtension:$IncludeNoExtension -ExcludePaths $ExcludePaths -Recurse:$Recurse -MaxFileSizeMB $MaxFileSizeMB
Write-Host ("[+] Arquivos candidatos: {0}" -f $files.Count) -ForegroundColor Yellow

Write-Host "[+] Buscando padrões de credenciais..." -ForegroundColor Cyan
$results = Search-InFiles -Files $files -KeywordPatterns $KeywordPatterns -RegexPatterns $RegexPatterns

# -------- Saída --------
if (-not $Output) {
    $results | Sort-Object Caminho, Linha | Format-Table -AutoSize
} else {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $out = $Output
    if ([IO.Path]::GetExtension($out) -eq "") {
        $out = if ($Format -eq "csv") { "$Output`_$ts.csv" } else { "$Output`_$ts.json" }
    }

    if ($Format -eq "csv") {
        $results | Sort-Object Caminho, Linha | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $out
    } else {
        $results | Sort-Object Caminho, Linha | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 -FilePath $out
    }
    Write-Host "[+] Resultados exportados para: $out" -ForegroundColor Green
}


