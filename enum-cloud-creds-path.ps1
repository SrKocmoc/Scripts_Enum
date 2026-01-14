<#
.SYNOPSIS
  Enumera possíveis credenciais em arquivos (inclusive sem extensão) em paths locais e UNC,  com saída em CSV/JSON/TXT/HTML, highlight de matches e resumo.

.USAGE (básico)
  Enumera possíveis credenciais em arquivos (inclui sem extensão), inclusive em paths UNC de rede, com opção de exibir os valores completos dos segredos.
  .\enum-cloud-creds-path.ps1 -Path "\\servidor\share\projeto"

.EXAMPLE
  # Exibe valores completos (sem máscara), CSV
  .\enum-cloud-creds-path.ps1 -Path "\\dcB\Temp\" -Recurse -ShowFull -Output ".\creds_full.csv" -Format csv -NoExtensionNames "credentials","config",".env"

.EXAMPLE
  # Mantém máscara (ofusca)
  .\enum-cloud-creds-path.ps1 -Path "C:\Repos" -Recurse -Mask -Output ".\creds_masked.json" -Format json

.EXAMPLE
  # Enumera contendo qualquer arquivo sem extensão
  .\enum-cloud-creds-path.ps1 -Path "\\dcAB\Temp\" -Recurse -ShowFull -Output ".\creds_full.csv" -Format csv -IncludeNoExtension


OBS: Ao utilizar o script algumas credenciais/keys não irão retornar o valor por inteiro sendo necessário você acessar o arquivo manualmente para obter a saída. .PARAMETERS (principais)
  -Path                Um ou mais caminhos (local ou UNC). Aceita pastas ou arquivos.
  -Format              csv|json|txt|html  (padrão: html)
  -Output              Caminho do arquivo de saída. Se omitido, grava na pasta atual com timestamp.
  -Recurse             Recursivo (padrão: true)
  -Mask                Ofusca trechos sensíveis (desativa o ShowFull).
  -ShowFull            Mostra valores completos (padrão: true).

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$Path,

    # Recursão ativada por padrão
    [switch]$Recurse = $true,

    # Extensões padrão sempre incluídas (ampliadas)
    [string[]]$IncludeExtensions = @(
        "*.json","*.yaml","*.yml","*.ini","*.env","*.config","*.txt",
        "*.tfvars","*.tfstate","*.ps1","*.bat","*.cmd","*.conf",
        "*.properties","*.xml",".npmrc",".git-credentials",
        "*.pem","*.key","*.crt","*.cfg","*.cnf",".dockercfg","*.kubeconfig"
    ),

    # Arquivos sem extensão comuns
    [string[]]$NoExtensionNames = @(
        "credentials","python_history","config",".env",".aws",".azure",".gcloud",
        ".docker",".kube",".git",".gitconfig",".git-credentials","id_rsa","id_dsa"
    ),

    # Inclui todos os arquivos sem extensão por padrão
    [switch]$IncludeNoExtension = $true,

    # Exclusões comuns (pode ajustar conforme ambiente)
    [string[]]$ExcludePaths = @(
        "C:\Windows","C:\Program Files","C:\Program Files (x86)",
        "C:\ProgramData","C:\$Recycle.Bin","C:\PerfLogs",
        ".git","node_modules","bin","obj","_archive","_old",".venv",".tox",".gradle",".m2",".cache"
    ),

    # Evita ler arquivos grandes (binários, etc.)
    [int]$MaxFileSizeMB = 25,

    # Saída e formato (padrão: HTML bonito)
    [string]$Output,
    [ValidateSet("csv","json","txt","html")]
    [string]$Format = "html",

    # Exibição: por padrão mostramos tudo (-ShowFull = true)
    [switch]$Mask,
    [switch]$ShowFull = $true
)

$ErrorActionPreference = "SilentlyContinue"

# ---------------------- Padrões de busca ----------------------
# Keywords (inclui variações em MAIÚSCULAS comuns em env/config)
$KeywordPatterns = @(
    # Genéricos
    'password','PASSWORD','pass','pwd','token','TOKEN','secret','SECRET','key','apikey','api_key',
    'Authorization','Bearer','Basic','connectionString','dsn','sas',
    'SharedAccessKey','SharedAccessSignature','AccountKey','EndpointSuffix',
    # AWS
    'aws_access_key_id','aws_secret_access_key','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN',
    # Azure / AAD / Storage
    'client_id','tenant','client_secret','subscriptionId','accessToken','refreshToken',
    'CLIENT_ID','CLIENT_SECRET','TENANT_ID','SUBSCRIPTION_ID',
    'DefaultEndpointsProtocol','AccountName','AccountKey','SharedAccessSignature',
    # GCP
    '"type": "service_account"','"private_key": "-----BEGIN PRIVATE KEY-----"','project_id','client_email','client_id',
    'GOOGLE_APPLICATION_CREDENTIALS',
    # Kubernetes
    'client-certificate-data','client-key-data','token:','kubeconfig',
    # Terraform
    'access_key','secret_key','subscription_id','tenant_id','client_id','client_secret','TF_VAR_',
    # Docker
    '"auths"','"auth"','credsStore','credStore','credsHelpers',
    # npm
    '_authToken','npmToken','//registry.npmjs.org/:_authToken',
    # Outras variáveis comuns
    'DB_PASSWORD','DB_USER','DB_PASS','DATABASE_URL','CONNECTION_STRING','REDIS_URL','RABBITMQ_URL'
)

# Regex (algumas heurísticas)
$RegexPatterns = @(
    # AWS
    'AKIA[0-9A-Z]{16}',                                          # Access Key ID
    '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',   # Secret (heurística)
    # Azure Storage (conn string)
    'DefaultEndpointsProtocol=https;AccountName=.*;AccountKey=.*;EndpointSuffix=.*',
    # SAS (heurística)
    'SharedAccessSignature=sv=.*?&ss=.*?&srt=.*?&sp=.*?&se=.*?&st=.*?&spr=.*?&sig=.*',
    # GCP service account (KEY)
    '-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----',
    # JWT (Bearer)
    'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    # GUIDs (client_id/tenant_id, etc.)
    '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b'
)

# ---------------------- Utilidades ----------------------
function Test-IsExcluded {
    param([string]$ItemPath, [string[]]$Excludes)
    foreach ($ex in $Excludes) {
        if ([string]::IsNullOrWhiteSpace($ex)) { continue }
        $i = $ItemPath.TrimEnd('\')
        $e = $ex.TrimEnd('\')
        if ($i.StartsWith($e, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function HtmlEscape {
    param([string]$s)
    if ($null -eq $s) { return "" }
    return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
}

# Controla máscara/mostra full
function Mask-Line {
    param([string]$line)
    if ($ShowFull -and -not $Mask) { return $line }  # padrão: mostra tudo
    if (-not $Mask) { return $line }                 # caso ShowFull=false e Mask não ligado, retorna como está
    $masked = $line
    $masked = $masked -replace '(AKIA[0-9A-Z]{8})([0-9A-Z]{8})', '$1********'
    $masked = $masked -replace '([A-Za-z0-9/+=]{8})([A-Za-z0-9/+=]{32})', '$1********************************'
    $masked = $masked -replace '(AccountKey=)([^;]{6})[^;]*', '$1$2******'
    $masked = $masked -replace '(SharedAccessSignature=)([^&]{6})[^&]*', '$1$2******'
    $masked = $masked -replace '("private_key"\s*:\s*")(.{10}).*(")', '$1$2***$3'
    $masked = $masked -replace '(_authToken=)([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]*', '$1$2******'
    return $masked
}

# Gera lista de arquivos conforme filtros
function Get-FileList {
    param(
        [string[]]$Roots,[string[]]$IncludeExtensions,[string[]]$NoExtensionNames,[switch]$IncludeNoExtension,
        [string[]]$ExcludePaths,[switch]$Recurse,[int]$MaxFileSizeMB
    )

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        # Se for arquivo específico, adiciona direto
        if (Test-Path $root -PathType Leaf) {
            try {
                $fi = Get-Item -LiteralPath $root -ErrorAction SilentlyContinue
                if ($fi -and ($fi.Length -le ($MaxFileSizeMB*1MB))) { $files.Add($fi) }
            } catch {}
            continue
        }

        # Enumera pasta
        try {
            $enum = if ($Recurse) {
                Get-ChildItem -Path $root -File -Force -Recurse -ErrorAction SilentlyContinue
            } else {
                Get-ChildItem -Path $root -File -Force -ErrorAction SilentlyContinue
            }
        } catch { continue }

        foreach ($f in $enum) {
            try {
                if (Test-IsExcluded -ItemPath $f.FullName -Excludes $ExcludePaths) { continue }
                if ($f.Length -gt ($MaxFileSizeMB*1MB)) { continue }

                $name = $f.Name
                $ext  = [IO.Path]::GetExtension($name)
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

                if ($match) { $files.Add($f) }
            } catch {}
        }
    }
    return $files
}

# Leitura segura (remove BOM) + retorno de linhas com índice
function Read-LinesSafe {
    param([string]$Path)
    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
        if ($null -eq $text) { return @() }
        # Remove BOM U+FEFF caso exista
        $text = $text -replace "^\uFEFF", ""
        # Divide em linhas universais
        $lines = $text -split "`r`n|`n|`r"
        $out = New-Object System.Collections.Generic.List[object]
        for ($i=0; $i -lt $lines.Count; $i++) {
            $out.Add([pscustomobject]@{ LineNumber = ($i+1); Line = $lines[$i] })
        }
        return $out
    } catch { return @() }
}

# Realça o match dentro da linha (para HTML)
function Highlight-Line {
    param([string]$line, [string]$pattern, [string]$type)  # type: Keyword|Regex
    if ([string]::IsNullOrEmpty($line)) { return "" }
    $escaped = HtmlEscape (Mask-Line $line)

    try {
        if ($type -eq "Keyword") {
            # highlight case-insensitive da keyword literal
            $regex = [Regex]::Escape($pattern)
            return ([regex]::Replace($escaped, $regex, { param($m) "<mark>" + $m.Value + "</mark>" }, 'IgnoreCase'))
        } else {
            # Regex: aplica highlight em todas ocorrências
            return ([regex]::Replace($escaped, $pattern, { param($m) "<mark>" + $m.Value + "</mark>" }))
        }
    } catch {
        return $escaped
    }
}

# Busca em arquivos
function Search-InFiles {
    param(
        [System.IO.FileInfo[]]$Files,[string[]]$KeywordPatterns,[string[]]$RegexPatterns
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($file in $Files) {
        $lines = Read-LinesSafe -Path $file.FullName
        if ($lines.Count -eq 0) { continue }

        # Keywords (comparação simples estilo "contém", case-insensitive)
        foreach ($pat in $KeywordPatterns) {
            foreach ($ln in $lines) {
                if ($ln.Line -like "*$pat*") {
                    $results.Add([pscustomobject]@{
                        Tipo    = "Keyword"
                        Padrao  = $pat
                        Caminho = $file.FullName
                        Linha   = $ln.LineNumber
                        Trecho  = (Mask-Line $ln.Line)
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
                        $results.Add([pscustomobject]@{
                            Tipo    = "Regex"
                            Padrao  = $r
                            Caminho = $file.FullName
                            Linha   = $ln.LineNumber
                            Trecho  = (Mask-Line $ln.Line)
                        })
                    }
                } catch {}
            }
        }
    }

    return $results
}

# ---------------------- Execução ----------------------
Write-Host "[+] Preparando lista de arquivos..." -ForegroundColor Cyan
$roots = $Path | Where-Object { $_ -and ($_ -notmatch '^\s*$') }

$files = Get-FileList -Roots $roots `
                      -IncludeExtensions $IncludeExtensions `
                      -NoExtensionNames $NoExtensionNames `
                      -IncludeNoExtension:$IncludeNoExtension `
                      -ExcludePaths $ExcludePaths `
                      -Recurse:$Recurse `
                      -MaxFileSizeMB $MaxFileSizeMB

Write-Host ("[+] Arquivos candidatos: {0}" -f $files.Count) -ForegroundColor Yellow
if ($files.Count -eq 0) {
    Write-Warning "Nenhum arquivo candidato encontrado. Verifique permissões, path e filtros."
}

Write-Host "[+] Buscando padrões de credenciais..." -ForegroundColor Cyan
$results = Search-InFiles -Files $files -KeywordPatterns $KeywordPatterns -RegexPatterns $RegexPatterns

# Estatísticas
$totalMatches = $results.Count
Write-Host "[+] Total de matches encontrados: $totalMatches" -ForegroundColor Cyan

# ---------------------- Saída ----------------------
# Gera nome de arquivo se não foi informado
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $Output -or [string]::IsNullOrWhiteSpace([IO.Path]::GetExtension($Output))) {
    $base = if ($Output) { [IO.Path]::GetFileNameWithoutExtension($Output) } else { "creds_report" }
    $Output = "$base`_$ts.$Format"
}

# Ordena saída
$sorted = $results | Sort-Object Caminho, Linha

switch ($Format) {
    "csv"  { $sorted | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Output }
    "json" { $sorted | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 -FilePath $Output }
    "txt"  {
        $sorted | ForEach-Object {
            "$($_.Tipo) | Padrão: $($_.Padrao) | $($_.Caminho) | Linha: $($_.Linha) | Trecho: $($_.Trecho)"
        } | Out-File -Encoding UTF8 -FilePath $Output
    }
    "html" {
        # Resumo por Tipo e por Padrão
        $byType   = $sorted | Group-Object Tipo | Sort-Object Count -Descending
        $byPat    = $sorted | Group-Object Padrao | Sort-Object Count -Descending

        # Monta HTML
        $html = @()
        $html += "<html><head><meta charset='utf-8'><title>Relatorio de Credenciais</title><style>
        body{font-family:Segoe UI,Arial,sans-serif;margin:20px}
        table{border-collapse:collapse;width:100%;margin-bottom:16px}
        th,td{border:1px solid #ddd;padding:8px;vertical-align:top}
        th{background:#333;color:#fff}
        .summary{margin-bottom:20px}
        .keyword{background:#e6f7ff}
        .regex{background:#fff0f6}
        mark{background:#ffdd57;padding:0 2px}
        small{color:#666}
        </style></head><body>"

        $html += "<h2>Relatorio de Credenciais</h2>"
        $html += "<div class='summary'><p><b>Total de arquivos analisados:</b> $($files.Count) &nbsp; | &nbsp; <b>Total de matches:</b> $totalMatches</p></div>"

        # Tabela de resumo por Tipo
        $html += "<h3>Resumo por Tipo</h3><table><tr><th>Tipo</th><th>Quantidade</th></tr>"
        foreach ($g in $byType) {
            $html += "<tr><td>$($g.Name)</td><td>$($g.Count)</td></tr>"
        }
        $html += "</table>"

        # Tabela de resumo por Padrao (top 30 para não pesar)
        $html += "<h3>Top Padrões</h3><table><tr><th>Padrão</th><th>Quantidade</th></tr>"
        foreach ($g in ($byPat | Select-Object -First 30)) {
            $p = HtmlEscape $g.Name
            $html += "<tr><td><small>$p</small></td><td>$($g.Count)</td></tr>"
        }
        $html += "</table>"

        # Tabela de resultados detalhados
        $html += "<h3>Resultados</h3><table><tr><th>Tipo</th><th>Padrão</th><th>Caminho</th><th>Linha</th><th>Trecho</th></tr>"

        foreach ($r in $sorted) {
            $class = if ($r.Tipo -eq "Keyword") { "keyword" } else { "regex" }

            # Link clicável para o arquivo
            $uri = "file:///" + ([System.Uri]::EscapeDataString($r.Caminho) -replace "%3A", ":" -replace "%5C", "/")
            $pathLink = "$uri$(HtmlEscape)</a>"

            # Highlight do trecho
            $trechoHighlighted = Highlight-Line -line $r.Trecho -pattern $r.Padrao -type $r.Tipo

            $html += "<tr class='$class'>
                        <td>$($r.Tipo)</td>
                        <td><small>$(HtmlEscape $r.Padrao)</small></td>
                        <td>$pathLink</td>
                        <td>$($r.Linha)</td>
                        <td><pre style='white-space:pre-wrap;margin:0'>$trechoHighlighted</pre></td>
                      </tr>"
        }

        $html += "</table><p><small>Gerado em $(Get-Date)</small></p></body></html>"
        ($html -join "`r`n") | Out-File -Encoding UTF8 -FilePath $Output
    }
}

if ($totalMatches -eq 0) {
    Write-Warning "Nenhum padrão encontrado. Dicas: verifique se o arquivo consta em 'Arquivos candidatos', ajuste IncludeExtensions/NoExtensionNames, ou use -MaxFileSizeMB maior."
}

Write-Host "[+] Resultados exportados para: $Output" -ForegroundColor Green
