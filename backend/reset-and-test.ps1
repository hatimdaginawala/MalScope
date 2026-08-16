# ============================================
# MALSCORE - WORKING FINAL SCRIPT
# ============================================

Write-Host "=== MALSCORE FINAL ===" -ForegroundColor Cyan

# 1. LOGIN
Write-Host "[1] Logging in..." -ForegroundColor Yellow
$loginBody = @{ username = "admin"; password = "AdminPassword123!" } | ConvertTo-Json
try {
    $loginResult = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/auth/login" -Method Post -ContentType "application/json" -Body $loginBody
    $token = $loginResult.data.token
    Write-Host "✅ Logged in" -ForegroundColor Green
} catch {
    Write-Host "❌ Login failed. Registering..." -ForegroundColor Yellow
    $registerBody = @{ username = "admin"; email = "admin@malscope.local"; password = "AdminPassword123!"; role = "admin" } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://localhost:5000/api/v1/auth/register" -Method Post -ContentType "application/json" -Body $registerBody | Out-Null
    $loginResult = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/auth/login" -Method Post -ContentType "application/json" -Body $loginBody
    $token = $loginResult.data.token
    Write-Host "✅ Registered and logged in" -ForegroundColor Green
}

$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

# 2. GET SAMPLE
Write-Host "[2] Getting sample..." -ForegroundColor Yellow
try {
    $samples = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/samples" -Method Get -Headers $headers
    if ($samples.data.Count -eq 0) {
        Write-Host "❌ No samples. Uploading..." -ForegroundColor Yellow
        $filePath = "C:\Users\Admin\Downloads\MalScope\analysis-engine\notepad.exe"
        if (-not (Test-Path $filePath)) {
            "test content" | Out-File -FilePath "test.exe"
            $filePath = ".\test.exe"
        }
        $uploadHeaders = @{ "Authorization" = "Bearer $token" }
        $form = @{ file = Get-Item $filePath }
        $uploadResult = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/samples" -Method Post -Headers $uploadHeaders -Form $form
        $sampleId = $uploadResult.data.sample._id
        Write-Host "✅ Uploaded: $sampleId" -ForegroundColor Green
    } else {
        $sampleId = $samples.data[0]._id
        Write-Host "✅ Using existing: $sampleId" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Failed: $_" -ForegroundColor Red
    exit
}

# 3. START ANALYSIS
Write-Host "[3] Starting analysis..." -ForegroundColor Yellow
$body = @{ sampleId = $sampleId; runDynamic = $false; runVirusTotal = $false } | ConvertTo-Json
try {
    $analysisResult = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/analyses" -Method Post -Headers $headers -Body $body
    $analysisId = $analysisResult.data.analysisId
    Write-Host "✅ Analysis: $analysisId" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $_" -ForegroundColor Red
    $analysisId = $null
}

# 4. WAIT FOR COMPLETION
if ($analysisId) {
    Write-Host "[4] Waiting..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 2
        try {
            $statusResult = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/analyses/$analysisId/status" -Method Get -Headers $headers
            $status = $statusResult.data.status
            Write-Host "  [$i] $status" -ForegroundColor Gray
            if ($status -eq "completed") { break }
            if ($status -eq "failed") { 
                Write-Host "❌ FAILED: $($statusResult.data.error.message)" -ForegroundColor Red
                break
            }
        } catch {
            Write-Host "  Error checking status" -ForegroundColor Red
        }
    }
}

# 5. GET RESULTS
if ($analysisId) {
    Write-Host "[5] Getting results..." -ForegroundColor Yellow
    try {
        $result = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/analyses/$analysisId/static" -Method Get -Headers $headers
        $result | ConvertTo-Json -Depth 10 | Out-File "C:\Users\Admin\Downloads\MalScope\output\result.json"
        Write-Host "✅ Saved to: C:\Users\Admin\Downloads\MalScope\output\result.json" -ForegroundColor Green
        
        # Show summary
        if ($result.data.findings) {
            Write-Host "`nFINDINGS:" -ForegroundColor Yellow
            $result.data.findings | ForEach-Object { Write-Host "  - $($_.description)" -ForegroundColor Gray }
        }
        if ($result.data.iocs) {
            Write-Host "`nIOCs: $($result.data.iocs.Count)" -ForegroundColor Yellow
        }
        if ($result.data.resources) {
            Write-Host "Resources: $($result.data.resources.Count)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Failed to get results: $_" -ForegroundColor Red
    }
}

Write-Host "`n=== DONE ===" -ForegroundColor Cyan