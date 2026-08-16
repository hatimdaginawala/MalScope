# ============================================
# MALSCORE - COMPLETE TEST SCRIPT
# ============================================

Write-Host "=== MalScope Full Test ===" -ForegroundColor Cyan

# 1. Login
Write-Host "`n[1] Logging in..." -ForegroundColor Yellow
$loginBody = @{
    username = "admin"
    password = "AdminPassword123!"
} | ConvertTo-Json

try {
    $login = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/auth/login" `
        -Method Post `
        -ContentType "application/json" `
        -Body $loginBody
    
    $token = $login.data.token
    $env:MALSCOPE_TOKEN = $token
    Write-Host "✅ Logged in successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Login failed: $_" -ForegroundColor Red
    exit
}

# 2. Upload or get existing sample
Write-Host "`n[2] Uploading sample..." -ForegroundColor Yellow
$filePath = "C:\Users\Admin\Downloads\MalScope\analysis-engine\notepad.exe"

if (Test-Path $filePath) {
    try {
        # Use curl.exe for upload
        $uploadOutput = curl.exe -X POST "http://localhost:5000/api/v1/samples" `
            -H "Authorization: Bearer $token" `
            -F "file=@$filePath" 2>&1
        
        # Parse JSON response
        $upload = $uploadOutput | ConvertFrom-Json
        
        if ($upload.data.sample._id) {
            $sampleId = $upload.data.sample._id
            Write-Host "✅ Uploaded: $sampleId" -ForegroundColor Green
        } else {
            Write-Host "⚠️ Upload response unexpected" -ForegroundColor Yellow
            $samples = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/samples" `
                -Method Get `
                -Headers @{"Authorization"="Bearer $token"}
            $sampleId = $samples.data[0]._id
            Write-Host "✅ Using existing sample: $sampleId" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️ Upload failed, checking existing samples..." -ForegroundColor Yellow
        try {
            $samples = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/samples" `
                -Method Get `
                -Headers @{"Authorization"="Bearer $token"}
            $sampleId = $samples.data[0]._id
            Write-Host "✅ Using existing sample: $sampleId" -ForegroundColor Green
        } catch {
            Write-Host "❌ No samples found and upload failed" -ForegroundColor Red
            exit
        }
    }
} else {
    Write-Host "⚠️ File not found, checking existing samples..." -ForegroundColor Yellow
    try {
        $samples = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/samples" `
            -Method Get `
            -Headers @{"Authorization"="Bearer $token"}
        $sampleId = $samples.data[0]._id
        Write-Host "✅ Using existing sample: $sampleId" -ForegroundColor Green
    } catch {
        Write-Host "❌ No samples found" -ForegroundColor Red
        exit
    }
}

$h = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# 3. Start analysis
Write-Host "`n[3] Starting analysis..." -ForegroundColor Yellow
$body = @{
    sampleId = $sampleId
    runDynamic = $false
    runVirusTotal = $false
} | ConvertTo-Json

try {
    $r = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/analyses" `
        -Method Post `
        -Headers $h `
        -Body $body
    
    $aid = $r.data.analysisId
    Write-Host "✅ Analysis started: $aid" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to start analysis: $_" -ForegroundColor Red
    exit
}

# 4. Wait for completion
Write-Host "`n[4] Waiting for completion..." -ForegroundColor Yellow
$completed = $false

for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 2
    try {
        $status = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/analyses/$aid/status" `
            -Method Get `
            -Headers $h
        
        Write-Host "  [$($i+1)/20] $($status.data.status)" -ForegroundColor Gray
        
        if ($status.data.status -eq "completed") {
            $completed = $true
            Write-Host "✅ Analysis completed successfully!" -ForegroundColor Green
            break
        }
        if ($status.data.status -eq "failed") {
            Write-Host "❌ Analysis failed: $($status.data.error.message)" -ForegroundColor Red
            exit
        }
    } catch {
        Write-Host "  Error checking status" -ForegroundColor Red
    }
}

if (-not $completed) {
    Write-Host "⚠️ Analysis did not complete within timeout" -ForegroundColor Yellow
}

# 5. Get Configuration Indicators
Write-Host "`n[5] Configuration Indicators:" -ForegroundColor Yellow
try {
    $configs = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/threat-intel/config/samples/$sampleId" `
        -Method Get `
        -Headers $h
    
    Write-Host "  Total: $($configs.data.Count)" -ForegroundColor Gray
    
    if ($configs.data.Count -gt 0) {
        $configs.data | ForEach-Object {
            Write-Host "  - $($_.type): $($_.value) (confidence: $($_.confidence))" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No configuration indicators found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ❌ Failed to get config indicators" -ForegroundColor Red
}

# 6. Get IOCs
Write-Host "`n[6] IOCs:" -ForegroundColor Yellow
try {
    $iocs = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/threat-intel/samples/$sampleId/iocs" `
        -Method Get `
        -Headers $h
    
    Write-Host "  Total: $($iocs.data.Count)" -ForegroundColor Gray
    
    if ($iocs.data.Count -gt 0) {
        $iocs.data | Select-Object -First 15 | ForEach-Object {
            Write-Host "  - $($_.type): $($_.value)" -ForegroundColor Gray
        }
        if ($iocs.data.Count -gt 15) {
            Write-Host "  ... and $($iocs.data.Count - 15) more" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No IOCs found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ❌ Failed to get IOCs" -ForegroundColor Red
}

# 7. Get Malware Families
Write-Host "`n[7] Malware Families:" -ForegroundColor Yellow
try {
    $families = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/threat-intel/families" `
        -Method Get `
        -Headers $h
    
    Write-Host "  Total: $($families.data.Count)" -ForegroundColor Gray
    
    if ($families.data.Count -gt 0) {
        $families.data | ForEach-Object {
            Write-Host "  - $($_.name) (Samples: $($_.stats.sampleCount))" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No malware families found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ❌ Failed to get families" -ForegroundColor Red
}

# 8. Get Similarity Results
Write-Host "`n[8] Similarity Results:" -ForegroundColor Yellow
try {
    $similarity = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/threat-intel/similarity/samples/$sampleId" `
        -Method Get `
        -Headers $h
    
    Write-Host "  Total: $($similarity.data.Count)" -ForegroundColor Gray
    
    if ($similarity.data.Count -gt 0) {
        $similarity.data | ForEach-Object {
            Write-Host "  - Score: $($_.similarityScore) (Relationship: $($_.relationshipType))" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No similarity results found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ❌ Failed to get similarity results" -ForegroundColor Red
}

# 9. Get Summary
Write-Host "`n[9] Threat Intelligence Summary:" -ForegroundColor Yellow
try {
    $summary = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/threat-intel/summary" `
        -Method Get `
        -Headers $h
    
    Write-Host "  Total IOCs: $($summary.data.iocs.total)" -ForegroundColor Gray
    Write-Host "  Total Samples: $($summary.data.samples.total)" -ForegroundColor Gray
    Write-Host "  Malicious: $($summary.data.samples.malicious)" -ForegroundColor Gray
    Write-Host "  Suspicious: $($summary.data.samples.suspicious)" -ForegroundColor Gray
    
    if ($summary.data.topFamilies.Count -gt 0) {
        Write-Host "  Top Families:" -ForegroundColor Gray
        $summary.data.topFamilies | ForEach-Object {
            Write-Host "    - $($_.name) ($($_.stats.sampleCount) samples)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  ❌ Failed to get summary" -ForegroundColor Red
}

# 10. Get Static Analysis Results
Write-Host "`n[10] Static Analysis Results:" -ForegroundColor Yellow
try {
    $static = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/analyses/$aid/static" `
        -Method Get `
        -Headers $h
    
    $fileInfo = $static.data.fileInfo
    if ($fileInfo) {
        Write-Host "  Filename: $($fileInfo.filename)" -ForegroundColor Gray
        Write-Host "  File Type: $($fileInfo.fileType)" -ForegroundColor Gray
        Write-Host "  PE Type: $($fileInfo.peType)" -ForegroundColor Gray
        Write-Host "  Architecture: $($fileInfo.arch)" -ForegroundColor Gray
        Write-Host "  File Size: $($fileInfo.fileSize) bytes" -ForegroundColor Gray
    }
    
    $findings = $static.data.findings
    if ($findings -and $findings.Count -gt 0) {
        Write-Host "`n  Findings:" -ForegroundColor Yellow
        $findings | ForEach-Object {
            Write-Host "    - $($_.description) ($($_.severity))" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  ❌ Failed to get static results" -ForegroundColor Red
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan