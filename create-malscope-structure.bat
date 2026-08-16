@echo off
echo ============================================
echo  MalScope Project Structure Creator
echo ============================================
echo.

REM Root directory
set ROOT=%CD%

echo Creating project structure in: %ROOT%
echo.

REM === BACKEND STRUCTURE ===
echo [1/6] Creating Backend structure...
mkdir "%ROOT%\backend\src\config" 2>nul
mkdir "%ROOT%\backend\src\routes" 2>nul
mkdir "%ROOT%\backend\src\controllers" 2>nul
mkdir "%ROOT%\backend\src\services" 2>nul
mkdir "%ROOT%\backend\src\models" 2>nul
mkdir "%ROOT%\backend\src\middleware" 2>nul
mkdir "%ROOT%\backend\src\utils" 2>nul
mkdir "%ROOT%\backend\tests" 2>nul

REM Backend root files
type nul > "%ROOT%\backend\package.json" 2>nul
type nul > "%ROOT%\backend\.env.example" 2>nul

REM Backend src files
type nul > "%ROOT%\backend\src\server.js" 2>nul

REM Backend config files
type nul > "%ROOT%\backend\src\config\database.js" 2>nul
type nul > "%ROOT%\backend\src\config\environment.js" 2>nul
type nul > "%ROOT%\backend\src\config\virusTotal.js" 2>nul

REM Backend route files
type nul > "%ROOT%\backend\src\routes\authRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\sampleRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\analysisRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\staticAnalysisRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\dynamicAnalysisRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\threatIntelRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\reportRoutes.js" 2>nul
type nul > "%ROOT%\backend\src\routes\dashboardRoutes.js" 2>nul

REM Backend controller files
type nul > "%ROOT%\backend\src\controllers\authController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\sampleController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\analysisController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\staticAnalysisController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\dynamicAnalysisController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\threatIntelController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\reportController.js" 2>nul
type nul > "%ROOT%\backend\src\controllers\dashboardController.js" 2>nul

REM Backend service files
type nul > "%ROOT%\backend\src\services\sampleService.js" 2>nul
type nul > "%ROOT%\backend\src\services\analysisService.js" 2>nul
type nul > "%ROOT%\backend\src\services\pythonAnalysisService.js" 2>nul
type nul > "%ROOT%\backend\src\services\staticAnalysisService.js" 2>nul
type nul > "%ROOT%\backend\src\services\dynamicAnalysisService.js" 2>nul
type nul > "%ROOT%\backend\src\services\virtualBoxService.js" 2>nul
type nul > "%ROOT%\backend\src\services\telemetryService.js" 2>nul
type nul > "%ROOT%\backend\src\services\virusTotalService.js" 2>nul
type nul > "%ROOT%\backend\src\services\correlationService.js" 2>nul
type nul > "%ROOT%\backend\src\services\iocService.js" 2>nul
type nul > "%ROOT%\backend\src\services\riskService.js" 2>nul
type nul > "%ROOT%\backend\src\services\reportService.js" 2>nul

REM Backend model files
type nul > "%ROOT%\backend\src\models\User.js" 2>nul
type nul > "%ROOT%\backend\src\models\MalwareSample.js" 2>nul
type nul > "%ROOT%\backend\src\models\Analysis.js" 2>nul
type nul > "%ROOT%\backend\src\models\StaticAnalysis.js" 2>nul
type nul > "%ROOT%\backend\src\models\DynamicAnalysis.js" 2>nul
type nul > "%ROOT%\backend\src\models\VirusTotalReport.js" 2>nul
type nul > "%ROOT%\backend\src\models\IOC.js" 2>nul
type nul > "%ROOT%\backend\src\models\Behavior.js" 2>nul
type nul > "%ROOT%\backend\src\models\ThreatAssessment.js" 2>nul

REM Backend middleware files
type nul > "%ROOT%\backend\src\middleware\authMiddleware.js" 2>nul
type nul > "%ROOT%\backend\src\middleware\uploadMiddleware.js" 2>nul
type nul > "%ROOT%\backend\src\middleware\validationMiddleware.js" 2>nul
type nul > "%ROOT%\backend\src\middleware\rateLimitMiddleware.js" 2>nul
type nul > "%ROOT%\backend\src\middleware\errorMiddleware.js" 2>nul

REM Backend utils files
type nul > "%ROOT%\backend\src\utils\hashUtils.js" 2>nul
type nul > "%ROOT%\backend\src\utils\fileUtils.js" 2>nul
type nul > "%ROOT%\backend\src\utils\logger.js" 2>nul
type nul > "%ROOT%\backend\src\utils\analysisStatus.js" 2>nul

REM Backend test files
type nul > "%ROOT%\backend\tests\samples.test.js" 2>nul
type nul > "%ROOT%\backend\tests\analysis.test.js" 2>nul
type nul > "%ROOT%\backend\tests\staticAnalysis.test.js" 2>nul
type nul > "%ROOT%\backend\tests\dynamicAnalysis.test.js" 2>nul
type nul > "%ROOT%\backend\tests\virusTotal.test.js" 2>nul
type nul > "%ROOT%\backend\tests\correlation.test.js" 2>nul

echo [1/6] Backend structure complete.
echo.

REM === ANALYSIS ENGINE STRUCTURE ===
echo [2/6] Creating Analysis Engine structure...
mkdir "%ROOT%\analysis-engine\static" 2>nul
mkdir "%ROOT%\analysis-engine\dynamic" 2>nul
mkdir "%ROOT%\analysis-engine\detection" 2>nul
mkdir "%ROOT%\analysis-engine\common" 2>nul

REM Analysis engine root files
type nul > "%ROOT%\analysis-engine\worker.py" 2>nul
type nul > "%ROOT%\analysis-engine\requirements.txt" 2>nul

REM Static analyzer files
type nul > "%ROOT%\analysis-engine\static\pe_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\file_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\hash_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\string_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\entropy_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\import_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\section_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\static\yara_analyzer.py" 2>nul

REM Dynamic analyzer files
type nul > "%ROOT%\analysis-engine\dynamic\telemetry_parser.py" 2>nul
type nul > "%ROOT%\analysis-engine\dynamic\process_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\dynamic\file_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\dynamic\registry_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\dynamic\network_analyzer.py" 2>nul
type nul > "%ROOT%\analysis-engine\dynamic\behavior_analyzer.py" 2>nul

REM Detection rule files
type nul > "%ROOT%\analysis-engine\detection\process_rules.json" 2>nul
type nul > "%ROOT%\analysis-engine\detection\file_rules.json" 2>nul
type nul > "%ROOT%\analysis-engine\detection\persistence_rules.json" 2>nul
type nul > "%ROOT%\analysis-engine\detection\network_rules.json" 2>nul

REM Common files
type nul > "%ROOT%\analysis-engine\common\models.py" 2>nul
type nul > "%ROOT%\analysis-engine\common\indicators.py" 2>nul
type nul > "%ROOT%\analysis-engine\common\result_formatter.py" 2>nul

echo [2/6] Analysis Engine structure complete.
echo.

REM === ANALYSIS VM STRUCTURE ===
echo [3/6] Creating Analysis VM structure...
mkdir "%ROOT%\analysis-vm\setup\monitoring-config" 2>nul
mkdir "%ROOT%\analysis-vm\agent" 2>nul
mkdir "%ROOT%\analysis-vm\snapshots" 2>nul

REM Root files
type nul > "%ROOT%\analysis-vm\README.md" 2>nul

REM Setup files
type nul > "%ROOT%\analysis-vm\setup\setup-guide.md" 2>nul

REM Agent files
type nul > "%ROOT%\analysis-vm\agent\collector.ps1" 2>nul
type nul > "%ROOT%\analysis-vm\agent\collector.py" 2>nul
type nul > "%ROOT%\analysis-vm\agent\config.json" 2>nul

REM Snapshots README
type nul > "%ROOT%\analysis-vm\snapshots\README.md" 2>nul

echo [3/6] Analysis VM structure complete.
echo.

REM === FRONTEND STRUCTURE ===
echo [4/6] Creating Frontend structure...
type nul > "%ROOT%\frontend\index.html" 2>nul
type nul > "%ROOT%\frontend\dashboard.html" 2>nul
type nul > "%ROOT%\frontend\upload.html" 2>nul
type nul > "%ROOT%\frontend\samples.html" 2>nul
type nul > "%ROOT%\frontend\sample-details.html" 2>nul
type nul > "%ROOT%\frontend\static-analysis.html" 2>nul
type nul > "%ROOT%\frontend\dynamic-analysis.html" 2>nul
type nul > "%ROOT%\frontend\threat-intelligence.html" 2>nul
type nul > "%ROOT%\frontend\reports.html" 2>nul

echo [4/6] Frontend structure complete.
echo.

REM === STORAGE STRUCTURE ===
echo [5/6] Creating Storage structure...
mkdir "%ROOT%\storage\samples\pending" 2>nul
mkdir "%ROOT%\storage\samples\analyzing" 2>nul
mkdir "%ROOT%\storage\samples\completed" 2>nul
mkdir "%ROOT%\storage\samples\failed" 2>nul
mkdir "%ROOT%\storage\reports" 2>nul

echo [5/6] Storage structure complete.
echo.

REM === RULES STRUCTURE ===
echo [6/6] Creating Rules structure...
mkdir "%ROOT%\rules\yara" 2>nul

type nul > "%ROOT%\rules\yara\malware.yar" 2>nul
type nul > "%ROOT%\rules\yara\ransomware.yar" 2>nul
type nul > "%ROOT%\rules\yara\trojan.yar" 2>nul
type nul > "%ROOT%\rules\yara\suspicious.yar" 2>nul

echo [6/6] Rules structure complete.
echo.

REM === DOCS STRUCTURE ===
echo [7/7] Creating Documentation structure...
mkdir "%ROOT%\docs" 2>nul

type nul > "%ROOT%\docs\architecture.md" 2>nul
type nul > "%ROOT%\docs\static-analysis.md" 2>nul
type nul > "%ROOT%\docs\dynamic-analysis.md" 2>nul
type nul > "%ROOT%\docs\sandbox-architecture.md" 2>nul
type nul > "%ROOT%\docs\virustotal-integration.md" 2>nul
type nul > "%ROOT%\docs\database.md" 2>nul
type nul > "%ROOT%\docs\api.md" 2>nul
type nul > "%ROOT%\docs\testing.md" 2>nul
type nul > "%ROOT%\docs\security.md" 2>nul

echo [7/7] Documentation structure complete.
echo.

REM === TESTS STRUCTURE ===
echo [8/8] Creating Integration Tests structure...
mkdir "%ROOT%\tests\integration" 2>nul
mkdir "%ROOT%\tests\fixtures" 2>nul

type nul > "%ROOT%\tests\fixtures\README.md" 2>nul

echo [8/8] Integration Tests structure complete.
echo.

REM === ROOT FILES ===
echo Creating root files...
type nul > "%ROOT%\.gitignore" 2>nul
type nul > "%ROOT%\README.md" 2>nul
type nul > "%ROOT%\LICENSE" 2>nul
type nul > "%ROOT%\docker-compose.yml" 2>nul

echo Root files complete.
echo.

REM ============================================
echo ============================================
echo  ✅ MalScope Project Structure Created!
echo ============================================
echo.
echo  Structure created at: %ROOT%
echo.
echo  Directories created: 30+
echo  Files created: 110+
echo.
echo  Next steps:
echo  1. Start MongoDB
echo  2. cd backend
echo  3. npm install
echo  4. cp .env.example .env
echo  5. npm run dev
echo.
echo ============================================
pause