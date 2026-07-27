# ============================================================================
# 跨机器攻击演示 —— Windows 端自动化
#
# 用法（管理员 PowerShell）:
#   .\demo\run_live_demo.ps1
#
# 环境: Windows 11 + Npcap + VMware Kali VM (192.168.235.133)
# ============================================================================

param([switch]$Quick, [switch]$AttackOnly)

$ErrorActionPreference = "Continue"
$KaliIP = if ($env:KALI_IP) { $env:KALI_IP } else { "192.168.235.133" }
$WinIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.235.1" }
$WinHTTP = if ($env:TARGET_HTTP) { $env:TARGET_HTTP } else { "192.168.235.1:8080" }
$CaptureIface = if ($env:CAPTURE_IFACE) { $env:CAPTURE_IFACE } else { "VMware Network Adapter VMnet8" }
$ProjectDir = "d:\network_detection"
$ResultsDir = "$ProjectDir\results"
$delay = if ($Quick) { 0.5 } else { 1 }

Write-Host "================================================"
Write-Host " 跨机器攻击演示: Kali -> Windows"
Write-Host " 抓包: ${CaptureIface}  |  靶机: ${WinHTTP}"
Write-Host "================================================"

# ---- step 1: start target ----
Write-Host "[1/5] 启动靶机 HTTP..."
$targetJob = Start-Job -ScriptBlock { param($d) Set-Location $d; python demo/target_server.py } -Arg $ProjectDir
Start-Sleep 2
if ($targetJob.State -eq "Failed") { throw "target failed" }

# ---- step 2: start capture ----
Write-Host "[2/5] 启动抓包..."
# 抓包使用独立的 live_capture.py（避免 PS 内嵌 Python 的转义问题）
$capPy = Join-Path $ProjectDir "demo\live_capture.py"
$capOut = Join-Path $ResultsDir "live_capture.json"

# 确保捕获目录存在
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

$env:CAPTURE_IFACE = $CaptureIface
$capJob = Start-Job -ScriptBlock {
    param($py, $out)
    python $py $out 120 2>&1
} -Arg $capPy, $capOut
Start-Sleep 3

# ---- step 3: run attacks via SSH ----
Write-Host "[3/5] Kali 攻击..."
$sshBase = "ssh -o StrictHostKeyChecking=no kali@$KaliIP"

# HTTP attacks (7 categories)
$httpTypes = @("sql_injection","xss","path_traversal","cmd_injection","webshell","trojan","xxe")
foreach ($t in $httpTypes) {
    Write-Host "  --- $t ---"
    Invoke-Expression "$sshBase 'cd ~/network_detection; TARGET=$WinHTTP bash demo/attack_scripts/${t}.sh'" 2>&1 | Select-Object -Last 5
    Start-Sleep -Seconds $delay
}

# Port scan
Write-Host "  --- port_scan ---"
Invoke-Expression "$sshBase 'cd ~/network_detection; TARGET=$WinIP bash demo/attack_scripts/port_scan.sh'" 2>&1 | Select-Object -Last 5
Start-Sleep -Seconds $delay

# SSH brute force
Write-Host "  --- ssh_bruteforce ---"
Invoke-Expression "$sshBase 'cd ~/network_detection; TARGET=$KaliIP bash demo/attack_scripts/ssh_bruteforce.sh'" 2>&1 | Select-Object -Last 5
Start-Sleep -Seconds $delay

# SYN flood
Write-Host "  --- SYN flood (90 packets) ---"
$synScript = "for i in {1..90}; do timeout 0.1 bash -c 'echo >/dev/tcp/" + $WinIP + "/8080' 2>/dev/null; done; echo DONE"
$synScript | Out-File -Encoding ASCII "$env:TEMP\syn_flood.sh"
scp -o StrictHostKeyChecking=no -q "$env:TEMP\syn_flood.sh" "kali@${KaliIP}:/tmp/syn_flood.sh"
ssh -o StrictHostKeyChecking=no "kali@$KaliIP" "bash /tmp/syn_flood.sh" 2>&1

Write-Host "[3/5] 攻击完成"

# ---- step 4: stop capture ----
Write-Host "[4/6] 停止抓包..."
Start-Sleep 5
if ($capJob.State -eq "Running") { Stop-Job $capJob }
$capJob | Receive-Job | Write-Host
if ($targetJob.State -eq "Running") { Stop-Job $targetJob }

# ---- step 5: 启动持续检测 + Web 面板 ----
Write-Host "[5/6] 启动持续检测 + Web 面板..."
Set-Location $ProjectDir

# 启动 watch 模式（后台持续检测）
$watchJob = Start-Job -ScriptBlock {
    param($dir, $input, $output)
    Set-Location $dir
    python main.py --watch 3 --input $input --output-dir $output 2>&1
} -Arg $ProjectDir, $capOut, $ResultsDir

# 启动 Web 面板
$webJob = Start-Job -ScriptBlock {
    param($dir)
    Set-Location $dir
    python main.py --web --web-port 8099 2>&1
} -Arg $ProjectDir

Start-Sleep 3
Write-Host "${Green}  Watch 检测已启动 (每 3s)${NC}"
Write-Host "${Green}  Web 面板: http://127.0.0.1:8099${NC}"
Write-Host ""
Write-Host "==========================================="
Write-Host "  打开浏览器 → http://127.0.0.1:8099"
Write-Host "  观察告警实时刷新！"
Write-Host "  Ctrl+C 停止全部服务"
Write-Host "==========================================="

# 等待用户手动结束
try {
    while ($true) { Start-Sleep 1 }
} catch {
    Write-Host "`n[清理] 停止所有服务..."
}
finally {
    if ($watchJob.State -eq "Running") { Stop-Job $watchJob }
    if ($webJob.State -eq "Running") { Stop-Job $webJob }
    if ($captureJob.State -eq "Running") { Stop-Job $captureJob }
    if ($targetJob.State -eq "Running") { Stop-Job $targetJob }
    Get-Job | Remove-Job -Force 2>$null
}
