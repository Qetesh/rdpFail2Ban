# PowerShell 脚本 - 每分钟检查RDP登录失败，并将失败超过3次的IP阻止
Write-Host -ForegroundColor Green "========================================================================"
Write-Host -ForegroundColor Cyan "  RDP login failure monitoring script has been started"
"  This script checks for RDP login failures every minute and blocks IP that have failed more than 3 times."
Write-Host -ForegroundColor Green "========================================================================"

# 配置变量
$ErrorActionPreference = "SilentlyContinue"
$LogName = "Security"
$EventID = 4625,4624 # Windows安全事件ID
$TimeSleepSeconds = 60
$FailedAttempsLimit = 3
$WhiteListIPs = @("127.0.0.1", "127.0.0.2")
$FirewallRuleName = "BlockedRDPAttempt_IPs"
$newBlockIPs = @()
$FailedIPs = @{}
# 初始化首次查询间隔
$startTime = (Get-Date).Add(-(New-TimeSpan -Hours 1))
$endTime = Get-Date

# 检查防火墙规则是否存在
$ruleExists = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue

# 创建一个无限循环，每分钟运行一次
while ($true) {
    # 计算时间间隔
    $TimeSpan = $endTime - $startTime
    $startTime = Get-Date

    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = $LogName
        ID        = $EventID
        StartTime = (Get-Date).Add(-$TimeSpan)
    }
    
    # 解析失败的IP地址并计算每个IP的失败次数
    foreach ($event in $Events) {
        $IpAddress = $event.Properties[19].Value
        if ((![string]::IsNullOrEmpty($IpAddress)) -and ($IpAddress -ne "-") -and ($IpAddress -ne "0")) {
            $FailedIPs[$IpAddress] = $FailedIPs[$IpAddress] + 1
            Write-Host -ForegroundColor Yellow "$(Get-Date) Detected failed login from: $IpAddress at $($event.TimeCreated)"
        }
    }

    # 打印登录成功的IP地址
    foreach ($event in $Events) {
        $SuccessIpAddress = $event.Properties[18].Value
        if ((![string]::IsNullOrEmpty($SuccessIpAddress)) -and ($SuccessIpAddress -ne "-") -and ($SuccessIpAddress -ne "0") -and ($event.Properties[8].Value -eq 3)) {
            Write-Host -ForegroundColor Green "$(Get-Date) Detected successful login from: $SuccessIpAddress at $($event.TimeCreated)"
        }
    }
    

    # 过滤出失败次数达到限制的IP并进行处理
    $BlockedIPs = $FailedIPs.Keys | Where-Object { $FailedIPs[$_] -ge $FailedAttempsLimit }
    $BlockedIPs = $BlockedIPs | Where-Object { $_ -notin $WhiteListIPs }
    
    if (Compare-Object -ReferenceObject $BlockedIPs -DifferenceObject $newBlockIPs -PassThru) {
        foreach ($ip in $BlockedIPs) {
            # 如果规则不存在，则创建一个新规则
            if (-not $ruleExists) {
                New-NetFirewallRule -DisplayName $FirewallRuleName -Direction Inbound -Action Block -RemoteAddress $ip -Protocol TCP -LocalPort 3389
                Write-Host -ForegroundColor Blue "$(Get-Date) Created new Firewall rule for IP: $ip"
				$ruleExists = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue
            } else {
                # 如果规则已存在，更新规则以添加新IP
                $existingBlockIPs = (Get-NetFirewallRule -DisplayName $FirewallRuleName | Get-NetFirewallAddressFilter).RemoteAddress
                $newBlockIPs = @()
                $newBlockIPs += $existingBlockIPs
                if ($newBlockIPs -notcontains $ip) {
                    $newBlockIPs += $ip
                    Write-Host -ForegroundColor Red "$(Get-Date) Detected IP with multiple RDP failures: $ip"
                }
                Set-NetFirewallRule -DisplayName $FirewallRuleName -RemoteAddress $newBlockIPs
            }
        }
        if (![string]::IsNullOrEmpty($newBlockIPs)) {
            Write-Host -ForegroundColor Red "$(Get-Date) Updated Firewall rule to add IP: $newBlockIPs"
        }
    }
    # 等待60秒后继续下一轮循环
    Start-Sleep -Seconds $TimeSleepSeconds

    # 结束时间戳
    $endTime = Get-Date
}
