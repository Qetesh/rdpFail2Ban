# PowerShell 脚本 - 每分钟检查RDP登录失败，并将失败超过3次的IP阻止

# 配置变量
$LogName = "Security"
$EventID = 4625 # Windows安全事件ID，表示登录尝试失败
$TimeSpan = New-TimeSpan -Hours 1
$FailedAttempsLimit = 3
$FirewallRuleName = "BlockedRDPAttempt_IPs"
$newBlockIPs = @()

# 创建一个无限循环，每分钟运行一次
while ($true) {
    # 获取最近一小时内的所有登录失败事件
    $FailedEvents = Get-WinEvent -FilterHashtable @{
        LogName   = $LogName
        ID        = $EventID
        # StartTime = (Get-Date).Add(-$TimeSpan)
    }
    
    # 解析失败的IP地址并计算每个IP的失败次数
    $FailedIPs = @{}
    foreach ($event in $FailedEvents) {
        $IpAddress = $event.Properties[19].Value
        if (![string]::IsNullOrEmpty($IpAddress)) {
            $FailedIPs[$IpAddress] = $FailedIPs[$IpAddress] + 1
        }
    }

    # 过滤出失败次数达到限制的IP并进行处理
    $BlockedIPs = $FailedIPs.Keys | Where-Object { $FailedIPs[$_] -ge $FailedAttempsLimit }
    
    if (Compare-Object -ReferenceObject $BlockedIPs -DifferenceObject $newBlockIPs -PassThru) {
        foreach ($ip in $BlockedIPs) {
            # 检查防火墙规则是否存在
            $ruleExists = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue
            
            # 如果规则不存在，则创建一个新规则
            if (-not $ruleExists) {
                New-NetFirewallRule -DisplayName $FirewallRuleName -Direction Inbound -Action Block -RemoteAddress $ip -Protocol TCP -LocalPort 3389
                Write-Output "$(Get-Date) Created new Firewall rule for IP: $ip"
            } else {
                # 如果规则已存在，更新规则以添加新IP
                $existingBlockIPs = (Get-NetFirewallRule -DisplayName $FirewallRuleName | Get-NetFirewallAddressFilter).RemoteAddress
                $newBlockIPs = @()
                $newBlockIPs += $existingBlockIPs
                if ($newBlockIPs -notcontains $ip) {
                    $newBlockIPs += $ip
                    Write-Output "$(Get-Date) Detected IP with multiple RDP failures: $ip"
                }
                Set-NetFirewallRule -DisplayName $FirewallRuleName -RemoteAddress $newBlockIPs
            }
        }
        Write-Output "$(Get-Date) Updated Firewall rule to add IP: $newBlockIPs"
    }
    # 等待60秒后继续下一轮循环
    Start-Sleep -Seconds 60
}
