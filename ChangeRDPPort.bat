@echo off
>NUL 2>&1 REG.exe query "HKU\S-1-5-19" || (
    ECHO SET UAC = CreateObject^("Shell.Application"^) > "%TEMP%\Getadmin.vbs"
    ECHO UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%TEMP%\Getadmin.vbs"
    "%TEMP%\Getadmin.vbs"
    DEL /f /q "%TEMP%\Getadmin.vbs" 2>NUL
    Exit /b
)
color f0
echo 修改远程桌面端口并自动添加防火墙规则
echo %date% %time%
set /p Port=请输入一个端口号 (1024 - 65535):
if "%Port%"=="" goto end
goto edit
:edit
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp" /v "PortNumber" /t REG_DWORD /d "%Port%" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "PortNumber" /t REG_DWORD /d "%Port%" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{338933891-3389-3389-3389-338933893389}" /t REG_SZ /d "v2.29|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=%Port%|Name=远程桌面(TCP-In)|" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{338933892-3389-3389-3389-338933893389}" /t REG_SZ /d "v2.29|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=%Port%|Name=远程桌面(UDP-In)|" /f > nul
echo 修改成功
echo 新的远程桌面端口是: %Port%
echo 请重启计算机以生效
pause
exit
:end
echo 错误：请输入正确的端口号
pause