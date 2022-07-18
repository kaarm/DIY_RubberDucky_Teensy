param($extended)
 
$lines="------------------------------------------"
function whost($a) {
    Write-Host
    Write-Host -ForegroundColor Green $lines
    Write-Host -ForegroundColor Green " "$a 
    Write-Host -ForegroundColor Green $lines
}


whost "Windows Enumeration Script v 0.1
          by absolomb
       www.sploitspren.com"

$standard_commands = [ordered]@{

    'Basic System Information'                    = 'Start-Process "systeminfo" -NoNewWindow -Wait >> C:/rendu.txt';
    'Environment Variables'                       = 'Get-ChildItem Env: | ft Key,Value >> C:/rendu.txt';
    'Network Information'                         = 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address >> C:/rendu.txt';
    'DNS Servers'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft >> C:/rendu.txt';
    'ARP cache'                                   = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State >> C:/rendu.txt';
    'Routing Table'                               = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex >> C:/rendu.txt';
    'Network Connections'                         = 'Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait | ft >> C:/rendu.txt';
    'Connected Drives'                            = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft >> C:/rendu.txt';
    'Firewall Config'                             = 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft >> C:/rendu.txt';
    'Current User'                                = 'Write-Host $env:UserDomain\$env:UserName >> C:/rendu.txt';
    'User Privileges'                             = 'start-process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | ft >> C:/rendu.txt';
    'Local Users'                                 = 'Get-LocalUser | ft Name,Enabled,LastLogon >> C:/rendu.txt';
    'Logged in Users'                             = 'Start-Process "qwinsta" -NoNewWindow -Wait | ft >> C:/rendu.txt';
    'Credential Manager'                          = 'start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | ft >> C:/rendu.txt'
    'User Autologon Registry Items'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft >> C:/rendu.txt';
    'Local Groups'                                = 'Get-LocalGroup | ft Name >> C:/rendu.txt';
    'Local Administrators'                        = 'Get-LocalGroupMember Administrateurs | ft Name, PrincipalSource >> C:/rendu.txt';
    'User Directories'                            = 'Get-ChildItem C:\Users | ft Name >> C:/rendu.txt';
    'Searching for SAM backup files'              = 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM >> C:/rendu.txt';
    'Running Processes'                           = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize >> C:/rendu.txt';
    'Installed Software Directories'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime >> C:/rendu.txt';
    'Software in Registry'                        = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name >> C:/rendu.txt';
    'Folders with Everyone Permissions'           = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft >> C:/rendu.txt';
    'Folders with BUILTIN\User Permissions'       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft >> C:/rendu.txt';
    'Checking registry for AlwaysInstallElevated' = 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft >> C:/rendu.txt';
    'Unquoted Service Paths'                      = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft >> C:/rendu.txt';
    'Scheduled Tasks'                             = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State >> C:/rendu.txt';
    'Tasks Folder'                                = 'Get-ChildItem C:\Windows\Tasks | ft >> C:/rendu.txt';
    'Startup Commands'                            = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl >> C:/rendu.txt';
    
}
function RunCommands($commands) {
    ForEach ($command in $commands.GetEnumerator()) {
        whost $command.Name
        Invoke-Expression $command.Value
    }
}


RunCommands($standard_commands)

if ($extended) {
    if ($extended.ToLower() -eq 'extended') {
        $result = Test-Path C:\temp
        if ($result -eq $False) {
            New-Item C:\temp -type directory
        }
        whost "Results writing to C:\temp\
    This may take a while..."
        RunCommands($extended_commands)
        whost "Script Finished! Check your files in C:\temp\"
    }
}
else {
    whost "Script finished!"
}
