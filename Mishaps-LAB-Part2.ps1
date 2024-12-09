# Windows Security Lab Setup Script - Part 2
# Advanced Exploits and Additional Security Scenarios
# For educational purposes in controlled lab environments only
# Requires Part 1 to be loaded first

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$CreateVulnerabilities,
    [switch]$Cleanup
)

function Set-VulnerableScheduledTask {
    param([switch]$Cleanup)
    
    $taskName = "LabVulnerableTask"
    $taskPath = "\Microsoft\Windows\Lab\"
    
    try {
        if (!$Cleanup) {
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo vulnerable > C:\temp\task.txt"
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            Register-ScheduledTask -TaskName $taskName `
                                 -TaskPath $taskPath `
                                 -Action $action `
                                 -Trigger $trigger `
                                 -Principal $principal `
                                 -Force
            
            # Set weak permissions
            $cmd = "icacls C:\Windows\System32\Tasks$taskPath /grant Users:F /T"
            Invoke-Expression $cmd
            Write-LogEntry "Created vulnerable scheduled task"
        }
        else {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
            Write-LogEntry "Removed vulnerable scheduled task"
        }
    }
    catch {
        Write-LogEntry "Error in Set-VulnerableScheduledTask: $_" -Severity Error
    }
}

function Set-UACBypass {
    param([switch]$Cleanup)
    
    try {
        if (!$Cleanup) {
            # Configure UAC settings
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                           -Name "EnableLUA" `
                           -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                           -Name "ConsentPromptBehaviorAdmin" `
                           -Value 0
            
            # Create auto-elevate COM object
            New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" `
                           -Name "(Default)" `
                           -Value "cmd.exe" `
                           -Force
            
            Write-LogEntry "Configured UAC bypass scenario"
        }
        else {
            # Restore UAC settings
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                           -Name "ConsentPromptBehaviorAdmin" `
                           -Value 5
            Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogEntry "Restored UAC settings"
        }
    }
    catch {
        Write-LogEntry "Error in Set-UACBypass: $_" -Severity Error
    }
}

function Set-TokenImpersonation {
    param([switch]$Cleanup)
    
    $serviceName = "LabTokenService"
    
    try {
        if (!$Cleanup) {
            # Create service that maintains token
            New-Service -Name $serviceName `
                       -DisplayName "Lab Token Service" `
                       -BinaryPathName "$env:SystemRoot\System32\cmd.exe /c echo token > C:\temp\token.txt" `
                       -StartupType Manual
            
            # Set weak token permissions
            $cmd = "sc.exe sdset $serviceName `"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)`""
            Invoke-Expression $cmd
            Write-LogEntry "Created service for token impersonation"
        }
        else {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Remove-Service -Name $serviceName -ErrorAction SilentlyContinue
            Write-LogEntry "Removed token impersonation service"
        }
    }
    catch {
        Write-LogEntry "Error in Set-TokenImpersonation: $_" -Severity Error
    }
}

function Set-ParentProcessSpoofing {
    param([switch]$Cleanup)
    
    $labPath = "C:\LabFiles\ProcessSpoofing"
    
    try {
        if (!$Cleanup) {
            # Create directory
            New-Item -Path $labPath -ItemType Directory -Force | Out-Null
            
            # Create demo source code
            @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ProcessSpoof {
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        byte[] lpStartupInfo,
        byte[] lpProcessInformation);

    public static void Main() {
        Console.WriteLine("Parent Process Spoofing Demo");
    }
}
'@ | Out-File "$labPath\ProcessSpoof.cs"

            # Set permissions
            $acl = Get-Acl $labPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $labPath $acl
            
            Write-LogEntry "Created parent process spoofing environment"
        }
        else {
            Remove-Item -Path $labPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogEntry "Cleaned up parent process spoofing environment"
        }
    }
    catch {
        Write-LogEntry "Error in Set-ParentProcessSpoofing: $_" -Severity Error
    }
}

function Set-PrivilegedAppExploit {
    param([switch]$Cleanup)
    
    $labPath = "C:\LabFiles\PrivilegedApp"
    
    try {
        if (!$Cleanup) {
            # Create directory and vulnerable application
            New-Item -Path $labPath -ItemType Directory -Force | Out-Null
            
            @'
using System;
using System.Diagnostics;

class VulnerableApp {
    static void Main() {
        Console.WriteLine("Privileged Application");
        string userInput = Console.ReadLine();
        Process.Start("cmd.exe", "/c " + userInput);
    }
}
'@ | Out-File "$labPath\VulnerableApp.cs"

            # Set up auto-elevation
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" `
                           -Name "$labPath\VulnerableApp.exe" `
                           -Value "RUNASADMIN" `
                           -Force
            
            Write-LogEntry "Created privileged application exploit environment"
        }
        else {
            Remove-Item -Path $labPath -Recurse -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" `
                              -Name "$labPath\VulnerableApp.exe" `
                              -ErrorAction SilentlyContinue
            Write-LogEntry "Cleaned up privileged application environment"
        }
    }
    catch {
        Write-LogEntry "Error in Set-PrivilegedAppExploit: $_" -Severity Error
    }
}

function Set-NamedPipeVulnerability {
    param([switch]$Cleanup)
    
    $pipeName = "LabVulnPipe"
    $serviceName = "LabPipeService"
    
    try {
        if (!$Cleanup) {
            # Create service that uses named pipe
            New-Service -Name $serviceName `
                       -DisplayName "Lab Pipe Service" `
                       -BinaryPathName "$env:SystemRoot\System32\cmd.exe /c echo pipe > \\.\pipe\$pipeName" `
                       -StartupType Manual
            
            # Set weak permissions
            $cmd = "sc.exe sdset $serviceName `"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)`""
            Invoke-Expression $cmd
            
            Write-LogEntry "Created named pipe vulnerability"
        }
        else {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Remove-Service -Name $serviceName -ErrorAction SilentlyContinue
            Write-LogEntry "Cleaned up named pipe vulnerability"
        }
    }
    catch {
        Write-LogEntry "Error in Set-NamedPipeVulnerability: $_" -Severity Error
    }
}

function Set-InsecureWMIObjects {
    param([switch]$Cleanup)
    
    try {
        if (!$Cleanup) {
            # Create WMI event subscription
            $query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
            $filterName = "LabWMIFilter"
            
            $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
                Name = $filterName
                EventNamespace = 'root\cimv2'
                QueryLanguage = 'WQL'
                Query = $query
            }
            
            # Set weak permissions
            $acl = Get-WmiObject -Namespace "root\subscription" -Class "__SystemSecurity"
            $descriptor = $acl.GetSecurityDescriptor()
            $descriptor.DACL += @{
                AccessMask = 0x1
                AceFlags = 0x3
                AceType = 0x0
                Trustee = @{
                    SIDString = "S-1-1-0" # Everyone
                }
            }
            $acl.SetSecurityDescriptor($descriptor)
            
            Write-LogEntry "Created insecure WMI objects"
        }
        else {
            Remove-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -Filter "Name='$filterName'"
            Write-LogEntry "Cleaned up insecure WMI objects"
        }
    }
    catch {
        Write-LogEntry "Error in Set-InsecureWMIObjects: $_" -Severity Error
    }
}

function Set-AccessibleSAMHive {
    param([switch]$Cleanup)
    
    try {
        if (!$Cleanup) {
            # Set weak permissions on SAM
            $cmd = "icacls C:\Windows\System32\config\SAM /grant Users:F"
            Invoke-Expression $cmd
            
            # Disable registry protection
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                           -Name "RunAsPPL" `
                           -Value 0 `
                           -Force
            
            Write-LogEntry "Created accessible SAM hive"
        }
        else {
            # Restore SAM permissions
            $cmd = "icacls C:\Windows\System32\config\SAM /setowner `"NT SERVICE\TrustedInstaller`""
            Invoke-Expression $cmd
            
            # Enable registry protection
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                           -Name "RunAsPPL" `
                           -Value 1 `
                           -Force
            
            Write-LogEntry "Restored SAM hive protection"
        }
    }
    catch {
        Write-LogEntry "Error in Set-AccessibleSAMHive: $_" -Severity Error
    }
}

# Main execution block for Part 2
function Start-SecurityLabPart2 {
    param([switch]$Cleanup)
    
    try {
        if (!$Cleanup) {
            Write-LogEntry "Starting advanced security lab setup..."
            Set-VulnerableScheduledTask
            Set-UACBypass
            Set-TokenImpersonation
            Set-ParentProcessSpoofing
            Set-PrivilegedAppExploit
            Set-NamedPipeVulnerability
            Set-InsecureWMIObjects
            Set-AccessibleSAMHive
            Write-LogEntry "Advanced security lab setup completed"
        }
        else {
            Write-LogEntry "Starting advanced security lab cleanup..."
            Set-VulnerableScheduledTask -Cleanup
            Set-UACBypass -Cleanup
            Set-TokenImpersonation -Cleanup
            Set-ParentProcessSpoofing -Cleanup
            Set-PrivilegedAppExploit -Cleanup
            Set-NamedPipeVulnerability -Cleanup
            Set-InsecureWMIObjects -Cleanup
            Set-AccessibleSAMHive -Cleanup
            Write-LogEntry "Advanced security lab cleanup completed"
        }
    }
    catch {
        Write-LogEntry "Critical error in Part 2: $_" -Severity Error
        return $false
    }
    return $true
}

# Combined execution function
function Start-CompleteSecurityLab {
    param([switch]$Cleanup)
    
    try {
        $part1Success = Start-SecurityLabPart1 -Cleanup:$Cleanup
        if ($part1Success) {
            $part2Success = Start-SecurityLabPart2 -Cleanup:$Cleanup
            if ($part2Success) {
                Write-LogEntry "Complete security lab setup/cleanup successful"
                return $true
            }
        }
        Write-LogEntry "Security lab setup/cleanup failed" -Severity Error
        return $false
    }
    catch {
        Write-LogEntry "Critical error in complete setup: $_" -Severity Error
        return $false
    }
}

Export-ModuleMember -Function Start-CompleteSecurityLab
