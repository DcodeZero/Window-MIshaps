# Windows Security Lab Setup Script - Part 1
# Core Functions and Basic Misconfigurations
# For educational purposes in controlled lab environments only
# Requires administrative privileges to run

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$CreateVulnerabilities,
    [switch]$Cleanup
)

# Error handling and logging function
function Write-LogEntry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Severity] $Message"
    
    switch ($Severity) {
        'Information' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
    }
    
    $logPath = "$env:TEMP\SecurityLab.log"
    Add-Content -Path $logPath -Value $logMessage
}

# Version verification
function Test-WindowsVersion {
    try {
        $osVersion = Get-WmiObject -Class Win32_OperatingSystem
        $buildNumber = [int]($osVersion.BuildNumber)
        
        if ($buildNumber -lt 19045) {
            throw "This script requires Windows 10 22H2 (19045) or higher"
        }
        Write-LogEntry "Windows version check passed: Build $buildNumber"
        return $true
    }
    catch {
        Write-LogEntry "Failed to verify Windows version: $_" -Severity Error
        return $false
    }
}

#region Basic Misconfigurations

function Set-UnquotedServicePath {
    param([switch]$Cleanup)
    
    $serviceName = "LabVulnService"
    $servicePath = "C:\Program Files\Lab Service\Service with spaces.exe"
    
    try {
        if (!$Cleanup) {
            New-Item -Path "C:\Program Files\Lab Service" -ItemType Directory -Force | Out-Null
            Copy-Item "$env:SystemRoot\System32\cmd.exe" -Destination $servicePath -Force
            
            New-Service -Name $serviceName `
                       -DisplayName "Lab Vulnerable Service" `
                       -BinaryPathName $servicePath `
                       -StartupType Manual
            
            Write-LogEntry "Created vulnerable service with unquoted path"
        }
        else {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Remove-Service -Name $serviceName -ErrorAction SilentlyContinue
            Remove-Item "C:\Program Files\Lab Service" -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogEntry "Cleaned up unquoted service path"
        }
    }
    catch {
        Write-LogEntry "Error in Set-UnquotedServicePath: $_" -Severity Error
    }
}

function Set-WeakServicePermissions {
    param([switch]$Cleanup)
    
    $serviceName = "LabWeakPermService"
    
    try {
        if (!$Cleanup) {
            New-Service -Name $serviceName `
                       -DisplayName "Lab Weak Permissions Service" `
                       -BinaryPathName "$env:SystemRoot\System32\cmd.exe" `
                       -StartupType Manual
            
            # Set weak DACL
            $cmd = "sc.exe sdset $serviceName `"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)`""
            Invoke-Expression $cmd
            Write-LogEntry "Created service with weak permissions"
        }
        else {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Remove-Service -Name $serviceName -ErrorAction SilentlyContinue
            Write-LogEntry "Cleaned up weak service permissions"
        }
    }
    catch {
        Write-LogEntry "Error in Set-WeakServicePermissions: $_" -Severity Error
    }
}

function Set-InsecureFilePermissions {
    param([switch]$Cleanup)
    
    $vulnPath = "C:\Program Files\Lab Files"
    
    try {
        if (!$Cleanup) {
            New-Item -Path $vulnPath -ItemType Directory -Force | Out-Null
            Copy-Item "$env:SystemRoot\System32\cmd.exe" -Destination "$vulnPath\vulnerable.exe" -Force
            
            # Set weak permissions
            $acl = Get-Acl $vulnPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Users","FullControl","ContainerInherit,ObjectInherit","None","Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $vulnPath $acl
            Write-LogEntry "Created directory with insecure file permissions"
        }
        else {
            Remove-Item $vulnPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogEntry "Cleaned up insecure file permissions"
        }
    }
    catch {
        Write-LogEntry "Error in Set-InsecureFilePermissions: $_" -Severity Error
    }
}

function Set-DLLHijacking {
    param([switch]$Cleanup)
    
    $vulnPath = "C:\Program Files\Lab DLL"
    $dllPath = "$vulnPath\SearchPath"
    
    try {
        if (!$Cleanup) {
            New-Item -Path $vulnPath -ItemType Directory -Force | Out-Null
            New-Item -Path $dllPath -ItemType Directory -Force | Out-Null
            Copy-Item "$env:SystemRoot\System32\cmd.exe" -Destination "$vulnPath\app.exe" -Force
            
            # Set weak permissions
            $acl = Get-Acl $dllPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Users","FullControl","ContainerInherit,ObjectInherit","None","Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $dllPath $acl
            
            # Modify DLL search order
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
                           -Name "SafeDllSearchMode" `
                           -Value 0 `
                           -PropertyType DWord `
                           -Force
            Write-LogEntry "Created DLL hijacking vulnerable environment"
        }
        else {
            Remove-Item $vulnPath -Recurse -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
                           -Name "SafeDllSearchMode" `
                           -Value 1
            Write-LogEntry "Cleaned up DLL hijacking environment"
        }
    }
    catch {
        Write-LogEntry "Error in Set-DLLHijacking: $_" -Severity Error
    }
}

function Set-AlwaysInstallElevated {
    param([switch]$Cleanup)
    
    try {
        if (!$Cleanup) {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                           -Name "AlwaysInstallElevated" `
                           -Value 1 `
                           -PropertyType DWord -Force
            
            New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                           -Name "AlwaysInstallElevated" `
                           -Value 1 `
                           -PropertyType DWord -Force
            Write-LogEntry "Enabled AlwaysInstallElevated"
        }
        else {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                              -Name "AlwaysInstallElevated" `
                              -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                              -Name "AlwaysInstallElevated" `
                              -ErrorAction SilentlyContinue
            Write-LogEntry "Disabled AlwaysInstallElevated"
        }
    }
    catch {
        Write-LogEntry "Error in Set-AlwaysInstallElevated: $_" -Severity Error
    }
}

# Main execution block for Part 1
function Start-SecurityLabPart1 {
    param([switch]$Cleanup)
    
    try {
        if (-not (Test-WindowsVersion)) {
            throw "Windows version check failed"
        }
        
        if (!$Cleanup) {
            Write-LogEntry "Starting basic security lab setup..."
            Set-UnquotedServicePath
            Set-WeakServicePermissions
            Set-InsecureFilePermissions
            Set-DLLHijacking
            Set-AlwaysInstallElevated
            Write-LogEntry "Basic security lab setup completed"
        }
        else {
            Write-LogEntry "Starting basic security lab cleanup..."
            Set-UnquotedServicePath -Cleanup
            Set-WeakServicePermissions -Cleanup
            Set-InsecureFilePermissions -Cleanup
            Set-DLLHijacking -Cleanup
            Set-AlwaysInstallElevated -Cleanup
            Write-LogEntry "Basic security lab cleanup completed"
        }
    }
    catch {
        Write-LogEntry "Critical error in Part 1: $_" -Severity Error
        return $false
    }
    return $true
}

# Export functions for Part 2
Export-ModuleMember -Function *
