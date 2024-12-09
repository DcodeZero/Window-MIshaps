# WindowS-MIShaps


A PowerShell-based tool for creating a controlled Windows security testing environment. 


## ⚠️ Important Security Notice

This tool creates intentionally vulnerable configurations for educational purposes. **NEVER** use this tool on production systems or any machine connected to a production network. Only use in isolated lab environments.

## Features

### Basic Misconfigurations
- Unquoted Service Paths
- Weak Service Permissions
- Insecure File Permissions
- DLL Hijacking Scenarios
- AlwaysInstallElevated Settings

### Advanced Security Scenarios
- Scheduled Task Vulnerabilities
- UAC Bypass Configurations
- Token Impersonation
- Parent Process Spoofing
- Privileged Application Exploits
- Named Pipe Vulnerabilities
- Insecure WMI Objects
- SAM Hive Access

## Prerequisites

- Windows 10 22H2 (Build 19045) or higher
- PowerShell 5.1 or higher
- Administrative privileges
- Isolated lab environment (Virtual Machine recommended)

## Installation

1. Download both script parts:
   - `Mishaps-LAB-Part1.ps1`
   - `Mishaps-LAB-Part2.ps1`

2. Place both files in the same directory

## Usage

### Basic Usage

```powershell
# Import both script parts
. .\Mishaps-LAB-Part1.ps1
. .\Mishaps-LAB-Part2.ps1

# Create lab environment
Start-CompleteSecurityLab

# Clean up lab environment
Start-CompleteSecurityLab -Cleanup
```

### Individual Components

You can also set up specific vulnerabilities:

```powershell
# Set up only service-related vulnerabilities
Set-UnquotedServicePath
Set-WeakServicePermissions

# Set up only file-related vulnerabilities
Set-InsecureFilePermissions
Set-DLLHijacking

# Set up advanced scenarios
Set-UACBypass
Set-TokenImpersonation
```

## Safety Features

1. **Version Checking**
   - Verifies Windows version compatibility
   - Prevents execution on unsupported systems

2. **Error Handling**
   - Comprehensive try-catch blocks
   - Detailed logging of all operations
   - Graceful failure handling

3. **Cleanup Functionality**
   - Complete removal of all created vulnerabilities
   - Restoration of default settings
   - Verification of cleanup success

## Logging

The tool maintains detailed logs at `$env:TEMP\SecurityLab.log` including:
- All operations performed
- Errors encountered
- Configuration changes
- Cleanup status

## Best Practices

1. **Environment Setup**
   - Use a dedicated virtual machine
   - Take snapshots before running the tool
   - Ensure network isolation

2. **Usage Guidelines**
   - Run in controlled lab environments only
   - Document all changes made
   - Always clean up after testing
   - Monitor system stability

3. **Security Considerations**
   - Never use on production systems
   - Maintain network isolation
   - Clean up immediately after testing
   - Monitor for unexpected behavior

## Troubleshooting

### Common Issues

1. **Permission Errors**
   - Verify administrative privileges
   - Check User Account Control settings
   - Verify script execution policy

2. **Version Compatibility**
   - Confirm Windows build number
   - Check PowerShell version
   - Verify system requirements

3. **Cleanup Failures**
   - Use system restore point
   - Manually verify service removal
   - Check registry modifications

## Educational Resources

This tool is designed to complement security training. Recommended learning paths:
- Windows Security Fundamentals
- Privilege Escalation Techniques
- Service Security
- File System Security
- Registry Security

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request
4. Include test cases
5. Update documentation

## License

This tool is for educational purposes only. Use at your own risk.

## Disclaimer

This tool creates intentionally vulnerable configurations. The authors are not responsible for any misuse or damage caused by this tool. Use only in controlled, isolated lab environments.

## Support

For issues, questions, or contributions:
1. Check the documentation
2. Review existing issues
3. Submit detailed bug reports
4. Provide system information

## Version History

- v1.0.0 - Initial release
  - Basic misconfigurations
  - Advanced exploits
  - Cleanup functionality
  - Logging system

## Acknowledgments

- Windows Security Community
- Security Researchers
- Educational Institutions

Remember: Security research should be conducted responsibly and ethically.
