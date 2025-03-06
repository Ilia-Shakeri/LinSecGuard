# LinSecGuard

## Overview
**LinSecGuard** (Linux Security Guard) is a powerful script designed to automate essential system security and administration tasks. It streamlines the process of checking and configuring SSH settings, firewalls, running services, file permissions, open ports, login attempts, and system updates. With a user-friendly interface and comprehensive logging, LinSecGuard makes system administration efficient and accessible.

## Features
### SSH Settings
- Ensure SSH is installed and running
- Disable root login for enhanced security
- Option to change the default SSH port

### Firewall Configuration
- Check and install UFW (Uncomplicated Firewall)
- Configure default firewall rules
- Allow custom user-defined ports

### Running Services
- List and manage running services
- Options to stop, restart, enable, or disable services

### File Permissions
- Identify and fix insecure file permissions
- User-friendly prompts for fixing specific files

### Open Ports
- Scan for open ports and manage them
- Close specific ports or open new ones
- View detailed process information for open ports

### Login Attempts
- Check failed login attempts and block suspicious IPs
- Filter logs by username or IP address

### System Updates
- Check and install system updates
- Option to reboot after updates
- Check for security updates

### Logging
The script maintains a detailed log file to track actions and changes. The log file is managed to ensure it doesn't exceed 1000 lines, maintaining a clean and readable log history.

### Contribution
Feel free to fork this repository, create issues, and submit pull requests. Your contributions are welcome and appreciated!

### Configuration
Before running the script, ensure you have a configuration file named LinSecGuard.conf in the same directory. This file should contain your custom settings.

## Installation
Clone the repository and navigate to the project directory:
```bash
git clone https://github.com/Ilia-Shakeri/LinSecGuard.git
cd LinSecGuard
chmod +x LinSecGuard.sh
./LinSecGuard.sh
