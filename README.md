## **MagicSpoofing**

### Project description
A python3 script for search possible misconfiguration in a DNS related to security protections of email service from the domain name. This project is for educational use, we are not responsible for its misuse.

### Cross-Platform Compatibility
The tool now supports multiple operating systems:
- **Linux**: Full support for all features
- **macOS**: Full support with automatic detection of system differences
- **Windows**: Basic support (some features like Postfix configuration are not available)

### New Modular Structure
The code has been refactored into a modular structure for better maintainability:

- `magicspoofmail.py`: Main script that orchestrates the entire process
- `utils.py`: Utility functions for colors, banner, and display
- `dns_checks.py`: Functions for checking SPF and DMARC records
- `email_sender.py`: Functions for sending test emails
- `cli.py`: Command-line argument parsing
- `profiles.py`: Predefined configuration profiles
- `config.py`: Configuration file management
- `interactive.py`: Interactive mode functionality

### Simplified Usage
The tool now offers several ways to use it, from simple to advanced:

1. **Interactive Mode**: Guided step-by-step interface
   ```
   ./magicspoofmail.py -i
   ```

2. **Predefined Profiles**: Use common configurations with a single parameter
   ```
   ./magicspoofmail.py -d example.com -p security
   ```

3. **Configuration Files**: Save and reuse your preferred settings
   ```
   ./magicspoofmail.py --save-config myconfig
   ./magicspoofmail.py --config myconfig -d example.com
   ```

4. **Quick All-in-One Analysis**: Run all checks with a single flag
   ```
   ./magicspoofmail.py -d example.com --all
   ```

5. **Traditional Command-Line**: Full control with detailed parameters
   ```
   ./magicspoofmail.py -d example.com --check-dkim --deep-spf --check-dmarc-ext
   ```

### Available Profiles
- **basic**: Basic verification of SPF, DKIM and DMARC
- **full**: Complete and detailed analysis of SPF, DKIM and DMARC
- **security**: Analysis focused on identifying security vulnerabilities
- **test**: Basic verification and test email sending
- **reports**: Analysis of DMARC report configuration

### Enhanced SPF Analysis
The tool now includes a comprehensive SPF record analyzer that:

- Detects all SPF mechanisms (ip4, ip6, include, a, mx, ptr, etc.)
- Analyzes the security level of SPF configuration
- Identifies common misconfigurations and security issues
- Provides recommendations for improving SPF security
- Checks for DNS lookup limits and recursive includes
- Detects overlapping IP ranges and redundant mechanisms
- Verifies the validity of included domains

New command-line options for SPF analysis:
```
--deep-spf         Perform deep recursive analysis of SPF includes
--spf-details      Show complete details of SPF analysis
--max-lookups N    Maximum number of DNS lookups to perform in recursive analysis (default: 10)
```

### Enhanced DKIM Analysis
The tool now includes a comprehensive DKIM record analyzer that:

- Scans for common DKIM selectors (default, dkim, selector1, etc.)
- Analyzes DKIM record fields and values
- Evaluates key types and sizes for security
- Detects testing mode and other configuration issues
- Provides recommendations for improving DKIM security
- Checks for DKIM alignment with mail servers
- Verifies hash algorithms and other security parameters

New command-line options for DKIM analysis:
```
--check-dkim                 Verify DKIM configuration for the domain
--dkim-selectors SEL1,SEL2   Specify DKIM selectors to check (comma-separated)
--check-alignment            Check DKIM alignment with mail servers
--dkim-key-min-size N        Minimum recommended DKIM key size in bits (default: 1024)
```

### Enhanced DMARC Analysis
The tool now includes a comprehensive DMARC record analyzer that:

- Analyzes DMARC policy settings (p, sp, pct)
- Evaluates the security level of DMARC configuration
- Checks for proper report configuration (rua, ruf)
- Verifies alignment settings (adkim, aspf)
- Analyzes failure reporting options (fo)
- Detects common misconfigurations and security issues
- Provides recommendations for improving DMARC security
- Verifies external report authorization records

New command-line options for DMARC analysis:
```
--check-dmarc-ext           Perform extended analysis of DMARC configuration
--check-external-reports    Verify external report configuration
--recommend-dmarc           Generate recommendations for improving DMARC configuration
--dmarc-policy POLICY       Recommended DMARC policy for recommendations (none, quarantine, reject)
```

### Output Options
The tool now supports various output formats and options:

```
-v, --verbose               Increase verbosity level (can be used multiple times, e.g., -vv)
-q, --quiet                 Quiet mode, only show important results
--json                      Generate JSON output
--output FILE               Save results to a file
```

### Dependencies
You can install the python3 dependencies using the requeriments.txt file:
```pip3 install -r requirements.txt```

For email testing functionality, a local or remote SMTP server is needed:

#### Linux
```sudo apt-get install postfix```

#### macOS
Postfix is pre-installed on macOS, but you may need to start it:
```sudo postfix start```

#### Windows
For Windows, specify an external SMTP server with the `-s` parameter:
```python magicspoofmail.py -d example.com -t -e your@email.com -s smtp.yourprovider.com```

To avoid issues with the `User unknown in local recipient table` error when using Postfix as the SMTP server, follow these steps to adjust the configuration:

1. Open the Postfix configuration file:
```sudo nano /etc/postfix/main.cf```
2. Ensure the mydestination line is properly set or left empty to prevent local delivery attempts:
```mydestination =```
3. Save the changes and restart the Postfix service to apply the new configuration:
```sudo systemctl restart postfix```  (Linux)
```sudo postfix stop && sudo postfix start```  (macOS)

This change ensures that Postfix does not attempt to handle destination addresses locally and forwards them correctly to the configured destination server.  

### Checks
    - Check SPF record in a domain name (comprehensive analysis)
    - Check DMARC record in a domain name (comprehensive analysis)
    - Check DKIM configuration and selectors (comprehensive analysis)
    - In case that SPF, DMARC or DKIM is not configured, send a test email 

### Available options

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/help.png "MagicSpoofing - Help")

### Check a domain name

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/check_domain.png "MagicSpoofing - Check domain name")

### Check & test domain name

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/check_and_test.png "MagicSpoofing - Check and test domain name")

### Search from a name some TLD's

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/check_tlds.png "MagicSpoofing - Check some tld's from a name")

Note: You can add more TLD's editing the tlds list in the main script file.

### Improvements in this version
1. **Modular Code Structure**: Code has been separated into logical modules for better organization and maintainability.
2. **Enhanced Error Handling**: Added proper exception handling throughout the code.
3. **Better Documentation**: Added docstrings and comments to explain the functionality.
4. **Code Optimization**: Improved code efficiency and readability.
5. **Consistent Styling**: Applied consistent code style throughout the project.
6. **Comprehensive SPF Analysis**: Added detailed SPF record analysis with security recommendations.
7. **Recursive SPF Checking**: Added capability to recursively check SPF includes for DNS lookup limits.
8. **IP Range Analysis**: Added capability to detect overlapping IP ranges in SPF records.
9. **DKIM Selector Discovery**: Added capability to scan for common DKIM selectors.
10. **DKIM Security Analysis**: Added detailed DKIM record analysis with security recommendations.
11. **DKIM Alignment Checking**: Added capability to verify DKIM alignment with mail servers.
12. **DMARC Policy Analysis**: Added detailed DMARC policy analysis with security recommendations.
13. **DMARC Report Verification**: Added capability to verify DMARC report configuration.
14. **External Report Authorization**: Added capability to check for external report authorization records.
15. **Interactive Mode**: Added user-friendly interactive interface for easier usage.
16. **Predefined Profiles**: Added common configuration profiles for different use cases.
17. **Configuration Files**: Added ability to save and load configurations.
18. **JSON Output**: Added support for structured output in JSON format.
19. **Output to File**: Added ability to save results to a file.
20. **Cross-Platform Compatibility**: Added support for Linux, macOS, and Windows.
