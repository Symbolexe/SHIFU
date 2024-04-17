# SHIFU - CVE Finder Toolkit
![SHIFU-Screenshot](https://github.com/Symbolexe/SHIFU/assets/140549630/44c669ce-731f-4ff0-992c-491fe18b2f4a)
## Introduction
SHIFU is a comprehensive and powerful toolkit designed to streamline the process of finding detailed information about Common Vulnerabilities and Exposures (CVEs). Developed with security professionals, system administrators, and developers in mind, SHIFU offers a wide range of features and capabilities to simplify CVE research and analysis.
## Key Features
1. Automated CVE Retrieval

SHIFU enables users to retrieve detailed information about CVEs directly from the Red Hat CVE database. By automating the retrieval process, SHIFU saves time and effort, allowing users to focus on analyzing and addressing security vulnerabilities.

2. Manual and File Input Options

Users have the flexibility to input CVEs manually or provide a text file containing a list of CVEs. This dual input option caters to different user preferences and workflow requirements, enhancing usability and convenience.

3. Colorized Output for Readability

SHIFU provides colorized output in the terminal, enhancing readability and making it easier for users to interpret and analyze CVE information at a glance. Color-coded text highlights key details and improves overall user experience.

4. Detailed CVE Information

Upon retrieving CVE information, SHIFU presents a detailed overview of each CVE, including severity, public date, advisories, Bugzilla references, CVSS scores, CWE classifications, affected packages, and more. This comprehensive information empowers users to make informed decisions and take appropriate actions to mitigate security risks.

5. Save Results for Future Reference

SHIFU allows users to save the detailed CVE information to a file for future reference and documentation. By providing a structured and organized record of CVE research, SHIFU supports auditing, compliance, and knowledge management efforts within organizations.
## Technical Details
### Installation Requirements
To use SHIFU, ensure that you have the following prerequisites installed:
- Ruby
- bundler (RubyGems package manager)
### Installation Steps
- Clone the SHIFU repository to your local machine:
```git clone https://github.com/symbolexe/shifu.git```

- Navigate to the SHIFU directory:
```cd shifu```

- Install dependencies using bundler:
```bundle install```
## Usage Instructions
1. Manual Input: Choose the option to enter CVE IDs manually. Provide the CVE IDs separated by commas (e.g., CVE-2024-3096,CVE-2022-1234) and follow the prompts.
2. File Input: Choose the option to provide a file containing CVE IDs. Enter the name of the file when prompted, and SHIFU will process the CVEs one by one.
3. Save Results: SHIFU will save the detailed CVE information to a file named result-cves.txt in the current directory.
## Example Usage
```ruby
$ ruby shifu.rb
┌────────────────────────────────────────────┐
│                  SHIFU                     │
│           CVE Finder Toolkit               │
└────────────────────────────────────────────┘
Do you want to enter CVE IDs manually or provide a file? (manual/file): manual
Enter CVE IDs separated by commas (e.g., CVE-2024-3096,CVE-2022-1234): CVE-2024-3096,CVE-2022-1234
CVE Information:
Cve: CVE-2024-3096
Severity: moderate
Public date: 2024-04-12T00:00:00Z
Advisories: []
Bugzilla: 2275061
Bugzilla description: php: password_verify can erroneously return true, opening ATO risk
Cvss score:
Cvss scoring vector:
Cwe: CWE-626
Affected packages: []
Package state:
Resource url: https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-3096.json
Cvss3 scoring vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N
Cvss3 score: 4.8
CVE Information has been saved to result-cves.txt
Do you want to perform another search? (y/n): n
Thanks for using SHIFU!
```
## License
This project is licensed under the MIT License - see the LICENSE file for details.
## Support and Contributions
If you encounter any issues or have suggestions for improvements, please open an issue on GitHub. Contributions from the community are welcome and encouraged to make SHIFU even more robust and effective.
