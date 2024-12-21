# SysInfo Command and Tests

## Overview
The `sysinfo` command is part of the Apache Cloudberry (Incubating) toolbox. It gathers and displays system information in either YAML or JSON format. This utility is designed for use in various environments to collect details about the operating system, architecture, memory, and other vital system properties.

The accompanying test suite validates the behavior and reliability of the `sysinfo` command, ensuring that edge cases are handled appropriately.

---

## Features
- System Information:
  - Operating System and version
  - Architecture
  - Kernel version
  - Hostname
  - CPU count
  - Memory statistics (Total, Free, Available, Cached, Buffers)

- Database Information (when GPHOME is set):
  - GPHOME environment validation
  - PostgreSQL build configuration options (from pg_config --configure)
  - PostgreSQL server version (from postgres --version)
  - Cloudberry Database version (from postgres --gp-version)

- Output Formats:
  - YAML (default)
  - JSON

- Additional Features:
  - Concurrent data collection for system information
  - Graceful error handling with detailed summaries
  - Memory sizes in human-readable format (KiB, MiB, GiB)

---

## Commands
### `sysinfo`
- Displays detailed system information.
- Supports output formats:
  - `yaml` (default)
  - `json`

#### Example Usage
```bash
# Default YAML output
./cbtoolbox sysinfo

# JSON output
./cbtoolbox sysinfo --format json
```

#### Example Output
```yaml
os: linux
architecture: amd64
hostname: mdw
kernel: Linux 4.18.0-553.el8_10.x86_64
os_version: Rocky Linux 8.10 (Green Obsidian)
cpus: 16
memory_stats:
  Buffers: 5.1 MiB
  Cached: 818.2 MiB
  MemAvailable: 60.6 GiB
  MemFree: 60.3 GiB
  MemTotal: 61.6 GiB
GPHOME: /usr/local/cloudberry-db-1.6.0
pg_config_configure:
  - --prefix=/usr/local/cloudberry-db
  - --disable-external-fts
  - --enable-gpcloud
  - --enable-ic-proxy
  - --enable-mapreduce
  - --enable-orafce
  - --enable-orca
  - --enable-pxf
  - --enable-tap-tests
  - --with-gssapi
  - --with-ldap
  - --with-libxml
  - --with-lz4
  - --with-pam
  - --with-perl
  - --with-pgport=5432
  - --with-python
  - --with-pythonsrc-ext
  - --with-ssl=openssl
  - --with-openssl
  - --with-uuid=e2fs
  - --with-includes=/usr/local/xerces-c/include
  - --with-libraries=/usr/local/cloudberry-db/lib
postgres_version: postgres (Cloudberry Database) 14.4
gp_version: postgres (Cloudberry Database) 1.6.0 build 1
```

---

## Test Suite
### Overview
The test suite validates:
1. System information retrieval
2. Database information collection
3. Error handling for missing components
4. Concurrent execution safety
5. Output format validation

### Key Test Cases
1. **System Information Tests**:
   - OS and architecture detection
   - Hostname and kernel version retrieval
   - Memory statistics collection
   - CPU count validation

2. **Database Integration Tests**:
   - GPHOME environment handling
   - PostgreSQL configuration parsing
   - Version information retrieval
   - Error cases for missing executables

3. **Format and Output Tests**:
   - YAML/JSON format validation
   - Output structure verification
   - Error message formatting

4. **Concurrency Tests**:
   - Safe parallel execution
   - Resource cleanup

### Additional Test Enhancements
- **Dynamic Output Validation**:
  - Validate the presence of specific keys (e.g., `os`, `hostname`) in the output instead of relying on raw size comparisons.
- **Permission Simulation**:
  - Incorporate mocking strategies to simulate inaccessible files or restricted permissions without requiring elevated privileges.

### How to Run Tests
```bash
# Run all tests
go test -v

# Run tests with coverage
go test -cover -v

# Run specific test
go test -v -run TestName
```

### Sample Output
```bash
=== RUN   TestGetOS
--- PASS: TestGetOS (0.00s)
=== RUN   TestGetArchitecture
--- PASS: TestGetArchitecture (0.00s)
=== RUN   TestRunSysInfoConcurrency
--- PASS: TestRunSysInfoConcurrency (0.01s)
PASS
coverage: 84.2% of statements
```

---

## Troubleshooting
### Common Issues
1. **GPHOME Configuration**:
   - Error: `GPHOME: environment variable not set`
   - Solution: Set GPHOME to your Cloudberry installation directory
   - Example: `export GPHOME=/usr/local/cloudberry-db-1.6.0`

2. **Missing Files**:
   - Error: `os-release: failed to read file`
   - Solution: Ensure required system files are accessible
   - Files needed: `/etc/os-release`, `/proc/meminfo`

3. **Missing Executables**:
   - Error: `postgres: executable not found at $GPHOME/bin/postgres`
   - Solution: Verify Cloudberry installation and permissions

4. **Format Errors**:
   - Error: `invalid format: xyz`
   - Solution: Use only 'yaml' or 'json' as format options

5. **Permissions**:
   - Insufficient permissions may prevent access to certain files or directories
   - Solution: Run the command with appropriate privileges

### Error Messages
- Error messages are prefixed with the component name
- Summary of all errors is displayed before output
- Non-zero exit code when errors occur

### Debugging Tips
- Use the `--format json` flag to capture structured output for easier parsing
- Review the error summary printed by `RunSysInfo` to identify specific issues

---

## Implementation Details
### System Information Retrieval
- The `sysinfo` command relies on Go standard libraries for retrieving basic system information
- Environment-specific details like `GPHOME` are validated for existence and correctness
- Implements concurrency with goroutines to improve performance
- Memory statistics are converted to human-readable formats

### Testing Framework
- **Go Testing Package**:
  - Unit tests for individual functions
  - Integration tests for end-to-end validation
- **Coverage Validation**:
  - Test coverage ensures all critical paths are validated
- **Mocking and Simulation**:
  - Simulates missing files or environment variables for robust error handling validation

---

## Contributing
To contribute to the `sysinfo` command or its tests:
1. Fork the repository
2. Create your feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

## License
Licensed under the Apache License, Version 2.0

---

## Contact
For questions or issues, please reach out via GitHub repository.
