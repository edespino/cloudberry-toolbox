# Apache Cloudberry (Incubating) Toolbox

`cbtoolbox` is a versatile CLI tool designed for administrators and developers working with Apache Cloudberry (Incubating). The tool provides diagnostic and utility functions to simplify the management, monitoring, and debugging of Cloudberry environments.

## Features

- **System Diagnostics**:
  - Gather detailed system information, including OS, kernel, architecture, CPUs, and memory statistics.
  - Fetch environment-specific details such as `GPHOME` and `pg_config` configuration.
- **Database Information**:
  - Retrieve Cloudberry Database and PostgreSQL versions.
  - Collect database configurations for troubleshooting.
- **Flexible Output Formats**:
  - Support for JSON and YAML output formats for easy integration into other tools and workflows.
- **Utility Commands**:
  - Planned commands for log collection, session tracing, and core dump packaging.

## Commands

### `sysinfo`
Displays detailed system and database environment information.

#### Example Usage:
```bash
cbtoolbox sysinfo --format yaml
```

#### Example Output:
```yaml
os: linux
architecture: amd64
hostname: mdw
kernel: Linux 4.18.0-553.el8_10.x86_64
os_version: Rocky Linux 8.10 (Green Obsidian)
cpus: 16
memory_stats:
  Buffers: 5.1 KiB
  Cached: 982.1 KiB
  MemAvailable: 60.5 MiB
  MemFree: 60.1 MiB
  MemTotal: 61.6 MiB
GPHOME: /usr/local/cloudberry-db-1.6.0
pg_config_configure: |
  --prefix=/usr/local/cloudberry-db
  --disable-external-fts
  --enable-gpcloud
postgres_version: postgres (Cloudberry Database) 14.4
gp_version: postgres (Cloudberry Database) 1.6.0 build 1
```

## Installation

### Prerequisites
- **Go**: Ensure you have Go installed ([installation instructions](https://go.dev/doc/install)).

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/edespino/cbtoolbox.git
   cd cbtoolbox
   ```
2. Build the tool:
   ```bash
   go build -o cbtoolbox
   ```
3. Run the tool:
   ```bash
   ./cbtoolbox sysinfo
   ```

## Contributing

We welcome contributions to `cbtoolbox`! To get started:
1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with a clear description of the changes.

Please refer to the `CONTRIBUTING.md` file for detailed guidelines.

## License

`cbtoolbox` is licensed under the Apache License 2.0. See the `LICENSE` file for more details.

## Acknowledgments

This tool is developed as part of the Apache Cloudberry (Incubating) project. Special thanks to the Cloudberry community for their support and contributions.

---

For more information, visit the [official repository](https://github.com/edespino/cbtoolbox).

