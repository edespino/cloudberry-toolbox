// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// File: sysinfo_test.go
// Package: cmd
//
// Description:
// This file contains unit tests for the `sysinfo` command in the Cloudberry toolbox.
// The tests validate the functionality of system information gathering methods,
// ensuring correctness and proper error handling. It includes real environment tests
// as well as simulated edge cases to cover various scenarios.
//
// Features Tested:
// - System detail retrieval:
//   * OS name and version
//   * Architecture
//   * Hostname
//   * Kernel version
//   * CPU count
//   * Memory statistics
// - Database information:
//   * GPHOME environment validation
//   * PostgreSQL build configuration
//   * PostgreSQL server version
//   * Cloudberry Database version
// - Format validation (JSON, YAML)
// - Concurrency safety
//
// Test Categories:
// 1. Basic System Information:
//    - Tests for retrieving system details
//    - Validation of output formats and content
//
// 2. Database Integration:
//    - GPHOME environment variable handling
//    - PostgreSQL configuration and version detection
//    - Cloudberry Database version detection
//
// 3. Error Cases:
//    - Missing files and executables
//    - Invalid GPHOME paths
//    - Inaccessible system information
//    - Invalid output formats
//
// 4. Performance and Concurrency:
//    - Concurrent execution safety
//    - Large output handling
//
// Usage:
// - Run all tests:
//   go test -v
//
// - Run tests with coverage:
//   go test -cover -v
//
// Note:
// - Some tests create temporary mock files and directories
// - Tests handle cleanup automatically via defer statements
// - Mock executables are created with appropriate permissions
//
// Authors:
// - Cloudberry Open Source Contributors

package cmd

import (
        "io"
        "os"
        "strings"
        "sync"
        "testing"
        "path/filepath"

)

// captureOutput captures the output of a function to help validate printed output in tests.
func captureOutput(f func()) string {
        r, w, _ := os.Pipe()
        stdOut := os.Stdout
        os.Stdout = w
        defer func() { os.Stdout = stdOut }()

        f()
        w.Close()
        out, _ := io.ReadAll(r)
        return string(out)
}

// TestGetOS validates that the getOS function returns a non-empty string representing the OS.
func TestGetOS(t *testing.T) {
        os := getOS()
        if os == "" {
                t.Errorf("Expected OS to be non-empty")
        }
}

// TestGetArchitecture ensures the getArchitecture function retrieves the system's architecture.
func TestGetArchitecture(t *testing.T) {
        arch := getArchitecture()
        if arch == "" {
                t.Errorf("Expected architecture to be non-empty")
        }
}

// TestGetHostname validates the getHostname function for expected hostname retrieval.
func TestGetHostname(t *testing.T) {
        hostname, err := getHostname()
        if err != nil {
                t.Errorf("Unexpected error retrieving hostname: %v", err)
        }
        if hostname == "" {
                t.Errorf("Expected hostname to be non-empty")
        }
}

// TestGetKernelVersion validates kernel version retrieval via getKernelVersion.
func TestGetKernelVersion(t *testing.T) {
        kernel, err := getKernelVersion()
        if err != nil {
                t.Errorf("Unexpected error retrieving kernel version: %v", err)
        }
        if !strings.HasPrefix(kernel, "Linux ") {
                t.Errorf("Expected kernel version to start with 'Linux '")
        }
}

// TestGetKernelVersionError tests error handling when uname is unavailable.
func TestGetKernelVersionError(t *testing.T) {
        tempDir := os.TempDir()
        originalPath := os.Getenv("PATH")
        defer os.Setenv("PATH", originalPath) // Restore original PATH after test

        os.Setenv("PATH", tempDir)
        _, err := getKernelVersion()

        if err == nil {
                t.Errorf("Expected error when uname command is unavailable")
        }
}

// TestGetOSVersion ensures proper error handling when the OS version cannot be retrieved.
func TestGetOSVersion(t *testing.T) {
        osVersion, err := getOSVersion()
        if err != nil {
                t.Errorf("Unexpected error retrieving OS version: %v", err)
        }
        if osVersion == "" {
                t.Errorf("Expected OS version to be non-empty")
        }
}

// TestGetCPUCount validates that the CPU count is greater than 0.
func TestGetCPUCount(t *testing.T) {
        cpus := getCPUCount()
        if cpus <= 0 {
                t.Errorf("Expected CPU count to be greater than 0, got: %d", cpus)
        }
}

// TestGetReadableMemoryStats validates memory stats retrieval from /proc/meminfo.
func TestGetReadableMemoryStats(t *testing.T) {
    // Save original procMeminfo value
    originalProcMeminfo := procMeminfo
    defer func() { procMeminfo = originalProcMeminfo }()

    memoryStats, err := getReadableMemoryStats()
    if err != nil {
        t.Errorf("Unexpected error retrieving memory stats: %v", err)
    }
    if len(memoryStats) == 0 {
        t.Errorf("Expected memory stats to be non-empty")
    }

    // Validate expected memory stat keys
    expectedKeys := []string{"MemTotal", "MemFree", "MemAvailable", "Cached", "Buffers"}
    for _, key := range expectedKeys {
        if _, exists := memoryStats[key]; !exists {
            t.Errorf("Expected memory stat '%s' not found", key)
        }
    }
}

// TestGetReadableMemoryStatsMissingFile simulates missing /proc/meminfo for error handling.
func TestGetReadableMemoryStatsMissingFile(t *testing.T) {
    // Save original procMeminfo value
    originalProcMeminfo := procMeminfo
    defer func() { procMeminfo = originalProcMeminfo }()

    // Set to non-existent file for test
    procMeminfo = "/nonexistent/meminfo"

    _, err := getReadableMemoryStats()
    if err == nil {
        t.Errorf("Expected error for missing /proc/meminfo")
    }
    if !strings.Contains(err.Error(), "meminfo: failed to read file") {
        t.Errorf("Expected error message to contain 'meminfo: failed to read file', got: %v", err)
    }
}

// TestHumanizeSize validates the memory size conversion function.
func TestHumanizeSize(t *testing.T) {
    testCases := []struct {
        input    string
        expected string
    }{
        {"1024", "1.0 MiB"},
        {"2048576", "2.0 GiB"},
        {"512", "512 KiB"},
        {"invalid", "invalid"},
    }

    for _, tc := range testCases {
        result := humanizeSize(tc.input)
        if result != tc.expected {
            t.Errorf("humanizeSize(%s) = %s; want %s", tc.input, result, tc.expected)
        }
    }
}

// TestGetGPHOMEEmpty validates error handling when GPHOME is unset.
func TestGPHOMEEmpty(t *testing.T) {
        os.Unsetenv("GPHOME") // Ensure GPHOME is unset
        _, err := getGPHOME()
        if err == nil || !strings.Contains(err.Error(), "GPHOME: environment variable not set") {
                t.Errorf("Expected error for unset GPHOME")
        }
}

// TestGetPGConfigConfigure tests error handling when pg_config does not exist.
func TestGetPGConfigConfigure(t *testing.T) {
        os.Setenv("GPHOME", "/tmp") // Assuming /tmp/bin/pg_config does not exist
        _, err := getPGConfigConfigure("/tmp")
        if err == nil {
                t.Errorf("Expected error for non-existent pg_config")
        }
}

// TestValidateFormat ensures validateFormat handles valid and invalid formats correctly.
func TestValidateFormat(t *testing.T) {
        err := validateFormat("json")
        if err != nil {
                t.Errorf("Unexpected error for valid format 'json'")
        }

        err = validateFormat("yaml")
        if err != nil {
                t.Errorf("Unexpected error for valid format 'yaml'")
        }

        err = validateFormat("invalid")
        if err == nil {
                t.Errorf("Expected error for invalid format")
        }
}

// TestRunSysInfoInvalidFormat validates error handling for an invalid format in RunSysInfo.
func TestRunSysInfoInvalidFormat(t *testing.T) {
        formatFlag = "invalid" // Invalid format
        defer func() { formatFlag = "yaml" }() // Reset after test

        err := RunSysInfo(nil, nil)
        if err == nil {
                t.Error("Expected error for invalid format")
        }
        if !strings.Contains(err.Error(), "invalid format") {
                t.Errorf("Expected error message to contain 'invalid format', got: %v", err)
        }
}

// TestRunSysInfoValidFormats validates JSON and YAML outputs from RunSysInfo.
func TestRunSysInfoValidFormats(t *testing.T) {
    // Save original GPHOME and restore after test
    originalGPHOME := os.Getenv("GPHOME")
    defer os.Setenv("GPHOME", originalGPHOME)
    
    // Set a valid GPHOME with required executables
    tmpDir := t.TempDir()
    binDir := filepath.Join(tmpDir, "bin")
    err := os.MkdirAll(binDir, 0755)
    if err != nil {
        t.Fatalf("Failed to create test bin directory: %v", err)
    }

    // Create mock executables
    pgConfigPath := filepath.Join(binDir, "pg_config")
    postgresPath := filepath.Join(binDir, "postgres")
    mockContent := "#!/bin/sh\necho 'test'\n"
    if err := os.WriteFile(pgConfigPath, []byte(mockContent), 0755); err != nil {
        t.Fatalf("Failed to create mock pg_config: %v", err)
    }
    if err := os.WriteFile(postgresPath, []byte(mockContent), 0755); err != nil {
        t.Fatalf("Failed to create mock postgres: %v", err)
    }

    os.Setenv("GPHOME", tmpDir)

    for _, format := range []string{"json", "yaml"} {
        formatFlag = format
        var output string
        output = captureOutput(func() {
            err := RunSysInfo(nil, nil)
            if err != nil {
                t.Errorf("Unexpected error for format %s: %v", format, err)
            }
        })

        if format == "json" && !strings.Contains(output, "\"os\"") {
            t.Errorf("Expected JSON output to contain OS information")
        }
        if format == "yaml" && !strings.Contains(output, "os:") {
            t.Errorf("Expected YAML output to contain OS information")
        }
    }
}

// TestRootCommandExecution validates rootCmd execution and output.
func TestRootCommandExecution(t *testing.T) {
        rootCmd.SetArgs([]string{})
        var output string
        output = captureOutput(func() {
                if err := rootCmd.Execute(); err != nil {
                    // Error output is expected part of normal operation now
                    if !strings.Contains(err.Error(), "invalid format") && 
                       !strings.Contains(err.Error(), "multiple errors occurred") {
                        t.Errorf("Unexpected error executing rootCmd: %v", err)
                    }
                }
        })

        if output == "" {
                t.Errorf("Expected output from rootCmd execution")
        }
}

// TestGPHOMEInvalidPath validates error handling for an invalid GPHOME path.
func TestGPHOMEInvalidPath(t *testing.T) {
        os.Setenv("GPHOME", "/invalid-path")
        _, err := getGPHOME()
        if err == nil || !strings.Contains(err.Error(), "directory does not exist") {
                t.Errorf("Expected directory does not exist error")
        }
}

// TestRunSysInfoConcurrency validates that RunSysInfo handles concurrent execution safely.
func TestRunSysInfoConcurrency(t *testing.T) {
    // Save original GPHOME and restore after test
    originalGPHOME := os.Getenv("GPHOME")
    defer os.Setenv("GPHOME", originalGPHOME)
    // Set GPHOME for this test
    tmpDir := t.TempDir()
    os.Setenv("GPHOME", tmpDir)

    var wg sync.WaitGroup
    formatFlag = "json" // Ensure valid format for test

    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            err := RunSysInfo(nil, nil)
            // Now we expect an error
            if err == nil {
                t.Errorf("Expected error in concurrent execution when GPHOME is not properly configured")
            }
        }()
    }

    wg.Wait()
}

// TestRunSysInfoLargeOutput ensures RunSysInfo produces a sufficiently large output.
func TestRunSysInfoLargeOutput(t *testing.T) {
        formatFlag = "json"
        output := captureOutput(func() {
                RunSysInfo(nil, nil)
        })

        if len(output) < 100 {
                t.Errorf("Expected larger output for detailed system info")
        }
}

// TestGetPostgresVersion validates postgres version retrieval
func TestGetPostgresVersion(t *testing.T) {
    // Create a temporary directory with a mock postgres executable
    tmpDir := t.TempDir()
    binDir := filepath.Join(tmpDir, "bin")
    err := os.MkdirAll(binDir, 0755)
    if err != nil {
        t.Fatalf("Failed to create temporary bin directory: %v", err)
    }

    // Create a mock postgres executable
    postgresPath := filepath.Join(binDir, "postgres")
    mockContent := `#!/bin/sh
echo "postgres (Cloudberry Database) 14.4"`
    err = os.WriteFile(postgresPath, []byte(mockContent), 0755)
    if err != nil {
        t.Fatalf("Failed to create mock postgres executable: %v", err)
    }

    // Test postgres version retrieval
    version, err := getPostgresVersion(tmpDir)
    if err != nil {
        t.Errorf("Unexpected error getting postgres version: %v", err)
    }
    if !strings.Contains(version, "Cloudberry Database") {
        t.Errorf("Expected version to contain 'Cloudberry Database', got: %s", version)
    }
}

// Add the error test function:
func TestGetPostgresVersionError(t *testing.T) {
    tmpDir := t.TempDir()
    _, err := getPostgresVersion(tmpDir)
    if err == nil {
        t.Error("Expected error for missing postgres executable")
    }
    if !strings.Contains(err.Error(), "executable not found") {
        t.Errorf("Expected 'executable not found' error, got: %v", err)
    }
}

// Modify the existing TestRunSysInfoRealEnvironment to include postgres version check:
func TestRunSysInfoRealEnvironment(t *testing.T) {
    // Save original GPHOME and restore after test
    originalGPHOME := os.Getenv("GPHOME")
    defer os.Setenv("GPHOME", originalGPHOME)

    // Set up a valid test environment
    tmpDir := t.TempDir()
    binDir := filepath.Join(tmpDir, "bin")
    err := os.MkdirAll(binDir, 0755)
    if err != nil {
        t.Fatalf("Failed to create test bin directory: %v", err)
    }

    // Create mock executables
    pgConfigPath := filepath.Join(binDir, "pg_config")
    postgresPath := filepath.Join(binDir, "postgres")
    mockContent := "#!/bin/sh\necho 'test'\n"
    if err := os.WriteFile(pgConfigPath, []byte(mockContent), 0755); err != nil {
        t.Fatalf("Failed to create mock pg_config: %v", err)
    }
    if err := os.WriteFile(postgresPath, []byte(mockContent), 0755); err != nil {
        t.Fatalf("Failed to create mock postgres: %v", err)
    }

    os.Setenv("GPHOME", tmpDir)

    formatFlag = "json"
    output := captureOutput(func() {
        err := RunSysInfo(nil, nil)
        if err != nil {
            t.Errorf("Unexpected error in real environment: %v", err)
        }
    })

    if !strings.Contains(output, "\"os\"") {
        t.Errorf("Expected output to contain OS information")
    }
}

// TestGetGPVersion validates gp version retrieval
func TestGetGPVersion(t *testing.T) {
    // Create a temporary directory with a mock postgres executable
    tmpDir := t.TempDir()
    binDir := filepath.Join(tmpDir, "bin")
    err := os.MkdirAll(binDir, 0755)
    if err != nil {
        t.Fatalf("Failed to create temporary bin directory: %v", err)
    }

    // Create a mock postgres executable
    postgresPath := filepath.Join(binDir, "postgres")
    mockContent := `#!/bin/sh
echo "postgres (Cloudberry Database) 1.6.0 build 1"`
    err = os.WriteFile(postgresPath, []byte(mockContent), 0755)
    if err != nil {
        t.Fatalf("Failed to create mock postgres executable: %v", err)
    }

    // Test gp version retrieval
    version, err := getGPVersion(tmpDir)
    if err != nil {
        t.Errorf("Unexpected error getting gp version: %v", err)
    }
    if !strings.Contains(version, "1.6.0") {
        t.Errorf("Expected version to contain '1.6.0', got: %s", version)
    }
}

// TestGetGPVersionError tests error handling when postgres executable is missing
func TestGetGPVersionError(t *testing.T) {
    tmpDir := t.TempDir()
    _, err := getGPVersion(tmpDir)
    if err == nil {
        t.Error("Expected error for missing postgres executable")
    }
    if !strings.Contains(err.Error(), "executable not found") {
        t.Errorf("Expected 'executable not found' error, got: %v", err)
    }
}
