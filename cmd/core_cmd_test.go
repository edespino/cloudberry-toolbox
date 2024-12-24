package cmd

import (
   "os"
   "path/filepath"
   "strings"
   "testing"
)

func TestCoreCommand(t *testing.T) {
   // Store original state
   origRoot := rootCmd
   defer func() { rootCmd = origRoot }()

   tmpDir, err := os.MkdirTemp("", "core_test_*")
   if err != nil {
       t.Fatal(err)
   }
   defer os.RemoveAll(tmpDir)

   // Setup mock environment
   mockGPHOME := filepath.Join(tmpDir, "gphome")
   mockBinDir := filepath.Join(mockGPHOME, "bin")
   mockOutputDir := filepath.Join(tmpDir, "output")
   mockCorePath := filepath.Join(tmpDir, "core.1234")

   // Create directories
   for _, dir := range []string{mockBinDir, mockOutputDir} {
       if err := os.MkdirAll(dir, 0755); err != nil {
           t.Fatal(err)
       }
   }

   // Create mock files
   if err := os.WriteFile(filepath.Join(mockBinDir, "postgres"), []byte("mock"), 0755); err != nil {
       t.Fatal(err)
   }
   if err := os.WriteFile(mockCorePath, []byte("mock"), 0644); err != nil {
       t.Fatal(err)
   }
   
   // Setup mock command execution
   mock := &MockCommander{
       Outputs: []string{
           "core file from 'postgres' (signal 11)",    // file command output
           "postgres (PostgreSQL) 14.2",               // postgres --version
           "postgres (CloudBerry Database) 1.0.0",     // postgres --gp-version  
           "--with-openssl --with-python",             // pg_config output
           `Thread 1 (LWP 1234):
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6
#1  0x00007f8b4c37dc05 in abort () from /lib64/libc.so.6

Program received signal SIGSEGV
si_signo = 11
si_code = 1
_sigfault = {si_addr = 0x0}`,                         // gdb output
       },
       Errors: []error{nil, nil, nil, nil, nil},
   }

   // Store original state
   origCmd := cmdExecutor
   origDir := outputDir  
   origGPHOME := os.Getenv("GPHOME")
   origFormat := formatFlag
   
   // Set mock state
   SetCommander(mock)
   
   // Restore original state after test
   defer func() {
       SetCommander(origCmd)
       outputDir = origDir
       os.Setenv("GPHOME", origGPHOME)
       formatFlag = origFormat
       rootCmd = origRoot
   }()

   tests := []struct {
       name        string
       setupFunc   func() // New setup function for each test
       args        []string
       envVars     map[string]string
       outputDir   string 
       format      string
       expectError bool
       errorMsg    string
   }{
       {
           name: "no args",
           args: []string{"core"},
           envVars: map[string]string{
               "GPHOME": "",
           },
           outputDir: mockOutputDir,
           format: "yaml",
           expectError: true,
           errorMsg: "please specify a core file or directory",
       },
       {
           name: "missing GPHOME",
           args: []string{"core", mockCorePath},
           envVars: map[string]string{
               "GPHOME": "",
           },
           outputDir: mockOutputDir,
           format: "yaml",
           expectError: true, 
           errorMsg: "GPHOME environment variable must be set",
       },
       {
           name: "valid args with GPHOME",
           setupFunc: func() {
               mock.index = 0 // Reset mock command index
           },
           args: []string{"core", mockCorePath},
           envVars: map[string]string{
               "GPHOME": mockGPHOME,
           },
           outputDir: mockOutputDir,
           format: "yaml",
           expectError: false,
       },
       {
           name: "invalid format flag",
           args: []string{"core", "--format", "invalid", mockCorePath},
           envVars: map[string]string{
               "GPHOME": mockGPHOME,
           },
           outputDir: mockOutputDir,
           format: "invalid",
           expectError: true,
           errorMsg: "invalid format",
       },
       {
           name: "non-existent core file",
           args: []string{"core", filepath.Join(tmpDir, "nonexistent.core")},
           envVars: map[string]string{
               "GPHOME": mockGPHOME,
           },
           outputDir: mockOutputDir,
           format: "yaml",
           expectError: true,
           errorMsg: "no such file or directory",
       },
       {
           name: "invalid output directory",
           args: []string{"core", mockCorePath}, 
           envVars: map[string]string{
               "GPHOME": mockGPHOME,
           },
           outputDir: "/nonexistent/dir",
           format: "yaml",
           expectError: true,
           errorMsg: "failed to create output directory",
       },
   }

   for _, tt := range tests {
       t.Run(tt.name, func(t *testing.T) {
           // Reset command state
           rootCmd = origRoot
           
           // Run test-specific setup
           if tt.setupFunc != nil {
               tt.setupFunc()
           }
           
           // Setup environment
           for k, v := range tt.envVars {
               os.Setenv(k, v)
           }
           outputDir = tt.outputDir
           formatFlag = tt.format

           // Execute command
           rootCmd.SetArgs(tt.args)
           err := rootCmd.Execute()

           // Check for expected errors
           if tt.expectError {
               if err == nil {
                   t.Error("expected error but got none")
               } else if !strings.Contains(err.Error(), tt.errorMsg) {
                   t.Errorf("error = %q, want %q", err.Error(), tt.errorMsg)
               }
               return
           }

           // Check successful execution
           if err != nil {
               t.Errorf("unexpected error: %v", err)
               return
           }

           // Verify output files were created
           files, err := os.ReadDir(tt.outputDir)
           if err != nil {
               t.Errorf("reading output dir: %v", err)
           } else if len(files) == 0 {
               t.Error("no output files created")
           }
       })
   }
}
