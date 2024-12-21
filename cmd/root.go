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

// File: root.go
// Package: cmd
//
// Description:
// This file contains the entry point and base configuration for the `cbtoolbox` CLI.
// It defines the root command (`rootCmd`) that acts as the main command for the
// application and manages subcommands like `sysinfo`. The root command also handles
// application-wide configuration and flags.
//
// Features:
// - Serves as the primary entry point for the `cbtoolbox` CLI application.
// - Defines global flags and configurations for the application.
// - Organizes and executes subcommands, such as `sysinfo`.
//
// Usage:
// - Run the `cbtoolbox` command without any arguments to see the help message:
//   `./cbtoolbox`
// - Add subcommands like `sysinfo` to extend functionality.
//
// Authors:
// - Cloudberry Open Source Contributors

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
// This command provides a help message and serves as the entry point for
// executing subcommands within the `cbtoolbox` CLI.
var rootCmd = &cobra.Command{
    Use:   "cbtoolbox",
    Short: "A toolbox for system and database diagnostics",
    Long: `The cbtoolbox CLI provides various utilities for diagnosing
system and database environments. It includes subcommands like
'sysinfo' to gather system information in JSON or YAML format.
    
Examples:
  - Display help for the root command:
    ./cbtoolbox --help

  - Execute the sysinfo subcommand:
    ./cbtoolbox sysinfo --format json`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This function is called by main.main() to start the application.
func Execute() {
    err := rootCmd.Execute()
    if err != nil {
        os.Exit(1)
    }
}

// init initializes the root command by defining global flags and configurations.
// Subcommands such as `sysinfo` are added to the root command during this phase.
func init() {
    // Example of a global persistent flag:
    // rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cbtoolbox.yaml)")
    rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
