/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"log"
	"os"
)

// main runs the estclient command named by the first argument.
func main() {
	log.SetPrefix(fmt.Sprintf("%s: ", appName))
	log.SetFlags(0)

	// Detect command.
	if len(os.Args) < 2 {
		usageError(os.Stderr, usageLineLength)
	}

	cmd, ok := commands[os.Args[1]]
	if !ok {
		usageError(os.Stderr, usageLineLength)
	}

	// Parse command line options. The flag set exits on a parse error, so
	// Parse returns no error to handle.
	set := cmd.FlagSet(os.Stdout, usageLineLength)
	_ = set.Parse(os.Args[2:])

	// Execute command.
	if isFlagPassed(set, helpFlag) {
		cmd.Usage(os.Stdout, usageLineLength)
	} else {
		if err := cmd.cmdFunc(os.Stdout, set); err != nil {
			log.Fatal(err)
		}
	}
}
