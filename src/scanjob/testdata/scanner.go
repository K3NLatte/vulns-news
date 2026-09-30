// Offline executable fixture implementing the repo-scan flag/output contract.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "heartbeat" {
		for {
			_ = os.WriteFile(os.Getenv("SCANJOB_HEARTBEAT"), []byte(time.Now().String()), 0600)
			time.Sleep(10 * time.Millisecond)
		}
	}
	repository := flag.String("repository", "", "")
	ref := flag.String("ref", "", "")
	state := flag.String("state", "", "")
	nvd := flag.Bool("nvd", true, "")
	timeout := flag.Duration("timeout", 0, "")
	flag.Parse()
	if *repository != "https://github.com/example/project" || *nvd || *timeout <= 0 || flag.NArg() != 0 {
		os.Exit(2)
	}
	if filepath.Dir(*state) != os.Getenv("TMPDIR") {
		os.Exit(3)
	}
	if err := os.WriteFile(os.Getenv("SCANJOB_MARKER"), []byte(filepath.Dir(*state)), 0600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*state, []byte("temporary state"), 0600); err != nil {
		panic(err)
	}
	fmt.Fprint(os.Stderr, strings.Repeat("private stderr", 10000))
	switch *ref {
	case "descendant":
		child := exec.Command(os.Args[0], "heartbeat")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			panic(err)
		}
		time.Sleep(time.Minute)
	case "failure":
		os.Exit(1)
	case "timeout":
		time.Sleep(time.Minute)
	case "invalid":
		fmt.Print("not json")
		return
	case "oversized":
		fmt.Print(strings.Repeat("x", 5<<20))
		return
	case "incomplete":
		fmt.Print(`{"repository":{"commit_sha":"abc"},"report":{"refresh_complete":false}}`)
		return
	}
	fmt.Print(`{"repository":{"commit_sha":"abc"},"report":{"refresh_complete":true}}`)
}
