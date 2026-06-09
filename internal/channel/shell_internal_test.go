package channel

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSetEnvOverridesExisting(t *testing.T) {
	env := []string{"PATH=/bin", "HOME=/home/alice", "TERM=xterm", "HOME=/dup"}
	out := setEnv(env, "HOME", "/")
	var homes []string
	for _, e := range out {
		if strings.HasPrefix(e, "HOME=") {
			homes = append(homes, e)
		}
	}
	if len(homes) != 1 || homes[0] != "HOME=/" {
		t.Fatalf("want single HOME=/, got %v (full env %v)", homes, out)
	}
	// Unrelated vars are preserved.
	if !contains(out, "PATH=/bin") || !contains(out, "TERM=xterm") {
		t.Fatalf("unrelated env vars dropped: %v", out)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestDescribeShellExit(t *testing.T) {
	if got := describeShellExit(nil); !strings.Contains(got, "status 0") {
		t.Errorf("nil err: got %q", got)
	}

	// Non-zero exit code.
	err := exec.Command("/bin/sh", "-c", "exit 7").Run()
	if got := describeShellExit(err); !strings.Contains(got, "status 7") {
		t.Errorf("exit 7: got %q", got)
	}

	// Killed by SIGSYS — the seccomp case — must be flagged specially.
	err = exec.Command("/bin/sh", "-c", "kill -SYS $$").Run()
	got := describeShellExit(err)
	if !strings.Contains(got, "SIGSYS") || !strings.Contains(got, "sandbox") {
		t.Errorf("SIGSYS: got %q, want mention of SIGSYS + sandbox", got)
	}

	// Killed by an ordinary signal.
	err = exec.Command("/bin/sh", "-c", "kill -TERM $$").Run()
	if got := describeShellExit(err); !strings.Contains(got, "signal") {
		t.Errorf("SIGTERM: got %q", got)
	}
}
