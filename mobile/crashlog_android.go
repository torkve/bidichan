//go:build android

package mobile

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"syscall"
)

// crashFile is kept for the life of the process: the descriptor is what fd 2
// now points at, and letting the File be collected would close it.
var (
	crashMu   sync.Mutex
	crashFile *os.File
)

// RedirectCrashOutput points the runtime's own error output at a file, so that
// what killed the process outlives it.
//
// A Go program that dies of a panic or a fatal error prints the reason, and the
// goroutine stacks under it, to standard error. On Android none of that is
// recoverable afterwards: the runtime does not call android_set_abort_message,
// so the tombstone the system keeps records the signal and the thread and
// nothing about the cause, and an ordinary app may not read the system log
// where the text actually went. The crash is real, repeatable, and completely
// anonymous — which is the state this exists to end.
//
// Called once at startup, before anything can fail. The host reads whatever is
// in the file at the next start, and empties it.
func RedirectCrashOutput(path string) error {
	crashMu.Lock()
	defer crashMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("crash log: %w", err)
	}
	// Dup3 rather than Dup2: arm64 has no dup2 at all, and Dup3 with no flags
	// means the same thing everywhere else.
	if err := syscall.Dup3(int(f.Fd()), 2, 0); err != nil {
		_ = f.Close()
		return fmt.Errorf("crash log: redirect: %w", err)
	}
	// Replaces, rather than closes, any previous redirection: fd 2 already
	// points at the new file, so closing the old one now is safe.
	if crashFile != nil {
		_ = crashFile.Close()
	}
	crashFile = f

	// Every goroutine, not just the one that died. What a tunnel is doing when
	// it fails is spread across the reader, the writer and the supervisor, and
	// the one that happens to hit the fault is rarely the one that explains it.
	debug.SetTraceback("all")
	return nil
}
