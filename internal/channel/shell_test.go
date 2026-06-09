package channel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestShellHandlerDeniesWhenNotAllowed(t *testing.T) {
	h := &ShellHandler{allow: false}
	if _, _, err := h.HandleOpen(context.Background(), nil, 1, json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected the open to be rejected when allow=false")
	}
}

func TestResolveShellHonorsUserShell(t *testing.T) {
	dir := t.TempDir()
	sh := filepath.Join(dir, "myshell")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, args, err := resolveShell(sh)
	if err != nil {
		t.Fatalf("resolveShell: %v", err)
	}
	if path != sh || len(args) != 0 {
		t.Fatalf("got (%q, %v), want (%q, nil)", path, args, sh)
	}
}

func TestResolveShellFallsBack(t *testing.T) {
	// A non-existent user shell falls through to a system shell (every Linux
	// box in CI has at least /bin/sh).
	path, _, err := resolveShell(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("resolveShell fallback: %v", err)
	}
	if !isExecutableFile(path) {
		t.Fatalf("fallback shell %q is not executable", path)
	}
}

func TestIsExecutableFile(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "exe")
	noexe := filepath.Join(dir, "noexe")
	_ = os.WriteFile(exe, []byte("x"), 0o755)
	_ = os.WriteFile(noexe, []byte("x"), 0o644)

	if !isExecutableFile(exe) {
		t.Error("executable file reported non-executable")
	}
	if isExecutableFile(noexe) {
		t.Error("non-executable file reported executable")
	}
	if isExecutableFile(dir) {
		t.Error("directory reported executable")
	}
	if isExecutableFile(filepath.Join(dir, "missing")) {
		t.Error("missing file reported executable")
	}
}
