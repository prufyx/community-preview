package cncfprepare

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	fixedPythonASTTimeout   = 3 * time.Second
	maxFixedPythonASTOutput = 16 << 10
)

var errFixedPythonASTRunner = errors.New("selected CPython AST runner failed")

// runFixedPythonAST runs trusted helper text under one explicitly selected
// CPython executable. Supplied source is passed only over stdin and is never
// interpolated into the command or imported by this process boundary.
func runFixedPythonAST(raw []byte, interpreter, helper string) ([]byte, error) {
	if !filepath.IsAbs(interpreter) {
		return nil, errFixedPythonASTRunner
	}
	info, err := os.Stat(interpreter)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, errFixedPythonASTRunner
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixedPythonASTTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, interpreter, "-I", "-S", "-c", helper)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(raw)
	var stdout limitedPythonASTOutput
	stdout.limit = maxFixedPythonASTOutput
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stdout.exceeded {
		return nil, errFixedPythonASTRunner
	}
	return stdout.Bytes(), nil
}

type limitedPythonASTOutput struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (w *limitedPythonASTOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		w.exceeded = true
		return 0, errFixedPythonASTRunner
	}
	return w.Buffer.Write(p)
}
