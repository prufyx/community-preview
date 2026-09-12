package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx-cli/internal/currentbundle"
	"github.com/prufyx/prufyx-cli/internal/maintainer/knowledgesign"
	"golang.org/x/term"
)

func runKnowledgeSign(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return knowledgeSignError()
	}
	switch args[0] {
	case "init":
		return runKnowledgeSignInit(args[1:], stdout, stderr)
	case "sign-role":
		return runKnowledgeSignRole(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(stdout, "usage: prufyx-maintainer knowledge-sign <init|sign-role> [options]")
		return err
	default:
		return knowledgeSignError()
	}
}

func runKnowledgeSignInit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("knowledge-sign init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyDir := flags.String("key-dir", "", "new absolute private key directory outside a Git checkout")
	expires := flags.String("root-expires", "", "future root expiry as exact UTC RFC3339")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, writeErr := fmt.Fprintln(stdout, "usage: prufyx-maintainer knowledge-sign init --key-dir ABSOLUTE_NEW_DIR --root-expires UTC_RFC3339")
			return writeErr
		}
		return knowledgeSignError()
	}
	if flags.NArg() != 0 || *keyDir == "" || *expires == "" || knowledgesign.ValidateInitRequest(*keyDir, *expires) != nil {
		return knowledgeSignError()
	}
	passphrase, err := promptPassphrase(stderr, true)
	if err != nil {
		return knowledgeSignError()
	}
	result, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: *keyDir, RootExpires: *expires, Passphrase: passphrase})
	if err != nil {
		return knowledgeSignError()
	}
	output, err := json.Marshal(struct {
		Status      string `json:"status"`
		RootDigest  string `json:"rootDigest"`
		NetworkUsed bool   `json:"networkUsed"`
		KeysHandled bool   `json:"keysHandled"`
	}{"INITIALIZED", result.RootDigest, false, true})
	if err != nil {
		return knowledgeSignError()
	}
	if _, err := fmt.Fprintln(stdout, string(output)); err != nil {
		return &commandError{code: 2, message: "knowledge-sign: receipt output failed"}
	}
	return nil
}

func runKnowledgeSignRole(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("knowledge-sign sign-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var root, rootDigest, role, unsigned, payloadDigest, key, output string
	flags.StringVar(&root, "root", "", "independently supplied signed public root")
	flags.StringVar(&rootDigest, "root-digest", "", "independently verified root SHA-256")
	flags.StringVar(&role, "role", "", "targets, snapshot, or timestamp")
	flags.StringVar(&unsigned, "unsigned", "", "exact canonical unsigned role metadata")
	flags.StringVar(&payloadDigest, "payload-digest", "", "exact OLPC canonical signed payload SHA-256")
	flags.StringVar(&key, "key", "", "encrypted local role key")
	flags.StringVar(&output, "output", "", "new signature envelope output")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, writeErr := fmt.Fprintln(stdout, "usage: prufyx-maintainer knowledge-sign sign-role --root ABS --root-digest sha256:... --role ROLE --unsigned ABS --payload-digest sha256:... --key ABS --output ABS")
			return writeErr
		}
		return knowledgeSignError()
	}
	if flags.NArg() != 0 || root == "" || rootDigest == "" || role == "" || unsigned == "" || payloadDigest == "" || key == "" || output == "" || !filepath.IsAbs(output) {
		return knowledgeSignError()
	}
	rootRaw, err1 := signerInput(root, 128<<10)
	unsignedRaw, err2 := signerInput(unsigned, 512<<10)
	keyRaw, err3 := signerKey(key)
	if err1 != nil || err2 != nil || err3 != nil || knowledgesign.ValidateRoot(rootRaw, rootDigest) != nil {
		return knowledgeSignError()
	}
	passphrase, err := promptPassphrase(stderr, false)
	if err != nil {
		return knowledgeSignError()
	}
	if err := knowledgesign.SignRoleToFile(knowledgesign.SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: role, Unsigned: unsignedRaw, ExpectedPayloadDigest: payloadDigest, EncryptedKey: keyRaw, Passphrase: passphrase}, output); err != nil {
		return knowledgeSignError()
	}
	return nil
}

func signerInput(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, knowledgesign.ErrRejected
	}
	return currentbundle.ReadBoundedFile(path, limit)
}

func signerKey(path string) ([]byte, error) {
	raw, info, err := currentbundle.ReadBoundedFileInfo(path, knowledgesign.MaxKeyBytes)
	if err != nil || info == nil || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) {
		return nil, knowledgesign.ErrRejected
	}
	return raw, nil
}

func promptPassphrase(stderr io.Writer, confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, knowledgesign.ErrRejected
	}
	if _, err := fmt.Fprint(stderr, "Passphrase: "); err != nil {
		return nil, err
	}
	first, err := term.ReadPassword(fd)
	if err != nil {
		wipeBytes(first)
		return nil, err
	}
	if _, err := fmt.Fprintln(stderr); err != nil {
		wipeBytes(first)
		return nil, err
	}
	if !confirm {
		return first, nil
	}
	if _, err := fmt.Fprint(stderr, "Confirm passphrase: "); err != nil {
		wipeBytes(first)
		return nil, err
	}
	second, err := term.ReadPassword(fd)
	if err != nil {
		wipeBytes(first)
		wipeBytes(second)
		return nil, err
	}
	if _, err := fmt.Fprintln(stderr); err != nil {
		wipeBytes(first)
		wipeBytes(second)
		return nil, err
	}
	if !bytes.Equal(first, second) {
		wipeBytes(first)
		wipeBytes(second)
		return nil, knowledgesign.ErrRejected
	}
	wipeBytes(second)
	return first, nil
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
func knowledgeSignError() error {
	return &commandError{code: 2, message: "knowledge-sign: operation rejected"}
}
