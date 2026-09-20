// Package corpusattest emits the maintainer's corpus-completeness attestation
// over the UNFILTERED embedded community-project rule pack.
//
// The attestation is the maintainer asserting, per component, that every
// reviewed rule they hold for that component is present in this pack at this
// revision. It authors no compatibility claim: every rule it covers was
// already reviewed and is already shipped. Its only job is to let the engine
// tell "this is the complete applicable corpus" apart from "these are the
// rules the caller happened to select".
//
// It is deliberately computed over the whole pack. A filtered view cannot
// support a completeness statement, so this command never narrows by project
// or by version pair.
package corpusattest

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx-cli/internal/maintainer/sourcecorpus"
	"github.com/prufyx/prufyx-cli/internal/projectcheck"
)

const maxPackBytes = 4 << 20

// Document renders the attestation for the current embedded pack as the exact
// bytes the asset holds: indented JSON with a trailing newline.
func Document() ([]byte, error) {
	attestation, err := projectcheck.BuildAttestation()
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return nil, err
	}
	// Round-trip through the same parser the runtime uses. An attestation this
	// command cannot itself parse must never reach the asset.
	if _, err := projectcheck.ParseAttestation(raw); err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// Digest is the attestation's canonical digest, computed with the reviewed
// corpus hashing helper rather than a second SHA-256 implementation.
func Digest(document []byte) (string, error) {
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return "", err
	}
	canonical, err := sourcecorpus.Canonical(value)
	if err != nil {
		return "", err
	}
	return sourcecorpus.SHA(canonical), nil
}

// verifyPackBinding re-reads the pack file in the working tree and confirms it
// hashes to the packDigest the embedded pack produced. It is an independent
// cross-check: the digest inside the attestation is computed from the compiled
// asset, and this confirms the reviewer is looking at the same bytes.
func verifyPackBinding(packPath, expected string) error {
	raw, err := os.ReadFile(packPath)
	if err != nil {
		return err
	}
	if len(raw) > maxPackBytes {
		return fmt.Errorf("rule pack exceeds the reviewed bound")
	}
	if actual := sourcecorpus.SHA(raw); actual != expected {
		return fmt.Errorf("rule pack digest does not match the embedded pack")
	}
	return nil
}

// Run is the maintainer subcommand adapter. It follows the same
// (args, stdout, stderr) int shape as the other maintainer commands.
func Run(args []string, stdout, stderr io.Writer, cliRoot string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	mode := args[0]
	if mode != "generate" && mode != "check" {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	flags := flag.NewFlagSet("corpus-attestation "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	defaultOutput := filepath.Join(cliRoot, "internal/projectcheck", projectcheck.AttestationPath)
	defaultPack := filepath.Join(cliRoot, "internal/projectcheck/data/rules.json")
	output := flags.String("output", defaultOutput, "attestation asset path")
	pack := flags.String("rules", defaultPack, "community-project rule pack")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *output == "" || *pack == "" {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}

	document, err := Document()
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}
	attestation, err := projectcheck.ParseAttestation(document)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}
	if err := verifyPackBinding(*pack, attestation.PackDigest); err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: rule pack binding rejected")
		return 2
	}
	digest, err := Digest(document)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}

	if mode == "check" {
		current, readErr := os.ReadFile(*output)
		if readErr != nil || string(current) != string(document) {
			fmt.Fprintln(stderr, "corpus-attestation: committed attestation is stale")
			return 2
		}
		fmt.Fprintf(stdout, "corpus-attestation current: revision=%s components=%d rules=%d digest=%s\n", attestation.Revision, len(attestation.Components), attestation.RuleCount, digest)
		return 0
	}
	if err := os.WriteFile(*output, document, 0o644); err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: cannot commit the attestation")
		return 2
	}
	fmt.Fprintf(stdout, "corpus-attestation written: revision=%s components=%d rules=%d digest=%s\n", attestation.Revision, len(attestation.Components), attestation.RuleCount, digest)
	return 0
}
