package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/prufyx/prufyx-cli/internal/currentbundle"
	"github.com/prufyx/prufyx-cli/internal/maintainer/knowledgepublish"
)

func runKnowledgePublish(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return knowledgePublishError()
	}
	switch args[0] {
	case "prepare-targets":
		return runPrepareTargets(args[1:])
	case "prepare-snapshot":
		return runPrepareSnapshot(args[1:])
	case "prepare-timestamp":
		return runPrepareTimestamp(args[1:])
	case "finalize-role":
		return runFinalizeRole(args[1:])
	case "finalize-package":
		return runFinalizeKnowledgePackage(args[1:], stdout)
	default:
		return knowledgePublishError()
	}
}

type publishCommon struct {
	root, rootDigest, target, output string
}

func bindPublishCommon(flags *flag.FlagSet, values *publishCommon, includeTarget bool) {
	flags.StringVar(&values.root, "root", "", "independently supplied signed public TUF root")
	flags.StringVar(&values.rootDigest, "root-digest", "", "independently verified public root SHA-256")
	if includeTarget {
		flags.StringVar(&values.target, "target", "", "canonical CNCF external replacement target")
	}
	flags.StringVar(&values.output, "output", "", "new private output path")
}

func runPrepareTargets(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-targets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var version int64
	var expires string
	bindPublishCommon(flags, &common, true)
	flags.Int64Var(&version, "version", 0, "positive targets metadata version")
	flags.StringVar(&expires, "expires", "", "targets expiry as exact UTC RFC3339")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || version == 0 || expires == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	prepared, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: root, Target: target, RootDigest: common.rootDigest, Version: version, Expires: expires})
	if err != nil || knowledgepublish.WritePreparation(common.output, prepared) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runPrepareSnapshot(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-snapshot", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var targets, expires string
	var version int64
	bindPublishCommon(flags, &common, true)
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.Int64Var(&version, "version", 0, "positive snapshot metadata version")
	flags.StringVar(&expires, "expires", "", "snapshot expiry as exact UTC RFC3339")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || targets == "" || version == 0 || expires == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	targetsRaw, err := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	if err != nil {
		return knowledgePublishError()
	}
	prepared, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: root, Target: target, Targets: targetsRaw, RootDigest: common.rootDigest, Version: version, Expires: expires})
	if err != nil || knowledgepublish.WritePreparation(common.output, prepared) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runPrepareTimestamp(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-timestamp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var targets, snapshot, expires string
	var version int64
	bindPublishCommon(flags, &common, true)
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.StringVar(&snapshot, "snapshot", "", "finalized snapshot metadata")
	flags.Int64Var(&version, "version", 0, "positive timestamp metadata version")
	flags.StringVar(&expires, "expires", "", "timestamp expiry as exact UTC RFC3339")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || targets == "" || snapshot == "" || version == 0 || expires == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	targetsRaw, err1 := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	snapshotRaw, err2 := readPublishInput(snapshot, knowledgepublish.MaxRoleBytes)
	if err1 != nil || err2 != nil {
		return knowledgePublishError()
	}
	prepared, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: root, Target: target, Targets: targetsRaw, Snapshot: snapshotRaw, RootDigest: common.rootDigest, Version: version, Expires: expires})
	if err != nil || knowledgepublish.WritePreparation(common.output, prepared) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runFinalizeRole(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish finalize-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var root, rootDigest, role, unsigned, signatures, output string
	flags.StringVar(&root, "root", "", "independently supplied signed public TUF root")
	flags.StringVar(&rootDigest, "root-digest", "", "independently verified public root SHA-256")
	flags.StringVar(&role, "role", "", "targets, snapshot, or timestamp")
	flags.StringVar(&unsigned, "unsigned", "", "prepared unsigned metadata")
	flags.StringVar(&signatures, "signatures", "", "external signature envelope")
	flags.StringVar(&output, "output", "", "new finalized metadata file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || root == "" || rootDigest == "" || unsigned == "" || signatures == "" || output == "" {
		return knowledgePublishError()
	}
	rootRaw, err1 := readPublishInput(root, knowledgepublish.MaxRootBytes)
	unsignedRaw, err2 := readPublishInput(unsigned, knowledgepublish.MaxRoleBytes)
	signatureRaw, err3 := readPublishInput(signatures, knowledgepublish.MaxEnvelopeBytes)
	if err1 != nil || err2 != nil || err3 != nil {
		return knowledgePublishError()
	}
	finalized, err := knowledgepublish.FinalizeRole(rootRaw, rootDigest, role, unsignedRaw, signatureRaw)
	if err != nil || knowledgepublish.WriteExclusive(output, finalized) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runFinalizeKnowledgePackage(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("knowledge-publish finalize-package", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var targets, snapshot, timestamp string
	bindPublishCommon(flags, &common, true)
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.StringVar(&snapshot, "snapshot", "", "finalized snapshot metadata")
	flags.StringVar(&timestamp, "timestamp", "", "finalized timestamp metadata")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || targets == "" || snapshot == "" || timestamp == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	targetsRaw, err1 := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	snapshotRaw, err2 := readPublishInput(snapshot, knowledgepublish.MaxRoleBytes)
	timestampRaw, err3 := readPublishInput(timestamp, knowledgepublish.MaxRoleBytes)
	if err1 != nil || err2 != nil || err3 != nil {
		return knowledgePublishError()
	}
	packageRaw, receipt, err := knowledgepublish.FinalizePackage(knowledgepublish.FinalizePackageOptions{Root: root, Target: target, Targets: targetsRaw, Snapshot: snapshotRaw, Timestamp: timestampRaw, RootDigest: common.rootDigest})
	if err != nil || knowledgepublish.WriteExclusive(common.output, packageRaw) != nil {
		return knowledgePublishError()
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return knowledgePublishError()
	}
	if _, err := fmt.Fprintln(stdout, string(receiptRaw)); err != nil {
		return &commandError{code: 2, message: "knowledge-publish: receipt output failed"}
	}
	return nil
}

func completeCommon(values publishCommon, target bool) bool {
	return values.root != "" && values.rootDigest != "" && values.output != "" && (!target || values.target != "") && filepath.IsAbs(values.output)
}

func readRootTarget(values publishCommon) ([]byte, []byte, error) {
	root, err := readPublishInput(values.root, knowledgepublish.MaxRootBytes)
	if err != nil {
		return nil, nil, err
	}
	target, err := readPublishInput(values.target, knowledgepublish.MaxTargetBytes)
	return root, target, err
}

func readPublishInput(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, knowledgepublish.ErrRejected
	}
	return currentbundle.ReadBoundedFile(path, limit)
}

func knowledgePublishError() error {
	return &commandError{code: 2, message: "knowledge-publish: operation rejected"}
}
