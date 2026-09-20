package communityapp

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/prufyx/prufyx-cli/internal/onecommand"
)

// assess is the one-command fast path (roadmap Workstream 2): it collects a
// current bundle from a local kubeconfig the operator already trusts and
// classifies every registered native check route's applicability against
// it. It never mutates cluster state, never reads more than the collector
// already reads, and never runs a check on the operator's behalf: it is a
// triage layer in front of the existing `check cncf` / `check project`
// routes, not a replacement for them. See cli/docs/one-command-flow.md.
func (r runtime) assess(ctx context.Context, args []string) int {
	if hasHelp(args) {
		r.assessUsage(r.stdout)
		return ExitOK
	}
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kubeconfig := fs.String("kubeconfig", "", "explicit private kubeconfig")
	ack := fs.Bool("acknowledge-kubeconfig-exec-risk", false, "acknowledge kubeconfig authentication helpers")
	profile := fs.String("component-configuration-profile", "v2", "v2 or v3")
	allowPartial := fs.Bool("allow-partial", false, "classify checks even when collection is partial")
	kubectl := fs.String("kubectl", "", "kubectl executable (default PATH lookup)")
	output := fs.String("output", "", "private working directory for the collected bundle (default: a fresh temporary directory)")
	format := fs.String("format", "human", "human or json")
	var execEnv stringsFlag
	fs.Var(&execEnv, "exec-env", "forward one named ambient variable; repeatable")
	if duplicateFlags(args) || fs.Parse(args) != nil {
		return r.usage("invalid assess arguments; use --help")
	}
	contexts := fs.Args()
	if *kubeconfig == "" || !*ack || len(contexts) == 0 || (*format != "human" && *format != "json") {
		return r.usage("invalid assess arguments; use --help")
	}

	opts := onecommand.Options{
		OutputRoot:                    *output,
		Kubeconfig:                    *kubeconfig,
		Contexts:                      contexts,
		AcknowledgeExecRisk:           *ack,
		AllowPartial:                  *allowPartial,
		ExecEnv:                       execEnv,
		Kubectl:                       *kubectl,
		ComponentConfigurationProfile: *profile,
	}
	report, code := onecommand.Run(ctx, opts, r.stdout, r.stderr)
	if code != onecommand.ExitOK {
		return code
	}
	if *format == "json" {
		raw, err := onecommand.MarshalReport(report)
		if err != nil {
			return r.fail("report encoding failed", ExitIntegrity)
		}
		fmt.Fprintln(r.stdout, string(raw))
		return ExitOK
	}
	writeAssessHuman(r.stdout, report)
	return ExitOK
}

type stringsFlag []string

func (s *stringsFlag) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func writeAssessHuman(w io.Writer, report onecommand.Report) {
	fmt.Fprintf(w, "prufyx assess: %d registered native check routes evaluated against the collected bundle.\n", report.RouteCatalog.TotalNativeRoutes)
	fmt.Fprintf(w, "aggregate (whole-upgrade): %s (%s)\n  %s\n", report.Aggregate.Assessment, report.Aggregate.ReasonCode, report.Aggregate.Note)
	for _, c := range report.Contexts {
		fmt.Fprintf(w, "\ncontext %s (%s)\n", c.ContextHash, c.CollectionStatus)
		s := c.Summary
		fmt.Fprintf(w, "  fully satisfiable (not yet auto-run):  %d\n", s.ApplicableFullySatisfied)
		fmt.Fprintf(w, "  applicable, needs your declarations:   %d\n", s.ApplicableNeedsDeclaration)
		fmt.Fprintf(w, "  not applicable (version mismatch):     %d\n", s.NotApplicableVersionMismatch)
		fmt.Fprintf(w, "  not applicable (component absent):     %d\n", s.NotApplicableComponentAbsent)
		fmt.Fprintf(w, "  indeterminate (not observable):        %d\n", s.IndeterminateNotObservable)
		fmt.Fprintf(w, "  indeterminate (partial collection):    %d\n", s.IndeterminatePartialCollection)

		actionable := make([]onecommand.CheckAssessment, 0)
		for _, check := range c.Checks {
			if check.Applicability == onecommand.ApplicableNeedsDeclaration || check.Applicability == onecommand.ApplicableFullySatisfied {
				actionable = append(actionable, check)
			}
		}
		if len(actionable) == 0 {
			continue
		}
		sort.Slice(actionable, func(i, j int) bool {
			if actionable[i].Project != actionable[j].Project {
				return actionable[i].Project < actionable[j].Project
			}
			return actionable[i].RuleID < actionable[j].RuleID
		})
		fmt.Fprintln(w, "\n  applicable checks:")
		for _, check := range actionable {
			fmt.Fprintf(w, "  - %s %s -> %s  (%s)  [%s]\n", check.Project, check.From, check.To, check.RuleID, check.Applicability)
			if len(check.MissingDeclarations) > 0 {
				flags := make([]string, 0, len(check.MissingDeclarations))
				for _, d := range check.MissingDeclarations {
					flags = append(flags, d.Flag)
				}
				fmt.Fprintf(w, "      missing declarations: %s\n", strings.Join(flags, ", "))
			}
			if len(check.Command) > 0 {
				fmt.Fprintf(w, "      command: %s\n", strings.Join(check.Command, " "))
			}
		}
	}
}

func (r runtime) assessUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: prufyx assess --kubeconfig FILE --acknowledge-kubeconfig-exec-risk [OPTIONS] CONTEXT...

Collects a current bundle from a local kubeconfig the operator already
trusts and classifies every registered native check route's applicability
against it: which are applicable and only need operator-declared input,
which do not apply, and which cannot be determined at all from what the
collector observes. It never mutates cluster state, never runs a check on
the operator's behalf, and never invents a declaration. See
cli/docs/one-command-flow.md for the full design and its limits.

Options:
  --component-configuration-profile v2|v3   default v2
  --allow-partial                           classify anyway when collection is partial (absence conclusions are downgraded to indeterminate)
  --kubectl PATH                            kubectl executable (default PATH lookup)
  --output DIR                              private working directory for the collected bundle (default: a fresh temporary directory)
  --exec-env NAME                           forward one named ambient variable to kubectl; repeatable
  --format human|json                       default human`)
}
