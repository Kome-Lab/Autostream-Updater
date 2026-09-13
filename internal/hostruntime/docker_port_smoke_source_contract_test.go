package hostruntime

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

type dockerSmokeSourceOwner struct {
	file, function string
}

func dockerSmokeSourceOwners() []dockerSmokeSourceOwner {
	return []dockerSmokeSourceOwner{
		{"docker_port_daemon_smoke_linux_test.go", "TestDockerPortDaemonSmoke"},
		{"docker_port_daemon_fixture_linux_test.go", "runDockerPortSmokeMutation"},
		{"docker_port_daemon_legacy_diagnostics_linux_test.go", "observeDockerPortSmokeUnhealthyMutation"},
		{"docker_port_daemon_assertions_linux_test.go", "assertDockerPortSmokeRolledBack"},
	}
}

// Read only the four real owners. A declaration from another owner or a method
// cannot stand in for the expected top-level function.
func readDockerSmokeSourceFunctions(readFile func(string) ([]byte, error)) (map[string]*ast.FuncDecl, error) {
	if readFile == nil {
		return nil, fmt.Errorf("missing smoke source reader")
	}
	type declaration struct {
		file string
		fn   *ast.FuncDecl
	}
	wanted := map[string]bool{}
	for _, owner := range dockerSmokeSourceOwners() {
		wanted[owner.function] = true
	}
	found := map[string][]declaration{}
	for _, owner := range dockerSmokeSourceOwners() {
		source, err := readFile(owner.file)
		if err != nil {
			return nil, fmt.Errorf("read owner %s: %w", owner.file, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), owner.file, source, 0)
		if err != nil {
			return nil, fmt.Errorf("parse owner %s: %w", owner.file, err)
		}
		if file.Name.Name != "hostruntime" {
			return nil, fmt.Errorf("wrong package in owner %s", owner.file)
		}
		for _, node := range file.Decls {
			if fn, ok := node.(*ast.FuncDecl); ok && wanted[fn.Name.Name] {
				found[fn.Name.Name] = append(found[fn.Name.Name], declaration{owner.file, fn})
			}
		}
	}
	functions := map[string]*ast.FuncDecl{}
	for _, owner := range dockerSmokeSourceOwners() {
		declarations := found[owner.function]
		if len(declarations) == 0 {
			return nil, fmt.Errorf("missing declaration %s in %s", owner.function, owner.file)
		}
		if len(declarations) != 1 {
			return nil, fmt.Errorf("duplicate declaration %s", owner.function)
		}
		declaration := declarations[0]
		if declaration.file != owner.file {
			return nil, fmt.Errorf("wrong owner for %s", owner.function)
		}
		if declaration.fn.Recv != nil {
			return nil, fmt.Errorf("receiver on declaration %s", owner.function)
		}
		if declaration.fn.Body == nil {
			return nil, fmt.Errorf("missing body for %s", owner.function)
		}
		functions[owner.function] = declaration.fn
	}
	return functions, nil
}

func dockerSmokeSourceCalls(body *ast.BlockStmt, target string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if name == target {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

func dockerSmokeSourceIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func dockerSmokeSourceString(expr ast.Expr, value string) bool {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	text, err := strconv.Unquote(literal.Value)
	return err == nil && text == value
}

func dockerSmokeSourceNames(expressions []ast.Expr, names ...string) bool {
	if len(expressions) != len(names) {
		return false
	}
	for index, name := range names {
		if !dockerSmokeSourceIdent(expressions[index], name) {
			return false
		}
	}
	return true
}

func checkDockerSmokeDiagnosticCallerSources(readFile func(string) ([]byte, error)) error {
	functions, err := readDockerSmokeSourceFunctions(readFile)
	if err != nil {
		return err
	}
	type requirement struct{ function, target string }
	requirements := []requirement{
		{"TestDockerPortDaemonSmoke", "observeDockerPortSmokeUnhealthyMutation"},
		{"TestDockerPortDaemonSmoke", "assertDockerPortSmokeRolledBack"},
		{"runDockerPortSmokeMutation", "handleLocalExecutorMutation"},
		{"runDockerPortSmokeMutation", "withFailureObserver"},
		{"runDockerPortSmokeMutation", "wrapCrashPoint"},
		{"observeDockerPortSmokeUnhealthyMutation", "mutate"},
		{"observeDockerPortSmokeUnhealthyMutation", "logReturn"},
		{"assertDockerPortSmokeRolledBack", "dockerPortSmokeRollbackSummary"},
		{"assertDockerPortSmokeRolledBack", "Fatalf"},
	}
	calls := map[requirement]*ast.CallExpr{}
	for _, required := range requirements {
		fn := functions[required.function]
		if fn == nil || fn.Body == nil {
			return fmt.Errorf("missing validated function body %s", required.function)
		}
		matches := dockerSmokeSourceCalls(fn.Body, required.target)
		if len(matches) != 1 {
			return fmt.Errorf("call count %s/%s: got %d, want 1", required.function, required.target, len(matches))
		}
		calls[required] = matches[0]
	}
	observed := calls[requirements[0]]
	assertion := calls[requirements[1]]
	// Each order comparison is confined to one FuncDecl.Body in one real file.
	if observed.Pos() >= assertion.Pos() {
		return fmt.Errorf("unhealthy observation must precede rollback assertion")
	}
	if calls[requirements[5]].Pos() >= calls[requirements[6]].Pos() {
		return fmt.Errorf("mutate must precede logReturn")
	}
	if err := checkDockerSmokeUnhealthySource(functions["TestDockerPortDaemonSmoke"], observed, assertion); err != nil {
		return err
	}
	return checkDockerSmokeGrantSource(functions["TestDockerPortDaemonSmoke"])
}

func checkDockerSmokeUnhealthySource(fn *ast.FuncDecl, observed, assertion *ast.CallExpr) error {
	if len(observed.Args) != 4 || !dockerSmokeSourceNames(observed.Args[:3], "t", "runner", "unhealthyPlan") {
		return fmt.Errorf("unhealthy observer arguments changed")
	}
	callback, ok := observed.Args[3].(*ast.FuncLit)
	if !ok || callback.Body == nil || len(callback.Body.List) != 1 {
		return fmt.Errorf("unhealthy return connection missing")
	}
	returned, ok := callback.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return fmt.Errorf("unhealthy return connection missing")
	}
	mutation, ok := returned.Results[0].(*ast.CallExpr)
	if !ok || !dockerSmokeSourceIdent(mutation.Fun, "runDockerPortSmokeMutation") {
		return fmt.Errorf("unhealthy return connection missing")
	}
	if mutation.Ellipsis.IsValid() || len(mutation.Args) != 7 ||
		!dockerSmokeSourceNames(mutation.Args[:4], "t", "runner", "stateDir", "unhealthyPlan") ||
		!dockerSmokeSourceString(mutation.Args[4], "port_reconfigure") ||
		!dockerSmokeSourceNames(mutation.Args[5:], "nil", "scope") {
		return fmt.Errorf("unhealthy request arguments changed")
	}
	parameters := callback.Type.Params.List
	if len(parameters) != 1 || len(parameters[0].Names) != 1 || parameters[0].Names[0].Name != "scope" {
		return fmt.Errorf("unhealthy scope parameter changed")
	}
	connected := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if ok && len(assignment.Rhs) == 1 && assignment.Rhs[0] == observed &&
			dockerSmokeSourceNames(assignment.Lhs, "rollbackResponse", "rollbackGrants") {
			connected++
		}
		return true
	})
	if connected != 1 || !dockerSmokeSourceNames(assertion.Args, "t", "rollbackResponse", "unhealthyPlan") {
		return fmt.Errorf("unhealthy result connection changed")
	}
	return nil
}

func checkDockerSmokeGrantSource(fn *ast.FuncDecl) error {
	var guards []*ast.IfStmt
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		guard, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		condition, ok := guard.Cond.(*ast.BinaryExpr)
		if !ok || condition.Op != token.NEQ || !dockerSmokeSourceIdent(condition.X, "rollbackGrants") {
			return true
		}
		value, ok := condition.Y.(*ast.BasicLit)
		if ok && value.Kind == token.INT && value.Value == "1" {
			guards = append(guards, guard)
		}
		return true
	})
	if len(guards) != 1 {
		return fmt.Errorf("rollback grant condition missing or duplicated")
	}
	guard := guards[0]
	if guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
		return fmt.Errorf("rollback grant fatal boundary changed")
	}
	statement, ok := guard.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("rollback grant fatal boundary changed")
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return fmt.Errorf("rollback grant fatal boundary changed")
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !dockerSmokeSourceIdent(selector.X, "t") || selector.Sel.Name != "Fatalf" ||
		!dockerSmokeSourceString(call.Args[0], "rollback mutation grant calls=%d") ||
		!dockerSmokeSourceIdent(call.Args[1], "rollbackGrants") {
		return fmt.Errorf("rollback grant fatal boundary changed")
	}
	return nil
}

// This checks the real Linux parent's error-checked call, so a correct but
// unused portable helper does not satisfy the source regression.
func checkDockerSmokeLinuxParentSource(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "docker_port_smoke_diagnostics_linux_test.go", source, 0)
	if err != nil {
		return fmt.Errorf("parse Linux parent: %w", err)
	}
	var parents []*ast.FuncDecl
	for _, node := range file.Decls {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == "TestDockerSmokeDiagnosticLegacyCallerConnection" {
			parents = append(parents, fn)
		}
	}
	if file.Name.Name != "hostruntime" || len(parents) != 1 || parents[0].Recv != nil ||
		parents[0].Body == nil || len(parents[0].Body.List) != 1 {
		return fmt.Errorf("Linux parent body must directly check the real source helper")
	}
	guard, ok := parents[0].Body.List[0].(*ast.IfStmt)
	if !ok {
		return fmt.Errorf("Linux parent helper connection missing")
	}
	assignment, ok := guard.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || !dockerSmokeSourceNames(assignment.Lhs, "err") || len(assignment.Rhs) != 1 {
		return fmt.Errorf("Linux parent helper connection missing")
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || !dockerSmokeSourceIdent(call.Fun, "checkDockerSmokeDiagnosticCallerSources") || len(call.Args) != 1 {
		return fmt.Errorf("Linux parent helper connection missing")
	}
	reader, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || !dockerSmokeSourceIdent(reader.X, "os") || reader.Sel.Name != "ReadFile" {
		return fmt.Errorf("Linux parent actual file reader missing")
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ || !dockerSmokeSourceIdent(condition.X, "err") ||
		!dockerSmokeSourceIdent(condition.Y, "nil") || guard.Else != nil || len(guard.Body.List) != 1 {
		return fmt.Errorf("Linux parent error boundary missing")
	}
	statement, ok := guard.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("Linux parent error boundary missing")
	}
	fatal, ok := statement.X.(*ast.CallExpr)
	if !ok || !dockerSmokeSourceNames(fatal.Args, "err") {
		return fmt.Errorf("Linux parent error boundary missing")
	}
	selector, ok := fatal.Fun.(*ast.SelectorExpr)
	if !ok || !dockerSmokeSourceIdent(selector.X, "t") || selector.Sel.Name != "Fatal" {
		return fmt.Errorf("Linux parent error boundary missing")
	}
	return nil
}

func dockerSmokeActualSources(t *testing.T) map[string][]byte {
	t.Helper()
	sources := map[string][]byte{}
	for _, owner := range dockerSmokeSourceOwners() {
		source, err := os.ReadFile(owner.file)
		if err != nil {
			t.Fatalf("read real owner %s: %v", owner.file, err)
		}
		sources[owner.file] = source
	}
	return sources
}

func dockerSmokeCopiedSources(sources map[string][]byte) map[string][]byte {
	copy := map[string][]byte{}
	for name, source := range sources {
		copy[name] = bytes.Clone(source)
	}
	return copy
}

func dockerSmokeMapReader(sources map[string][]byte) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		data, ok := sources[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return data, nil
	}
}

func dockerSmokeRequireSourceError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("source rejection = %v, want reason %q", err, want)
	}
}

func dockerSmokeMutationFunction(t *testing.T, source []byte, name string) (*token.FileSet, *ast.FuncDecl) {
	t.Helper()
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "actual.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var functions []*ast.FuncDecl
	for _, node := range file.Decls {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == name {
			functions = append(functions, fn)
		}
	}
	if len(functions) != 1 || functions[0].Body == nil {
		t.Fatalf("mutation requires one real body for %s", name)
	}
	return set, functions[0]
}

func dockerSmokeReplaceSpan(source []byte, start, end int, replacement string) []byte {
	result := append([]byte{}, source[:start]...)
	result = append(result, replacement...)
	return append(result, source[end:]...)
}

func dockerSmokeReplaceOnce(t *testing.T, source []byte, old, replacement string) []byte {
	t.Helper()
	if bytes.Count(source, []byte(old)) != 1 {
		t.Fatalf("mutation anchor must occur once: %q", old)
	}
	return bytes.Replace(source, []byte(old), []byte(replacement), 1)
}

func TestDockerSmokeSourceContract(t *testing.T) {
	actual := dockerSmokeActualSources(t)
	t.Run("actual_four_owners", func(t *testing.T) {
		reads := map[string]int{}
		err := checkDockerSmokeDiagnosticCallerSources(func(name string) ([]byte, error) {
			reads[name]++
			return os.ReadFile(name)
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"docker_port_daemon_smoke_linux_test.go", "docker_port_daemon_fixture_linux_test.go", "docker_port_daemon_legacy_diagnostics_linux_test.go", "docker_port_daemon_assertions_linux_test.go"} {
			if reads[name] != 1 {
				t.Fatalf("owner %s reads=%d, want 1", name, reads[name])
			}
		}
		if len(reads) != 4 {
			t.Fatal("source reader escaped the four-owner allowlist")
		}
	})
	for _, owner := range dockerSmokeSourceOwners() {
		for _, fault := range []string{"missing_file", "missing_declaration", "duplicate", "receiver", "syntax", "package", "body"} {
			t.Run(fault+"/"+owner.function, func(t *testing.T) {
				sources := dockerSmokeCopiedSources(actual)
				source := sources[owner.file]
				set, fn := dockerSmokeMutationFunction(t, source, owner.function)
				file := set.File(fn.Pos())
				start, end := file.Offset(fn.Pos()), file.Offset(fn.End())
				want := ""
				switch fault {
				case "missing_file":
					delete(sources, owner.file)
					want = "read owner " + owner.file
				case "missing_declaration":
					sources[owner.file] = dockerSmokeReplaceSpan(source, start, end, "")
					want = "missing declaration " + owner.function
				case "duplicate":
					sources[owner.file] = append(source, append([]byte("\n"), source[start:end]...)...)
					want = "duplicate declaration " + owner.function
				case "receiver":
					sources[owner.file] = dockerSmokeReplaceSpan(source, start, start+len("func"), "func (unrelated *OtherReceiver)")
					want = "receiver on declaration " + owner.function
				case "syntax":
					sources[owner.file] = append(source, []byte("\nfunc broken(\n")...)
					want = "parse owner " + owner.file
				case "package":
					sources[owner.file] = dockerSmokeReplaceOnce(t, source, "package hostruntime", "package unrelated")
					want = "wrong package in owner " + owner.file
				case "body":
					sources[owner.file] = dockerSmokeReplaceSpan(source, file.Offset(fn.Body.Pos()), end, "")
					want = "missing body for " + owner.function
				}
				dockerSmokeRequireSourceError(t, checkDockerSmokeDiagnosticCallerSources(dockerSmokeMapReader(sources)), want)
			})
		}
	}
	t.Run("wrong_owner", func(t *testing.T) {
		sources := dockerSmokeCopiedSources(actual)
		owner := dockerSmokeSourceOwners()[1]
		set, fn := dockerSmokeMutationFunction(t, sources[owner.file], owner.function)
		file := set.File(fn.Pos())
		start, end := file.Offset(fn.Pos()), file.Offset(fn.End())
		declaration := bytes.Clone(sources[owner.file][start:end])
		sources[owner.file] = dockerSmokeReplaceSpan(sources[owner.file], start, end, "")
		other := dockerSmokeSourceOwners()[0].file
		sources[other] = append(sources[other], append([]byte("\n"), declaration...)...)
		dockerSmokeRequireSourceError(t, checkDockerSmokeDiagnosticCallerSources(dockerSmokeMapReader(sources)), "wrong owner for "+owner.function)
	})
	for _, required := range []struct{ owner, target string }{
		{"TestDockerPortDaemonSmoke", "observeDockerPortSmokeUnhealthyMutation"},
		{"TestDockerPortDaemonSmoke", "assertDockerPortSmokeRolledBack"},
		{"runDockerPortSmokeMutation", "handleLocalExecutorMutation"},
		{"runDockerPortSmokeMutation", "withFailureObserver"},
		{"runDockerPortSmokeMutation", "wrapCrashPoint"},
		{"observeDockerPortSmokeUnhealthyMutation", "mutate"},
		{"observeDockerPortSmokeUnhealthyMutation", "logReturn"},
		{"assertDockerPortSmokeRolledBack", "dockerPortSmokeRollbackSummary"},
		{"assertDockerPortSmokeRolledBack", "Fatalf"},
	} {
		for _, mutation := range []string{"remove_call", "duplicate_call", "unrelated_function", "comment", "string"} {
			t.Run(mutation+"/"+required.target, func(t *testing.T) {
				sources := dockerSmokeCopiedSources(actual)
				for _, owner := range dockerSmokeSourceOwners() {
					if owner.function != required.owner {
						continue
					}
					source := sources[owner.file]
					set, fn := dockerSmokeMutationFunction(t, source, required.owner)
					matches := dockerSmokeSourceCalls(fn.Body, required.target)
					if len(matches) != 1 {
						t.Fatalf("real mutation target %s count=%d", required.target, len(matches))
					}
					file := set.File(fn.Pos())
					if mutation == "duplicate_call" {
						sources[owner.file] = dockerSmokeReplaceSpan(source, file.Offset(fn.Body.Rbrace), file.Offset(fn.Body.Rbrace), required.target+"()\n")
					} else {
						// Disconnect only this callee; keep nested calls such as the
						// rollback summary intact so the rejection has one cause.
						sources[owner.file] = dockerSmokeReplaceSpan(source, file.Offset(matches[0].Fun.Pos()), file.Offset(matches[0].Fun.End()), "disconnectedSourceCall")
						switch mutation {
						case "unrelated_function":
							sources[owner.file] = append(sources[owner.file], []byte("\nfunc unrelatedSourceDecoy() { "+required.target+"() }\n")...)
						case "comment":
							sources[owner.file] = append(sources[owner.file], []byte("\n// "+required.target+"()\n")...)
						case "string":
							sources[owner.file] = append(sources[owner.file], []byte("\nvar sourceDecoy = "+strconv.Quote(required.target+"()")+"\n")...)
						}
					}
				}
				want := "call count " + required.owner + "/" + required.target + ": got 0, want 1"
				if mutation == "duplicate_call" {
					want = "call count " + required.owner + "/" + required.target + ": got 2, want 1"
				}
				dockerSmokeRequireSourceError(t, checkDockerSmokeDiagnosticCallerSources(dockerSmokeMapReader(sources)), want)
			})
		}
	}
	for _, order := range []struct{ owner, first, last, reason string }{
		{"TestDockerPortDaemonSmoke", "observeDockerPortSmokeUnhealthyMutation", "assertDockerPortSmokeRolledBack", "unhealthy observation must precede rollback assertion"},
		{"observeDockerPortSmokeUnhealthyMutation", "mutate", "logReturn", "mutate must precede logReturn"},
	} {
		t.Run("reverse_order/"+order.owner, func(t *testing.T) {
			sources := dockerSmokeCopiedSources(actual)
			for _, owner := range dockerSmokeSourceOwners() {
				if owner.function != order.owner {
					continue
				}
				source := sources[owner.file]
				set, fn := dockerSmokeMutationFunction(t, source, order.owner)
				first, last := dockerSmokeSourceCalls(fn.Body, order.first), dockerSmokeSourceCalls(fn.Body, order.last)
				if len(first) != 1 || len(last) != 1 || first[0].Pos() >= last[0].Pos() {
					t.Fatal("real source does not provide the ordered mutation pair")
				}
				file := set.File(fn.Pos())
				a, b, c, d := file.Offset(first[0].Pos()), file.Offset(first[0].End()), file.Offset(last[0].Pos()), file.Offset(last[0].End())
				swapped := dockerSmokeReplaceSpan(source, c, d, string(source[a:b]))
				sources[owner.file] = dockerSmokeReplaceSpan(swapped, a, b, string(source[c:d]))
			}
			dockerSmokeRequireSourceError(t, checkDockerSmokeDiagnosticCallerSources(dockerSmokeMapReader(sources)), order.reason)
		})
	}
	request := `return runDockerPortSmokeMutation(t, runner, stateDir, unhealthyPlan, "port_reconfigure", nil, scope)`
	for _, argument := range []struct{ old, replacement string }{
		{"(t,", "(otherT,"}, {", runner,", ", otherRunner,"}, {", stateDir,", ", otherDir,"},
		{", unhealthyPlan,", ", otherPlan,"}, {`"port_reconfigure"`, `"apply"`}, {", nil,", ", otherHook,"}, {", scope)", ", otherScope)"},
	} {
		t.Run("unhealthy_argument/"+argument.replacement, func(t *testing.T) {
			sources := dockerSmokeCopiedSources(actual)
			file := dockerSmokeSourceOwners()[0].file
			changed := strings.Replace(request, argument.old, argument.replacement, 1)
			sources[file] = dockerSmokeReplaceOnce(t, sources[file], request, changed)
			dockerSmokeRequireSourceError(t, checkDockerSmokeDiagnosticCallerSources(dockerSmokeMapReader(sources)), "unhealthy request arguments changed")
		})
	}
	for _, boundary := range []struct{ name, old, replacement, reason string }{
		{"return", request, strings.TrimPrefix(request, "return "), "unhealthy return connection missing"},
		{"result", "rollbackResponse, rollbackGrants :=", "rollbackResponse, unrelatedGrants :=", "unhealthy result connection changed"},
		{"grant_number", "if rollbackGrants != 1 {", "if rollbackGrants != 2 {", "rollback grant condition missing"},
		{"grant_condition", "if rollbackGrants != 1 {", "if unrelatedGrants != 1 {", "rollback grant condition missing"},
		{"grant_fatal_removed", `t.Fatalf("rollback mutation grant calls=%d", rollbackGrants)`, "_ = rollbackGrants", "rollback grant fatal boundary changed"},
		{"grant_fatal_weakened", `t.Fatalf("rollback mutation grant calls=%d", rollbackGrants)`, `t.Logf("rollback mutation grant calls=%d", rollbackGrants)`, "rollback grant fatal boundary changed"},
		{"grant_format", `"rollback mutation grant calls=%d"`, `"different grant diagnostic"`, "rollback grant fatal boundary changed"},
	} {
		t.Run("boundary/"+boundary.name, func(t *testing.T) {
			sources := dockerSmokeCopiedSources(actual)
			file := dockerSmokeSourceOwners()[0].file
			sources[file] = dockerSmokeReplaceOnce(t, sources[file], boundary.old, boundary.replacement)
			dockerSmokeRequireSourceError(t, checkDockerSmokeDiagnosticCallerSources(dockerSmokeMapReader(sources)), boundary.reason)
		})
	}
}

func TestDockerSmokeSourceContractLinuxParentConnection(t *testing.T) {
	source, err := os.ReadFile("docker_port_smoke_diagnostics_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDockerSmokeLinuxParentSource(source); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, old, replacement, reason string }{
		{"unused_helper", "checkDockerSmokeDiagnosticCallerSources(os.ReadFile)", "unrelatedSourceHelper(os.ReadFile)", "Linux parent helper connection missing"},
		{"fake_reader", "checkDockerSmokeDiagnosticCallerSources(os.ReadFile)", "checkDockerSmokeDiagnosticCallerSources(fake.ReadFile)", "Linux parent actual file reader missing"},
		{"ignored_error", "err != nil {\n\t\tt.Fatal(err)", "err == nil {\n\t\tt.Fatal(err)", "Linux parent error boundary missing"},
		{"fatal_removed", "err != nil {\n\t\tt.Fatal(err)", "err != nil {\n\t\t_ = err", "Linux parent error boundary missing"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			set, parent := dockerSmokeMutationFunction(t, source, "TestDockerSmokeDiagnosticLegacyCallerConnection")
			file := set.File(parent.Pos())
			start, end := file.Offset(parent.Pos()), file.Offset(parent.End())
			body := dockerSmokeReplaceOnce(t, source[start:end], mutation.old, mutation.replacement)
			changed := dockerSmokeReplaceSpan(source, start, end, string(body))
			dockerSmokeRequireSourceError(t, checkDockerSmokeLinuxParentSource(changed), mutation.reason)
		})
	}
}
