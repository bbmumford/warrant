package warrant

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// warrantModuleDir is this module's own root (the dir holding go.mod), used to point a
// generated throwaway adversary module at the real warrant via a local replace. The proofs
// below need an EXTERNAL module to demonstrate the boundary a real consumer hits; rather
// than keep a committed sibling module around, they generate that module at test time.
func warrantModuleDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Dir(thisFile)
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestInternalMintNotImportableFromSiblingPath proves DEFENSE-IN-DEPTH ONLY, not the
// security guarantee: a NON-NESTED external module (module path "forgetest", not under
// github.com/bbmumford/warrant/) cannot import internal/mint and fails to build. This does
// NOT establish unforgeability — a NESTED-path module can import it (see the next test). The
// real guarantee is the receiver-pinned seal, which denies the nested forger regardless.
func TestInternalMintNotImportableFromSiblingPath(t *testing.T) {
	warrantAbs := warrantModuleDir(t)
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module forgetest\n\ngo 1.25.0\n\nrequire github.com/bbmumford/warrant v0.0.0\n\nreplace github.com/bbmumford/warrant => "+warrantAbs+"\n")
	writeFile(t, dir, "forge.go", "package forgetest\n\nimport _ \"github.com/bbmumford/warrant/internal/mint\"\n")
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a non-nested external module importing internal/mint must FAIL to build; output:\n%s", out)
	}
	if !strings.Contains(string(out), "use of internal package") {
		t.Fatalf("expected 'use of internal package' error; got:\n%s", out)
	}
}

// nestedForgerMain is a program for a module whose path IS nested under the warrant module
// (github.com/bbmumford/warrant/forger), so it can legally import internal/mint. It mints a
// forged principal with its OWN Verifier and presents it to the REAL host Authorizer.
const nestedForgerMain = `package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbmumford/warrant"
	"github.com/bbmumford/warrant/internal/mint"
)

func main() {
	// A nested-path module CAN import internal/mint (Go internal is import-path ancestry).
	forger, _ := mint.NewVerifier()
	real, _ := warrant.NewVerifier()

	home := warrant.RealmTrust{Realm: "orbtr.io", Issuer: "io-edge", Audience: "node.orbtr.io", PolicyVersion: "v1", ExpiresAtMS: 1 << 62}
	reqCap, _ := warrant.ParseCapability("orbtr.io:device.read")
	route, _ := warrant.PartitionBoundRoute("device.read", reqCap)
	clock := func() int64 { return 5000 }

	realAz, _ := warrant.NewAuthorizer(real, "orbtr", clock, []warrant.Route{route}, home)
	forgerAz, _ := warrant.NewAuthorizer(forger, "orbtr", clock, []warrant.Route{route}, home)

	// A perfect assertion — only the secret is the forger's own.
	as := mint.Assertion{
		Subject:        mint.Subject{ID: "u1", Kind: "user"},
		Deployment: "orbtr",
		HasPartition:       true,
		Partition:          "acme",
		Capabilities:   []string{"orbtr.io:device.read"},
		Issuer:         "io-edge",
		Audience:       "node.orbtr.io",
		Version:        "v1",
		Realm:          "orbtr.io",
		ExpiresAtMS:    10000,
		Nonce:          "nonce-nested-01",
	}
	forged, _ := forger.Mint(as)

	_, errReal := realAz.Authorize(context.Background(), forged, "device.read", "acme")
	_, errForger := forgerAz.Authorize(context.Background(), forged, "device.read", "acme")

	// The nested-path forger CAN mint (this built + ran), its own authorizer ACCEPTS the
	// principal (so the assertion is otherwise perfectly valid), yet the REAL host authorizer
	// DENIES it — purely on the seal mismatch.
	if errors.Is(errReal, warrant.ErrDenied) && errForger == nil {
		fmt.Println("NESTED_FORGERY_DENIED_BY_REAL_AUTHORIZER")
	} else {
		fmt.Printf("UNEXPECTED real=%v forger=%v\n", errReal, errForger)
	}
}
`

// TestNestedModule_ForgedPrincipal_DeniedByRealAuthorizer is the durable R-2411 pin-5 proof:
// it builds a real nested-path module that imports internal/mint, mints a forged principal,
// and asserts the REAL host Authorizer denies it. The adversary module is generated at test
// time, so no separate committed module is needed.
func TestNestedModule_ForgedPrincipal_DeniedByRealAuthorizer(t *testing.T) {
	warrantAbs := warrantModuleDir(t)
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module github.com/bbmumford/warrant/forger\n\ngo 1.25.0\n\nrequire github.com/bbmumford/warrant v0.0.0\n\nreplace github.com/bbmumford/warrant => "+warrantAbs+"\n")
	writeFile(t, dir, "main.go", nestedForgerMain)
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nested forger program failed to build/run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "NESTED_FORGERY_DENIED_BY_REAL_AUTHORIZER") {
		t.Fatalf("the real Authorizer must DENY a nested-module forged principal; got:\n%s", out)
	}
}
