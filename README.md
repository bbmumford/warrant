# warrant

The authority core. Inside the process that serves a request, it decides whether an already-authenticated caller may run one named operation, and it makes that decision impossible to bypass from caller-supplied data.

- A trusted host builds one `Verifier`. Its authentication edge seals (HMAC) each caller's identity, partition and held capabilities into a `VerifiedPrincipal` (`Verifier.Mint`).
- One `Authorizer` checks, for each call: the seal, the deployment, an immutable route table keyed by operation id, the realm's trust entry, expiry, the partition binding, capability coverage (a negative capability always wins), and a once-only nonce. A refusal is `ErrDenied` (or a `DeniedError` naming the route's required capability), and nothing a caller sends can change the route table.
- The capability grammar every judge shares: `realm:resource.action`, optionally with one `(parameter)`, and `-realm:resource.action` for a negative capability (`ParseCapability`, `CapabilitySet`, `ParseHeldSet`, `ParseGrantSet`), plus a bridge from older dotted scope strings (`ScopeConversion`).

## Use

```sh
go get github.com/bbmumford/warrant
```

```go
v, err := warrant.NewVerifier()

need, err := warrant.ParseCapability("orbtr:files.read")
route, err := warrant.PartitionBoundRoute("files.read", need)
az, err := warrant.NewAuthorizer(v, "prod", nil, []warrant.Route{route}, homeRealmTrust)

// at the authentication edge, after the credential is proved:
p, err := v.Mint(warrant.Assertion{ /* subject, deployment, partition, capabilities, realm, expiry, nonce ... */ })
ctx = warrant.WithPrincipal(ctx, p)

// in the handler:
id, err := warrant.AuthorizeFromContext(ctx, az, "files.read", bodyPartition)
```

`GlobalRoute` declares an operation that is not bound to a partition. A nil clock uses wall time.

## Consumers

ai cortex and the api.orbtr.ai endpoint, ORBTR library, io constellation and the app.orbtr.io endpoint, and the shuttle package.
