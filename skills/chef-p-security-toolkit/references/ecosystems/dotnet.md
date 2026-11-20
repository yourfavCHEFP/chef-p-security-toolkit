# .NET (C#/F#)
Manifests: `*.csproj`, `packages.lock.json`. Tests: `dotnet test`. Audit: `dotnet list package --vulnerable --include-transitive`, osv-scanner, trivy.
Upgrade: `dotnet add package NAME --version X`; enable lockfiles with `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`.
Watch for `BinaryFormatter`, string-built SQL (`SqlCommand` concatenation), and disabled cert validation.
