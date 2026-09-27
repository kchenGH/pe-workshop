# Licensing scope and external components

The root [MIT license](LICENSE) covers PE Workshop's project-owned source code, documentation, build and verification scripts, and the four native teaching executables in `Samples`. No third-party source packages are vendored in this repository.

The editor uses .NET and Windows Presentation Foundation (WPF). These are external runtime dependencies. Their upstream projects use the MIT license and carry their own copyright and third-party notices:

- [.NET runtime license](https://github.com/dotnet/runtime/blob/main/LICENSE.TXT) and [third-party notices](https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT).
- [WPF license](https://github.com/dotnet/wpf/blob/main/LICENSE.TXT) and [third-party notices](https://github.com/dotnet/wpf/blob/main/THIRD-PARTY-NOTICES.TXT).

Runtime assemblies, Windows system DLLs, Windows SDK libraries and compiler binaries are not checked into this repository. The native samples dynamically import functions from the user's installed Windows system DLLs. LLVM and the Windows SDK are external build tools with their own license terms; this project's license does not replace those terms.

If distributing a self-contained editor build, retain the applicable copyright, license and third-party notices supplied with the included runtime and other dependencies. The project's MIT license alone does not relicense external components.
