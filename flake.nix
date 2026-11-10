{
  description = "Kubera: template driven secret detection, verification, analysis and rotation";

  # Builds kubera from source with nixpkgs' Rust toolchain:
  #   nix run github:dmdhrumilmistry/kubera -- --version
  #   nix profile install github:dmdhrumilmistry/kubera
  #   nix develop            # cargo, clippy, rustfmt, mdbook, git
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # nixpkgs dropped x86_64-darwin in 26.11; Intel Macs can use
      # Homebrew or install.sh.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      manifest = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          lib = pkgs.lib;
          kubera = pkgs.rustPlatform.buildRustPackage {
            pname = "kubera";
            inherit (manifest) version;

            # Only what the build and the tests read.
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./build.rs
                ./src
                ./templates
                ./tests
                ./README.md
                ./LICENSE
              ];
            };
            cargoLock.lockFile = ./Cargo.lock;

            # rustls' crypto provider (aws-lc-rs) links nixpkgs' AWS-LC
            # instead of compiling a vendored copy.
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.aws-lc ];

            # Integration tests create throwaway git repositories and talk
            # only to local mock servers, so they run in the sandbox.
            # The sandbox has no system trust store, which the HTTP client
            # loads even when tests only talk plain http to localhost.
            nativeCheckInputs = [
              pkgs.git
              pkgs.cacert
            ];
            preCheck = ''
              export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
              export HOME=$TMPDIR
            '';

            meta = {
              description = manifest.description;
              homepage = manifest.homepage;
              changelog = "https://github.com/dmdhrumilmistry/kubera/releases/tag/v${manifest.version}";
              license = lib.licenses.mit;
              mainProgram = "kubera";
              platforms = systems;
            };
          };
        in
        {
          inherit kubera;
          default = kubera;
        }
      );

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = nixpkgs.lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default ];
          packages = [
            pkgs.clippy
            pkgs.rustfmt
            pkgs.mdbook
            pkgs.git
          ];
        };
      });

      checks = forAllSystems (pkgs: {
        kubera = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      });
    };
}
