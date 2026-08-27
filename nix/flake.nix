{
  description = "NekoGuard: reverse proxy with PoW protection";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "nekoguard";
          version = "1.0.0";
          src = ../.;
          cargoLock.lockFile = ../Cargo.lock;
          buildAndTestSubdir = "nekoguard";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            redis
          ];
        };
      }
    );
}
