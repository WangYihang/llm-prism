{
  description = "LLM-Redactor — redact secrets locally before traffic leaves your machine";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];

      eachSystem = f: lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});

      releaseVersion = "0-unstable-${lib.substring 0 7 (self.rev or self.dirtyRev or "0000000")}";
    in
    {
      devShells = eachSystem (_system: pkgs: {
        default = pkgs.mkShellNoCC {
          packages = [
            pkgs.go_1_25
            pkgs.gopls
          ];
        };
      });

      packages = eachSystem (system: pkgs: {
        default = self.packages.${system}.llm-redactor;
        llm-redactor = pkgs.buildGo125Module {
          pname = "llm-redactor";
          version = releaseVersion;

          src = ./.;

          vendorHash = "sha256-bPK6/g0t7nOnWecQDGc3hAgwWxqkhcgRuqvMS7rSxjw=";

          subPackages = [
            "cmd/llm-redactor-proxy"
            "cmd/llm-redactor-exec"
          ];

          ldflags = [
            "-s"
            "-w"
            "-X github.com/wangyihang/llm-redactor/pkg/utils/version.Version=${releaseVersion}"
            "-X github.com/wangyihang/llm-redactor/pkg/utils/version.Commit=${self.rev or self.dirtyRev or "unknown"}"
            "-X github.com/wangyihang/llm-redactor/pkg/utils/version.Date=${self.lastModifiedDate or "19700101000000"}"
          ];

          meta = {
            description = "Transparent proxy and exec wrapper to redact secrets before LLM API calls";
            homepage = "https://github.com/wangyihang/llm-redactor";
            license = lib.licenses.mit;
            mainProgram = "llm-redactor-exec";
          };
        };
      });

      apps = eachSystem (system: _pkgs: {
        default = self.apps.${system}.exec;
        exec = {
          type = "app";
          program = "${self.packages.${system}.llm-redactor}/bin/llm-redactor-exec";
        };
        proxy = {
          type = "app";
          program = "${self.packages.${system}.llm-redactor}/bin/llm-redactor-proxy";
        };
      });

      checks = eachSystem (system: _pkgs: {
        default = self.packages.${system}.llm-redactor;
      });
    };
}
