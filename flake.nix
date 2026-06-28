{
  description = "CLI tool for inspecting, validating, and comparing X.509 certificate chains";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          version = "0.2.0";
        in
        {
          default = pkgs.buildGoModule {
            pname = "xcv";
            inherit version;

            src = self;
            vendorHash = "sha256-7K17JaXFsjf163g5PXCb5ng2gYdotnZ2IDKk8KFjNj0=";

            nativeBuildInputs = [ pkgs.installShellFiles ];

            postInstall = ''
              installShellCompletion --cmd xcv \
                --zsh <($out/bin/xcv completion zsh) \
                --bash <($out/bin/xcv completion bash) \
                --fish <($out/bin/xcv completion fish)
            '';

            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
            ];

            meta = with pkgs.lib; {
              description = "CLI tool for inspecting, validating, and comparing X.509 certificate chains — live TLS checks, RFC 5280 compliance, and PEM order enforcement.";
              homepage = "https://github.com/rwilgaard/xcv";
              license = licenses.mit;
              mainProgram = "xcv";
            };
          };
        }
      );
    };
}
