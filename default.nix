let
    pkgs = import <nixpkgs> {};
in
    { stdenv ? pkgs.stdenv }:

    stdenv.mkDerivation {
        name = "network-forensics";
        buildInputs = [
            pkgs.python3
            pkgs.python36Packages.ipython
            pkgs.python36Packages.scapy
            pkgs.python36Packages.pytest
            pkgs.python36Packages.django
            pkgs.python36Packages.pyaml
        ]
        ++ (with pkgs.python36Packages; [
            (scikitlearn.overridePythonAttrs (oldAttrs: {
              checkPhase = "true";
              })
            )
        ]);
    }
