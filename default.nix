with import <nixpkgs> {};

(python36.withPackages (ps: with ps; [ scapy pytest ])).env
