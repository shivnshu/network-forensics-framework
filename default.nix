with import <nixpkgs> {};

(python36.withPackages (ps: with ps; [ ipython scapy pytest scikitlearn ])).env
