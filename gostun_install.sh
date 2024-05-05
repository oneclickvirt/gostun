#!/bin/bash
#From https://github.com/oneclickvirt/gostun
#2024.05.05

rm -rf gostun
os=$(uname -s)
arch=$(uname -m)

case $os in
  Linux)
    case $arch in
      "x86_64" | "x86" | "amd64" | "x64")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-linux-amd64
        ;;
      "i386" | "i686")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-linux-386
        ;;
      "armv7l" | "armv8" | "armv8l" | "aarch64")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-linux-arm64
        ;;
      *)
        echo "Unsupported architecture: $arch"
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case $arch in
      "x86_64" | "x86" | "amd64" | "x64")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-darwin-amd64
        ;;
      "i386" | "i686")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-darwin-386
        ;;
      "armv7l" | "armv8" | "armv8l" | "aarch64")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-darwin-arm64
        ;;
      *)
        echo "Unsupported architecture: $arch"
        exit 1
        ;;
    esac
    ;;
  FreeBSD)
    case $arch in
      amd64)
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-freebsd-amd64
        ;;
      "i386" | "i686")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-freebsd-386
        ;;
      "armv7l" | "armv8" | "armv8l" | "aarch64")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-freebsd-arm64
        ;;
      *)
        echo "Unsupported architecture: $arch"
        exit 1
        ;;
    esac
    ;;
  OpenBSD)
    case $arch in
      amd64)
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-openbsd-amd64
        ;;
      "i386" | "i686")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-openbsd-386
        ;;
      "armv7l" | "armv8" | "armv8l" | "aarch64")
        wget -O gostun https://github.com/oneclickvirt/gostun/releases/download/output/gostun-openbsd-arm64
        ;;
      *)
        echo "Unsupported architecture: $arch"
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported operating system: $os"
    exit 1
    ;;
esac

chmod 777 gostun
./gostun