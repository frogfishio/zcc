#!/bin/sh
set -eu

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$arch" in
  amd64|x86_64)
    arch="x86_64"
    ;;
  arm64|aarch64)
    arch="arm64"
    ;;
esac

case "$os" in
  linux)
    os="linux"
    ;;
  darwin)
    os="darwin"
    ;;
  msys*|mingw*|cygwin*)
    os="windows"
    ;;
esac

printf "%s-%s\n" "$os" "$arch"
