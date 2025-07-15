#!/usr/bin/env bash
set -euo pipefail

# Issue a 3-tier certificate chain.

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ca-tool> <purpose>"
    exit 1
fi

# CA_TOOL should point to the compiled Go CLI.
CA_TOOL=$1
PURPOSE=$2

read -p "Before you use this in production, think hard about the validity periods! Type 'yes' to continue: " confirmation

if [ "$confirmation" != "yes" ]; then
    echo "Fission mailed."
    exit 1
fi

# Generate a root CA key and certificate, 10 year validity.
$CA_TOOL issue --subject $PURPOSE-root --validity_in_days 3650 --self_signed

# Generate an intermediate CA key and certificate, 6 year validity.
$CA_TOOL issue --subject $PURPOSE-intermediate --validity_in_days 2190 --issuer $PURPOSE-root.pct --issuer_key $PURPOSE-root.priv.der

# And the leaf, 4 year validity.
$CA_TOOL issue --subject $PURPOSE-leaf --validity_in_days 1460 --issuer $PURPOSE-intermediate.pct --issuer_key $PURPOSE-intermediate.priv.der
