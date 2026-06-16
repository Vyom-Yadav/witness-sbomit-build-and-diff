#!/bin/bash
# Build base image with all binaries for SBOMit Accuracy Analyzer
# This image includes: syft, witness, sbomit, and witness configuration files
# Rebuild only when binaries are updated

set -e

echo "Building sbomit-analyzer:base image..."

# Define paths
BINARY_DIR="/home/vyomydv/test-witness"
SBOMIT_DIR="/home/vyomydv/GolandProjects/sbomit"
DOCKER_DIR="$(dirname "$0")/../docker"

# Check permissions of ca_key.pem
if [ ! -r "$BINARY_DIR/witness_nettrace_proxy/ca_key.pem" ]; then
    echo "ERROR: Cannot read $BINARY_DIR/witness_nettrace_proxy/ca_key.pem"
    echo "This file has restrictive permissions (owned by root)."
    echo ""
    echo "To fix this, run:"
    echo "  sudo chmod 644 $BINARY_DIR/witness_nettrace_proxy/ca_key.pem"
    echo ""
    echo "Then re-run this script."
    exit 1
fi

# Create temporary build context
TEMP_DIR=$(mktemp -d)
echo "Using temporary build context: $TEMP_DIR"

# Copy binaries to build context
echo "Copying syft binary..."
cp "$BINARY_DIR/syft" "$TEMP_DIR/"

echo "Copying witness binary..."
cp "$BINARY_DIR/witness" "$TEMP_DIR/"

echo "Copying sbomit binary..."
cp "$SBOMIT_DIR/sbomit" "$TEMP_DIR/"

# Copy witness configuration files
echo "Copying witness configuration..."
cp "$BINARY_DIR/.witness.yaml" "$TEMP_DIR/"
cp "$BINARY_DIR/testkey.pem" "$TEMP_DIR/"
cp "$BINARY_DIR/testpub.pem" "$TEMP_DIR/"
cp -r "$BINARY_DIR/witness_nettrace_proxy" "$TEMP_DIR/"

# Copy Dockerfile
cp "$DOCKER_DIR/Dockerfile.base" "$TEMP_DIR/"

# Build image
echo "Building Docker image..."
docker build -t sbomit-analyzer:base -f "$TEMP_DIR/Dockerfile.base" "$TEMP_DIR"

# Cleanup
echo "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo "Base image built successfully: sbomit-analyzer:base"
echo ""
echo "To test the image, run:"
echo "  docker run --rm sbomit-analyzer:base which syft witness sbomit"
echo "  docker run --rm sbomit-analyzer:base witness --version"
echo "  docker run --rm sbomit-analyzer:base syft --version"
