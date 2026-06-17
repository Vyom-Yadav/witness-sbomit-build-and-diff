#!/bin/bash
# Build base image with all binaries for SBOMit Accuracy Analyzer
# This image includes: syft, witness, sbomit, and witness configuration files
# Rebuild only when binaries are updated

set -e

echo "Building sbomit-analyzer:base image..."

# Load configuration from environment or use defaults
# Override these by setting environment variables before running this script
# Or by creating a .env file in the project root

# Try to load .env file if it exists
if [ -f "$(dirname "$0")/../.env" ]; then
    echo "Loading configuration from .env file..."
    export $(grep -v '^#' "$(dirname "$0")/../.env" | xargs)
fi

# Define paths (can be overridden via environment variables)
BINARY_DIR="${SBOMIT_BINARY_DIR:-/home/vyom.yadav@canonical.com/witness-data/}"
SBOMIT_DIR="${SBOMIT_SBOMIT_DIR:-/home/vyom.yadav@canonical.com/git-pulls/sbomit/}"
DOCKER_DIR="$(dirname "$0")/../docker"

echo "Using BINARY_DIR: $BINARY_DIR"
echo "Using SBOMIT_DIR: $SBOMIT_DIR"

# Validate paths exist
if [ ! -d "$BINARY_DIR" ]; then
    echo "ERROR: BINARY_DIR does not exist: $BINARY_DIR"
    echo "Set SBOMIT_BINARY_DIR environment variable or update the script"
    exit 1
fi

if [ ! -d "$SBOMIT_DIR" ]; then
    echo "ERROR: SBOMIT_DIR does not exist: $SBOMIT_DIR"
    echo "Set SBOMIT_SBOMIT_DIR environment variable or update the script"
    exit 1
fi

# Check permissions of required files
echo "Checking file permissions..."

# Check ca_key.pem permissions
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

# Check if binaries are executable
for binary in "$BINARY_DIR/syft" "$BINARY_DIR/witness" "$SBOMIT_DIR/sbomit"; do
    if [ -f "$binary" ] && [ ! -x "$binary" ]; then
        echo "WARNING: $binary is not executable. Run: chmod +x $binary"
    fi
done

# Check required files exist
for file in "$BINARY_DIR/syft" "$BINARY_DIR/witness" "$BINARY_DIR/.witness.yaml" \
            "$BINARY_DIR/testkey.pem" "$BINARY_DIR/testpub.pem" \
            "$BINARY_DIR/witness_nettrace_proxy" "$SBOMIT_DIR/sbomit"; do
    if [ ! -e "$file" ]; then
        echo "ERROR: Required file/directory not found: $file"
        exit 1
    fi
done

echo "All required files found. Proceeding with build..."

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
