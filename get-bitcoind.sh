#!/bin/bash

set -e

echo "🚀 Starting bitcoind setup..."

# Detect platform
OS="$(uname -s)"

if [[ "$OS" == "Darwin" || "$OS" == "Linux" ]]; then
    echo "🔍 Detected Unix-like OS ($OS)"

    if command -v bitcoind >/dev/null 2>&1; then
        BITCOIND_PATH="$(which bitcoind)"
        echo "✅ bitcoind is already installed at: $BITCOIND_PATH"
    else
        echo "📦 Installing Bitcoin Core via Homebrew (macOS) or package manager (Linux)..."
        if [[ "$OS" == "Darwin" ]]; then
            brew install bitcoind
        else
            echo "❌ Please install bitcoind manually (e.g., apt-get install bitcoind)"
            exit 1
        fi

        BITCOIND_PATH="$(which bitcoind)"
        echo "✅ bitcoind installed at: $BITCOIND_PATH"
    fi

    # Determine profile file
    case "$SHELL" in
    */zsh)
        PROFILE_FILE="$HOME/.zprofile"
        ;;
    */bash)
        PROFILE_FILE="$HOME/.bash_profile"
        ;;
    *)
        PROFILE_FILE="$HOME/.profile"
        ;;
    esac

    if ! grep -q 'export BITCOIND_PATH=' "$PROFILE_FILE" 2>/dev/null; then
        echo "🔧 Adding BITCOIND_PATH to $PROFILE_FILE"
        echo "export BITCOIND_PATH=\"$BITCOIND_PATH\"" >> "$PROFILE_FILE"
    else
        echo "⚠️  BITCOIND_PATH already set in $PROFILE_FILE"
    fi

    export BITCOIND_PATH="$BITCOIND_PATH"
    echo "✅ BITCOIND_PATH exported for current session"

elif [[ "$OS" == "MINGW"* || "$OS" == "CYGWIN"* || "$OS" == "MSYS"* ]]; then
    echo "🔍 Detected Windows (Git Bash / MSYS)"

    BITCOIND_PATH="$(powershell.exe -Command "Get-Command bitcoind.exe | Select-Object -ExpandProperty Source" 2>/dev/null | tr -d '\r')"

    if [[ -z "$BITCOIND_PATH" ]]; then
        echo "❌ bitcoind.exe not found in PATH. Please install Bitcoin Core and ensure bitcoind.exe is available."
        exit 1
    fi

    echo "✅ bitcoind.exe found at: $BITCOIND_PATH"

    echo "🔧 Setting BITCOIND_PATH for current session..."
    export BITCOIND_PATH="$BITCOIND_PATH"

    echo "🔧 Persisting BITCOIND_PATH for future shells..."
    powershell.exe -Command "[Environment]::SetEnvironmentVariable('BITCOIND_PATH', '$BITCOIND_PATH', 'User')" 2>/dev/null

    echo "✅ BITCOIND_PATH has been set for this session and saved in your user environment variables."

else
    echo "❌ Unsupported OS: $OS"
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo "➡️  You can now run tests with:"
echo ""
echo "   cargo test -- --nocapture"
echo ""
echo "📌 BITCOIND_PATH is ready!"
