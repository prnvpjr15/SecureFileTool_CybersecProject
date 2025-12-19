SecureFile Tool 🔒

A robust, cross-platform Desktop GUI application for file encryption and integrity verification. Built using wxWidgets for the interface and Crypto++ for industry-standard cryptographic operations.

Features ✨

AES-256 Encryption: Securely encrypts any file type.

Random Salts: Generates a unique 16-byte random salt for every encryption to prevent Rainbow Table attacks.

PBKDF2: Derives the key and IV from your password using 10,000 iterations of SHA-256.

SHA-256 Hashing: Generate unique file fingerprints.

Hash Comparator: Paste an expected hash to instantly verify if a downloaded file is authentic (Green = Match, Red = Mismatch).

HMAC Signing: Verify file authenticity using a shared secret key.

Drag & Drop: Simply drag files onto the window to load them.

Cross-Platform: Runs on Windows, Linux, and macOS.

Installation 🛠️

Prerequisites

C++ Compiler (MSVC, GCC, or Clang)

CMake (v3.10+)

wxWidgets (v3.x)

Crypto++ (v8.x)

1. Windows (using vcpkg)

The easiest way to build on Windows is using the vcpkg package manager.

# Install dependencies
.\vcpkg\vcpkg install wxwidgets:x64-windows
.\vcpkg\vcpkg install cryptopp:x64-windows

# Build
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build .


2. Linux (Ubuntu/Debian)

# Install dependencies
sudo apt-get install build-essential cmake libwxgtk3.0-gtk3-dev libcrypto++-dev

# Build
mkdir build && cd build
cmake ..
make


Usage 🚀

Launch the App: Run SecureFileTool (or SecureFileTool.exe).

Load a File: Drag and drop a file or click "Open File".

Choose Operation:

AES: Enter a password. If the file is plain, it encrypts. If it's .enc, it decrypts.

SHA-256: View the hash. Paste an expected hash in the comparison box to verify.

HMAC: Calculates signature based on the key in config.txt.

Project Structure 📂

SecureFileTool/
├── src/
│   └── main.cpp       # Main application source code
├── config.txt         # Configuration file (HMAC Key)
├── CMakeLists.txt     # CMake Build System
└── README.md          # Documentation


License

This project is licensed under the MIT License - see the LICENSE file for details.