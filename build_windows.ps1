# ZeroTrustScope Windows Build Script
# This script compiles the C components for Windows

Write-Host "=== ZeroTrustScope Windows Build ===" -ForegroundColor Green
Write-Host ""

# Check for available compilers
$compiler = $null
$compiler_args = @()

# Try to find MSVC (Visual Studio)
try {
    $vs_path = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vs_path) {
        $vcvars_path = Join-Path $vs_path "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $vcvars_path) {
            $compiler = "cl"
            $compiler_args = @("/Fe:zerotrust.dll", "/LD", "/MD")
            Write-Host "Found Visual Studio Build Tools" -ForegroundColor Yellow
        }
    }
} catch {
    # Ignore errors
}

# Try to find MinGW
if (-not $compiler) {
    $mingw_paths = @(
        "C:\mingw64\bin\gcc.exe",
        "C:\msys64\mingw64\bin\gcc.exe",
        "C:\msys64\usr\bin\gcc.exe"
    )
    
    foreach ($path in $mingw_paths) {
        if (Test-Path $path) {
            $compiler = $path
            $compiler_args = @("-shared", "-o", "zerotrust.dll", "-DWIN32", "-D_WINDOWS")
            Write-Host "Found MinGW at: $path" -ForegroundColor Yellow
            break
        }
    }
}

# Try to find gcc in PATH
if (-not $compiler) {
    try {
        $gcc_output = & gcc --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            $compiler = "gcc"
            $compiler_args = @("-shared", "-o", "zerotrust.dll", "-DWIN32", "-D_WINDOWS")
            Write-Host "Found gcc in PATH" -ForegroundColor Yellow
        }
    } catch {
        # Ignore errors
    }
}

if (-not $compiler) {
    Write-Host "No C compiler found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To compile the C library, you need to install one of:" -ForegroundColor Yellow
    Write-Host "1. Visual Studio Build Tools (recommended)" -ForegroundColor White
    Write-Host "2. MinGW-w64" -ForegroundColor White
    Write-Host "3. MSYS2 with gcc" -ForegroundColor White
    Write-Host ""
    Write-Host "For now, creating a stub library for testing..." -ForegroundColor Yellow
    
    # Create a stub DLL for testing
    $stub_code = @"
#include <stdio.h>

__declspec(dllexport) void start_monitoring() {
    printf("[*] Stub: Starting packet monitoring (C library not compiled)\n");
}

__declspec(dllexport) void add_trusted_ip(const char *ip) {
    printf("[*] Stub: Adding trusted IP %s (C library not compiled)\n", ip);
}

__declspec(dllexport) void block_untrusted_ip(const char *ip) {
    printf("[*] Stub: Blocking untrusted IP %s (C library not compiled)\n", ip);
}
"@
    
    $stub_code | Out-File -FilePath "src\stub.c" -Encoding ASCII
    Write-Host "Created stub.c for testing" -ForegroundColor Green
    exit 0
}

# Compile the C code
Write-Host "Compiling C components..." -ForegroundColor Green

$source_files = @(
    "src\main.c",
    "src\capture.c", 
    "src\policy.c",
    "src\ffi_interface.c"
)

$include_dirs = @("-Isrc")

if ($compiler -eq "cl") {
    # Use MSVC
    $cmd = "& '$vcvars_path' && cl $compiler_args $include_dirs $source_files"
    Write-Host "Using MSVC compiler..." -ForegroundColor Yellow
} else {
    # Use gcc/MinGW
    $cmd = "$compiler $compiler_args $include_dirs $source_files"
    Write-Host "Using $compiler compiler..." -ForegroundColor Yellow
}

Write-Host "Running: $cmd" -ForegroundColor Gray
Invoke-Expression $cmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "Compilation successful!" -ForegroundColor Green
    Write-Host "Created: zerotrust.dll" -ForegroundColor Green
} else {
    Write-Host "Compilation failed!" -ForegroundColor Red
    Write-Host "Creating stub library for testing..." -ForegroundColor Yellow
    
    # Create a stub DLL for testing
    $stub_code = @"
#include <stdio.h>

__declspec(dllexport) void start_monitoring() {
    printf("[*] Stub: Starting packet monitoring (C library not compiled)\n");
}

__declspec(dllexport) void add_trusted_ip(const char *ip) {
    printf("[*] Stub: Adding trusted IP %s (C library not compiled)\n", ip);
}

__declspec(dllexport) void block_untrusted_ip(const char *ip) {
    printf("[*] Stub: Blocking untrusted IP %s (C library not compiled)\n", ip);
}
"@
    
    $stub_code | Out-File -FilePath "src\stub.c" -Encoding ASCII
    Write-Host "Created stub.c for testing" -ForegroundColor Green
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green 