#!/usr/bin/env python3
"""
fix_selaco_archipelago.py - Fix Selaco's CMakeLists.txt for Archipelago build
"""

import sys
import shutil
from pathlib import Path
from datetime import datetime

def fix_cmakelists(file_path):
    """Fix the CMakeLists.txt file"""
    
    cmake_file = Path(file_path)
    if not cmake_file.exists():
        print(f"ERROR: {cmake_file} not found!")
        return False
    
    # Create backup
    backup_file = cmake_file.with_suffix(f'.txt.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
    shutil.copy2(cmake_file, backup_file)
    print(f"Created backup: {backup_file}")
    
    with open(cmake_file, 'r') as f:
        content = f.read()
    
    # Fix 1: Add target_architecture macro before it's used
    # Find where it's called (line 85)
    target_arch_pos = content.find('target_architecture(TARGET_ARCHITECTURE)')
    
    if target_arch_pos != -1:
        # Check if macro is already defined
        if 'macro(target_architecture' not in content[:target_arch_pos]:
            print("Adding target_architecture macro definition...")
            
            # Find a good place to insert it - after the Archipelago section but before line 85
            # Let's put it right before the include statements
            insert_pos = content.find('include( CheckCXXSourceCompiles )')
            if insert_pos == -1:
                # Alternative: put it right before target_architecture is called
                insert_pos = target_arch_pos
            
            macro_definition = '''
# Define target_architecture macro (needed by libwebsockets)
macro(target_architecture output_var)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(${output_var} "x64")
    else()
        set(${output_var} "x86")
    endif()
endmacro()

'''
            content = content[:insert_pos] + macro_definition + content[insert_pos:]
            print("Added target_architecture macro")
    
    # Fix 2: Also add the macro inside the Archipelago section for libwebsockets
    archipelago_section = content.find('if(ENABLE_ARCHIPELAGO)')
    if archipelago_section != -1:
        # Find FetchContent_MakeAvailable(libwebsockets)
        fetch_lws = content.find('FetchContent_MakeAvailable(libwebsockets)', archipelago_section)
        if fetch_lws != -1:
            # Check if we need to add options before FetchContent_MakeAvailable
            if 'LWS_WITHOUT_EXTENSIONS' not in content[archipelago_section:fetch_lws]:
                print("Adding additional libwebsockets options...")
                
                additional_options = '''    
    # Additional libwebsockets options to avoid build issues
    set(LWS_WITHOUT_EXTENSIONS ON CACHE BOOL "" FORCE)
    set(LWS_WITHOUT_DAEMONIZE ON CACHE BOOL "" FORCE)
    set(LWS_WITHOUT_SERVER ON CACHE BOOL "" FORCE)
    
'''
                content = content[:fetch_lws] + additional_options + content[fetch_lws:]
    
    # Write the fixed content
    with open(cmake_file, 'w') as f:
        f.write(content)
    
    print(f"Fixed {cmake_file}")
    return True

def create_build_script(selaco_dir):
    """Create a build script"""
    
    build_script = f'''@echo off
REM rebuild_archipelago.bat - Clean rebuild with Archipelago

echo ==========================================
echo Clean rebuild with Archipelago support
echo ==========================================

cd "{selaco_dir}"

REM Clean the build directory
echo Cleaning build directory...
cd build
if exist _deps rd /s /q _deps
if exist CMakeCache.txt del CMakeCache.txt

REM Reconfigure
echo Configuring...
cmake ..\\src -G "Visual Studio 17 2022" -A x64 -DENABLE_ARCHIPELAGO=ON

if %errorlevel% neq 0 (
    echo Configuration failed!
    pause
    exit /b 1
)

REM Build
echo Building...
cmake --build . --config Release

if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build completed!
echo Executable: build\\Release\\Selaco.exe
pause
'''
    
    script_path = Path(selaco_dir) / "rebuild_archipelago.bat"
    script_path.write_text(build_script)
    print(f"\nCreated build script: {script_path}")
    return script_path

def main():
    if len(sys.argv) > 1:
        cmake_path = sys.argv[1]
    else:
        # Default path
        cmake_path = r"C:\Users\Skuldier\Documents\SelacoFreshSource\src\CMakeLists.txt"
    
    # Get the Selaco directory
    cmake_file = Path(cmake_path)
    if cmake_file.name != "CMakeLists.txt":
        print("ERROR: Please provide path to CMakeLists.txt")
        return 1
    
    selaco_dir = cmake_file.parent.parent  # Go up from src to SelacoFreshSource
    
    print(f"Fixing CMakeLists.txt at: {cmake_path}")
    print(f"Selaco directory: {selaco_dir}")
    
    if fix_cmakelists(cmake_path):
        create_build_script(selaco_dir)
        
        print("\n" + "="*60)
        print("SUCCESS! CMakeLists.txt has been fixed.")
        print("="*60)
        print("\nNext steps:")
        print("1. Run: rebuild_archipelago.bat")
        print("   OR")
        print("2. Manually:")
        print("   cd build")
        print("   rmdir /s /q _deps")
        print("   cmake ..\\src -DENABLE_ARCHIPELAGO=ON")
        print("   cmake --build . --config Release")
        print("\nThe build should now work without the target_architecture error.")
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())