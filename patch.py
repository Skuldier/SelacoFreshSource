#!/usr/bin/env python3
"""
Fix missing require_stricmp() and require_strnicmp() CMake functions
"""

import os
import sys
import shutil

def create_checkfunctions_cmake(cmake_dir):
    """Create CheckFunctions.cmake with the missing function definitions"""
    
    checkfunctions_content = '''# CheckFunctions.cmake - Check for string comparison functions

include(CheckFunctionExists)
include(CheckCXXSourceCompiles)

# Check for stricmp/strcasecmp
function(require_stricmp)
    if(MSVC)
        # MSVC has _stricmp
        add_definitions(-Dstricmp=_stricmp)
    else()
        # Check for POSIX strcasecmp
        check_function_exists(strcasecmp HAVE_STRCASECMP)
        if(HAVE_STRCASECMP)
            add_definitions(-Dstricmp=strcasecmp)
        else()
            # Try to compile a test program
            check_cxx_source_compiles("
                #include <string.h>
                int main() { 
                    return strcasecmp(\"a\", \"b\"); 
                }" HAVE_STRCASECMP_CXX)
            if(HAVE_STRCASECMP_CXX)
                add_definitions(-Dstricmp=strcasecmp)
            else()
                message(FATAL_ERROR "No case-insensitive string comparison function found")
            endif()
        endif()
    endif()
endfunction()

# Check for strnicmp/strncasecmp
function(require_strnicmp)
    if(MSVC)
        # MSVC has _strnicmp
        add_definitions(-Dstrnicmp=_strnicmp)
    else()
        # Check for POSIX strncasecmp
        check_function_exists(strncasecmp HAVE_STRNCASECMP)
        if(HAVE_STRNCASECMP)
            add_definitions(-Dstrnicmp=strncasecmp)
        else()
            # Try to compile a test program
            check_cxx_source_compiles("
                #include <string.h>
                int main() { 
                    return strncasecmp(\"a\", \"b\", 1); 
                }" HAVE_STRNCASECMP_CXX)
            if(HAVE_STRNCASECMP_CXX)
                add_definitions(-Dstrnicmp=strncasecmp)
            else()
                message(FATAL_ERROR "No case-insensitive string comparison function found")
            endif()
        endif()
    endif()
endfunction()
'''
    
    checkfunctions_path = os.path.join(cmake_dir, "CheckFunctions.cmake")
    
    # Backup existing file if it exists
    if os.path.exists(checkfunctions_path):
        backup_path = checkfunctions_path + ".backup"
        shutil.copy2(checkfunctions_path, backup_path)
        print(f"Backed up existing file to: {backup_path}")
    
    # Write the new content
    with open(checkfunctions_path, 'w') as f:
        f.write(checkfunctions_content)
    
    print(f"Created: {checkfunctions_path}")
    return checkfunctions_path

def patch_root_cmakelists(root_dir):
    """Add include for CheckFunctions.cmake in root CMakeLists.txt"""
    
    root_cmake = os.path.join(root_dir, "CMakeLists.txt")
    
    if not os.path.exists(root_cmake):
        print(f"Error: Root CMakeLists.txt not found at {root_cmake}")
        return False
    
    # Read the file
    with open(root_cmake, 'r') as f:
        content = f.read()
    
    # Check if CheckFunctions is already included
    if "CheckFunctions" in content:
        print("CheckFunctions.cmake already included in root CMakeLists.txt")
        return True
    
    # Find a good place to add the include (after other includes)
    include_lines = []
    lines = content.split('\n')
    insert_index = -1
    
    for i, line in enumerate(lines):
        if 'include(' in line.lower() and 'fetchcontent' not in line.lower():
            insert_index = i + 1
    
    # If no includes found, add after project() command
    if insert_index == -1:
        for i, line in enumerate(lines):
            if 'project(' in line.lower():
                insert_index = i + 1
                break
    
    # If still not found, add at the beginning
    if insert_index == -1:
        insert_index = 0
    
    # Insert the include
    lines.insert(insert_index, 'include(cmake/CheckFunctions.cmake)')
    
    # Write back
    with open(root_cmake, 'w') as f:
        f.write('\n'.join(lines))
    
    print(f"Updated root CMakeLists.txt to include CheckFunctions.cmake")
    return True

def main():
    # Get the Selaco source directory
    selaco_dir = r"C:\Users\Skuldier\Documents\SelacoFreshSource"
    
    if not os.path.exists(selaco_dir):
        print(f"Error: Selaco directory not found at {selaco_dir}")
        return 1
    
    cmake_dir = os.path.join(selaco_dir, "cmake")
    
    # Create cmake directory if it doesn't exist
    if not os.path.exists(cmake_dir):
        os.makedirs(cmake_dir)
        print(f"Created cmake directory: {cmake_dir}")
    
    # Create CheckFunctions.cmake
    checkfunctions_path = create_checkfunctions_cmake(cmake_dir)
    
    # Patch root CMakeLists.txt
    if patch_root_cmakelists(selaco_dir):
        print("\nSuccessfully created CheckFunctions.cmake and updated CMakeLists.txt")
        print("\nYou can now try building again with:")
        print("cd build")
        print("cmake ..")
    else:
        print("\nError: Failed to update root CMakeLists.txt")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())