cd C:\Users\Skuldier\Documents\SelacoFreshSource

# Backup the file
Copy-Item "src\CMakeLists.txt" "src\CMakeLists.txt.backup"

# Replace the problematic lines
(Get-Content "src\CMakeLists.txt") -replace @'
# Check for functions that may or may not exist.

require_stricmp\(\)
require_strnicmp\(\)
'@, @'
# Check for functions that may or may not exist.

# Define string comparison functions based on platform
if(MSVC)
    add_definitions(-Dstricmp=_stricmp -Dstrnicmp=_strnicmp)
else()
    include(CheckFunctionExists)
    check_function_exists(strcasecmp HAVE_STRCASECMP)
    check_function_exists(strncasecmp HAVE_STRNCASECMP)
    
    if(HAVE_STRCASECMP)
        add_definitions(-Dstricmp=strcasecmp)
    endif()
    
    if(HAVE_STRNCASECMP)
        add_definitions(-Dstrnicmp=strncasecmp)
    endif()
endif()
'@ | Set-Content "src\CMakeLists.txt"