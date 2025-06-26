# CheckFunctions.cmake - Check for string comparison functions

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
                    return strcasecmp("a", "b"); 
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
                    return strncasecmp("a", "b", 1); 
                }" HAVE_STRNCASECMP_CXX)
            if(HAVE_STRNCASECMP_CXX)
                add_definitions(-Dstrnicmp=strncasecmp)
            else()
                message(FATAL_ERROR "No case-insensitive string comparison function found")
            endif()
        endif()
    endif()
endfunction()
