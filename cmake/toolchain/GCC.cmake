set(CMAKE_C_COMPILER gcc)
set(CMAKE_AR gcc-ar)
set(CMAKE_LINKER gcc)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    if(ARCH STREQUAL "x64")
        set(CMAKE_C_FLAGS_INIT "-m64 -mcmodel=small")
    elseif(ARCH STREQUAL "ia32")
        set(CMAKE_C_FLAGS_INIT "-m32")
        set(CMAKE_EXE_LINKER_FLAGS_INIT "-m32")
    endif()
endif()

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ARCH)
