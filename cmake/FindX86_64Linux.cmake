set(CMAKE_SYSTEM_NAME Linux)
set(CROSS x86_64-linux-)

set(CMAKE_C_COMPILER ${CROSS}gcc)
set(CMAKE_CXX_COMPILER ${CROSS}g++)
set(CMAKE_AR${CROSS}ar)
set(CMAKE_RANLIB ${CROSS}ranlib)

add_definitions(-nodefaultlibs)

