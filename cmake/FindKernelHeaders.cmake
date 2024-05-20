set(CPU "x86")

# Find the kernel release
execute_process(
  COMMAND uname -r
  OUTPUT_VARIABLE KERNEL_RELEASE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Find the headers
find_path(
  KERNELHEADERS_DIR 
  NAMES include/linux/user.h
  PATHS /usr/src/linux-headers-${KERNEL_RELEASE}
)

if (KERNELHEADERS_DIR)	
  set(KERNELHEADERS_INCLUDE_DIRS
    ${KERNELHEADERS_DIR}/include
    ${KERNELHEADERS_DIR}/arch/${CPU}/include
  )
  set(KERNELHEADERS_FOUND 1 CACHE STRING "Set to 1 if kernel headers were found")
else ()
  set(KERNELHEADERS_FOUND 0 CACHE STRING "Set to 1 if kernel headers were found")
endif (KERNELHEADERS_DIR)

message("Kernel headers: ${KERNELHEADERS_DIR}")
message("Kernel include headers: ${KERNELHEADERS_INCLUDE_DIRS}")

mark_as_advanced(KERNELHEADERS_FOUND)
