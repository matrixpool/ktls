
# Module info
add_definitions(-D__KERNEL__ -DMODULE)

set(TLS_NAME tls)
set(TLS_MODULE_FILE ${TLS_NAME}.ko)
set(
	KBUILD_CMD 
	$(MAKE) ARCH=${CPU} CROSS_COMPILE=${CROSS} -C ${KERNELHEADERS_DIR} 
	modules M=${CMAKE_CURRENT_BINARY_DIR} 
	src=${CMAKE_CURRENT_SOURCE_DIR}
)
set(TLS_OBJS "tls_main.o tls_sw.o tls_proc.o tls_toe.o tls_device.o tls_device_fallback.o trace.o")

FILE(
	WRITE 
	${CMAKE_CURRENT_SOURCE_DIR}/Kbuild 
	"obj-m := ${TLS_NAME}.o\n${TLS_NAME}-y := ${TLS_OBJS}"
)

add_custom_command(OUTPUT ${TLS_MODULE_FILE}
	COMMAND ${KBUILD_CMD}
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS ${SRC_LISTS} VERBATIM
)

add_custom_target(tls-module ALL DEPENDS ${TLS_MODULE_FILE})
add_custom_target(tls-module-clean COMMAND ${KBUILD_CMD} clean)

