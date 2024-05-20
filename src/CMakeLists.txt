add_executable(client client.c)
target_link_libraries(client ssl crypto)

add_executable(server server.c)
target_link_libraries(server ssl crypto)

add_executable(aead_openssl aead_openssl.c)
target_link_libraries(aead_openssl ssl crypto)

add_executable(aead_afalg aead_afalg.c)