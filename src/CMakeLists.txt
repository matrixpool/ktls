add_executable(client client.c)
target_link_libraries(client ssl crypto)

add_executable(server server.c)
target_link_libraries(server ssl crypto)

add_executable(aead_openssl aead_openssl.c)
target_link_libraries(aead_openssl ssl crypto)

add_executable(aead_afalg aead_afalg.c)

add_executable(gcm_sm4 gcm_sm4.c)
target_link_libraries(gcm_sm4 ssl crypto)

add_executable(gcm_aes gcm_aes.c)
target_link_libraries(gcm_aes ssl crypto)

add_executable(cbc_aes cbc_aes.c)
target_link_libraries(cbc_aes ssl crypto)

add_executable(client_ntls client_ntls.c)
target_link_libraries(client_ntls ssl crypto)

add_executable(server_ntls server_ntls.c)
target_link_libraries(server_ntls ssl crypto)