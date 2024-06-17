add_executable(client13 client13.c)
target_link_libraries(client13 ssl crypto)

add_executable(server13 server13.c)
target_link_libraries(server13 ssl crypto)

add_executable(client12 client12.c)
target_link_libraries(client12 ssl crypto)

add_executable(server12 server12.c)
target_link_libraries(server12 ssl crypto)

add_executable(client_ntls client_ntls.c)
target_link_libraries(client_ntls ssl crypto)

add_executable(server_ntls server_ntls.c)
target_link_libraries(server_ntls ssl crypto)

# add_executable(aead_openssl aead_openssl.c)
# target_link_libraries(aead_openssl ssl crypto)

add_executable(aead_afalg aead_afalg.c)

add_executable(gcm_sm4 gcm_sm4.c)
target_link_libraries(gcm_sm4 ssl crypto)

add_executable(gcm_sm4_dec gcm_sm4_dec.c)
target_link_libraries(gcm_sm4_dec ssl crypto)

add_executable(gcm_sm4_error gcm_sm4_error.c)
target_link_libraries(gcm_sm4_error ssl crypto)

add_executable(authenc_sm3_sm4 authenc_sm3_sm4.c)
target_link_libraries(authenc_sm3_sm4 ssl crypto)

add_executable(cbc_sm3_sm4 cbc_sm3_sm4.c)
target_link_libraries(cbc_sm3_sm4 ssl crypto)

add_executable(xor xor.c)
target_link_libraries(xor ssl crypto)

add_executable(authenctls_afalg authenctls_afalg.c)
add_executable(authenctls_afalgnew authenctls_afalgnew.c)

