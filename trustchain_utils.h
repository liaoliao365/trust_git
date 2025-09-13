#ifndef TRUSTCHAIN_UTILS_H
#define TRUSTCHAIN_UTILS_H
#include <openssl/evp.h>
#include "cache.h"

char *binary_to_hex(const unsigned char *data, size_t len);
EVP_PKEY *load_public_key_from_str(const char *pubkey_str);
EVP_PKEY *load_public_key_from_file(const char *filename);
EVP_PKEY *load_private_key(const char *filename);
int trustchain_sign_message(const char *msg, EVP_PKEY *pkey,
    unsigned char **sig, size_t *siglen);
// int trustchain_verify_signature(const char *msg, EVP_PKEY *pkey, 
//     const unsigned char *sig, size_t siglen);
int trustchain_verify_signature_return_hash(
    const char *msg, EVP_PKEY *pkey, 
    const unsigned char *sig, size_t siglen,
    unsigned char out_hash[32]);  
char *base64_encode(const unsigned char *input, int length);
void get_contri_block_sync(const char *commit_msg, struct strbuf *contri_block, int *contri_block_tag);
int verify_and_store_contri_block(struct strbuf *contri_block, unsigned char hash[32]);
int store_contri_block_to_repo(struct strbuf *contri_block, char * hex_hash);
int insert_contri_block_to_db(
    const char *parent_hash,
    const char *op,
    const char *op_key,
    const char *commit_hash,
    const char *tee_time,
    const char *tee_sig
);

#endif