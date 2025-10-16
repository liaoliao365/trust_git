#define list_add __mysql_list_add  // 临时重命名MySQL的list_add
#include <mysql.h>
#undef list_add                    // 恢复宏定义

#include "trustchain_utils.h"

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <jansson.h>
#include "cache.h"
#include <time.h>
#include <unistd.h>

// 数据库连接信息
#define DB_HOST "localhost"
#define DB_USER "trustchain"
#define DB_PASS "trustchain"  // 如果需要密码，请填写
#define DB_NAME "trustchaindb"

void debug_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    FILE *log = fopen("/home/lele/debuggit.log", "a");
    if (log) {
        // fprintf(log, "debug: ");
        vfprintf(log, format, args);
        // fprintf(log, "\n");
        fclose(log);
    }

    va_end(args);
}


//返回时间戳字符串
char *get_timestamp_string(){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    long seconds = ts.tv_sec;
    long milliseconds = ts.tv_nsec / 1000000; // 纳秒转毫秒

    // printf("%ld.%03ld\n", seconds, milliseconds);
    return xstrfmt("%ld.%03ld", seconds, milliseconds);
}

char *binary_to_hex(const unsigned char *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        snprintf(hex + i * 2, 3, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

char *base64_encode(const unsigned char *input, int length){
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不要换行
    BIO_write(b64, input, length);
    BIO_flush(b64);

    BUF_MEM *buffer_ptr;
    BIO_get_mem_ptr(b64, &buffer_ptr);

    char *b64text = strndup(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(b64);
    return b64text;
}
    


EVP_PKEY *load_public_key_from_str(const char *pubkey_str) {
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(pubkey_str, -1); // -1 表示字符串以 '\0' 结尾
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return NULL;
    }

    // 从 PEM 格式解析公钥
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        // 如果失败，回到开头，尝试 PKCS#1 格式
        BIO_reset(bio);
        RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        if (rsa) {
            pkey = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(pkey, rsa);
        }
    }
    BIO_free(bio);

    if (!pkey) {
        fprintf(stderr, "Failed to parse public key\n");
        return NULL;
    }

    return pkey;
}

EVP_PKEY *load_public_key_from_file(const char *filename) {
    if (!filename) {
        fprintf(stderr, "Filename is NULL\n");
        return NULL;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to load public key from %s\n", filename);
        return NULL;
    }

    return pkey;
}

EVP_PKEY *load_private_key(const char *filename){
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        ERR_print_errors_fp(stderr);  // 打印OpenSSL错误
        return NULL;
    }
    return pkey;
}



// 使用 SHA256 + 私钥 对 msg 进行签名
int trustchain_sign_message(const char *msg, EVP_PKEY *pkey,
    unsigned char **sig, size_t *siglen)
{
    // 输入验证
    if (!msg || !pkey || !sig || !siglen) {
        fprintf(stderr, "Invalid input parameters\n");
        return 0;
    }
    
    if (strlen(msg) == 0) {
        fprintf(stderr, "Empty message\n");
        return 0;
    }

    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    *sig = NULL;
    *siglen = 0;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto done;
    }

    // 初始化签名上下文，指定哈希算法 SHA256
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    // 输入数据
    if (EVP_DigestSignUpdate(ctx, msg, strlen(msg)) <= 0) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    // 先获取签名长度
    if (EVP_DigestSignFinal(ctx, NULL, siglen) <= 0) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    // 分配内存
    *sig = OPENSSL_malloc(*siglen);
    if (!*sig) {
        fprintf(stderr, "OPENSSL_malloc failed\n");
        goto done;
    }

    // 生成签名
    if (EVP_DigestSignFinal(ctx, *sig, siglen) <= 0) {
        ERR_print_errors_fp(stderr);
        OPENSSL_free(*sig);
        *sig = NULL;
        *siglen = 0;
        goto done;
    }

    ret = 1; // success

    done:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int trustchain_verify_signature_return_hash(
    const char *msg, EVP_PKEY *pkey, 
    const unsigned char *sig, size_t siglen,
    unsigned char out_hash[32])
{
    if (!msg || !pkey || !sig || siglen == 0 || !out_hash) {
        return 0;
    }

    // 1. 先计算消息的SHA256哈希
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    if (!hash_ctx) return 0;

    // 1. 先计算消息的 SHA256 哈希
    unsigned int hash_len = 0;
    if (EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(hash_ctx, msg, strlen(msg)) <= 0 ||
        EVP_DigestFinal_ex(hash_ctx, out_hash, &hash_len) <= 0) {
        EVP_MD_CTX_free(hash_ctx);
        return 0;
    }
    EVP_MD_CTX_free(hash_ctx);

    if (hash_len != 32) {
        die("trustchain_verify_signature_return_hash hash_len != 32\nmay not use SHA256\n");
        return 0;
    }

    // 2. 使用 EVP_PKEY_verify 验证签名（直接用哈希）
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // 如果是 RSA，设置 PKCS1 填充（根据你签名方式）
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    }

    int ret = EVP_PKEY_verify(ctx,
                              sig, siglen,   // 签名
                              out_hash, hash_len); // 已计算的哈希
    EVP_PKEY_CTX_free(ctx);

    return ret == 1; // 1 表示验证成功，0 失败
}

// int trustchain_verify_signature(const char *msg, EVP_PKEY *pkey, 
//     const unsigned char *sig, size_t siglen)
// {
//     if (!msg || !pkey || !sig || siglen == 0) {
//         return 0;
//     }

//     EVP_MD_CTX *ctx = EVP_MD_CTX_new();
//     if (!ctx) return 0;

//     int ret = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
//     if (ret <= 0) {
//     EVP_MD_CTX_free(ctx);
//     return 0;
//     }

//     ret = EVP_DigestVerifyUpdate(ctx, msg, strlen(msg));
//     if (ret <= 0) {
//     EVP_MD_CTX_free(ctx);
//     return 0;
//     }

//     ret = EVP_DigestVerifyFinal(ctx, sig, siglen);
//     EVP_MD_CTX_free(ctx);

//     return ret > 0;
// }



void get_contri_block_sync(const char *commit_msg, struct strbuf *contri_block, int *contri_block_tag)
{
    // 这里本来应该调用远程服务的tee的commit接口，返回结果存储到 contri_block中,如果合法，则返回contri_block
    // 但是现在为了调试，模拟等待时间，并直接返回一个合法的contri_block，contri_block_tag设为1
    // sleep 15 seconds
    // sleep(15);
    // usleep 毫秒级别 4184 milliseconds 
    usleep(4184 * 1000); 
    *contri_block_tag = 1;
    json_t *json_obj = json_object();
    json_object_set_new(json_obj, "parent_hash", json_string("5ab92ff2e9e8e609398a36733c057e4903ac6643c646fbd9ab12d0f6234c8daf"));
    json_object_set_new(json_obj, "op", json_string("PUSH"));
    json_object_set_new(json_obj, "op_key", json_string("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuiyYFuYlJj6osgbPqSfg\nHxzGfzROUMHxcPWMxGxB62QeuJZGjuP/lR/BAy2D2WUjtpcR6VuS6x70/RI13nV2\nERNaBDdPG2QTjVM76EammdFwCBVdxNZO1a9+m4ppNWQyQRhwRT+yIMZdaoPrknkR\nCpTwUPOU3HPPio3e09yH9ZHMaqFed6oVURT02ymaR690PkXkAaMAozj/E9O4L1CT\n/UchBS1zVpbgxWaV/X034Ew/saTKHfbtXEOv2627d5ClO7/455d8YiJMjJc4lzFV\nZOXfNDYl7/JDzBYxLZbms2MVdbSoWcGmdoAfKkBly3ZVRjDe8ELFk4d0SdddLrRd\nXQIDAQAB\n-----END PUBLIC KEY-----\n"));
    json_object_set_new(json_obj, "commit_hash", json_string("301eac76e56d8702c5514a8f6f2c96c013ce94e341826bdbf69f73685693749a"));
    json_object_set_new(json_obj, "tee_time", json_string("2025-09-19 11:31:51"));
    json_object_set_new(json_obj, "tee_sig", json_string("873f337906aef8a96601ef44eff12364d60ec63cec0cdff24bbc13bfafc85ccb43cf1718f8aeeb8f32422835cdf1111a1af5d4bdf8c1789028c18fc2c058b17caea0aaf1a156a8d62d8e7ba3c7c814cd8c25f7d1e38b408d32af311885dad51ab4a39466efd646f08b74484d8a117f842c045a4fc79ce26e589be1efe12c4faf286c5bdf01cd0ab9a80d0e4fa386a4357beb1e3bdf5efb3601774b20042e190f5c1634a708c7dd0ab048d6bd21a10f232f302ed8932e0f7c57ffe4049126f22081f7f2b59f7b3c773528c65c9060a8e8a50a75c8ac0e4fcc88eb858a2f7a05ffbfb5c6e5a2d4392e9115d04a21de3e8ef78a330c06b969df56329edd3b01ad71"));
    
    char *dump = json_dumps(json_obj, JSON_INDENT(4)); // 美化输出，缩进 4 空格
    // printf("%s\n", dump);
    strbuf_addstr(contri_block, dump);
    *contri_block_tag = 1;
    free(dump);
    json_decref(json_obj);
}

int store_contri_block_to_repo(struct strbuf *contri_block, char * hex_hash)
{
    char *git_dir_abs = realpath(get_git_dir(), NULL);
    if (!git_dir_abs) {
        debug_log("Failed to get absolute path for git_dir: %s\n", get_git_dir());
        return -1;
    }
    // debug_log("git_dir_abs = %s\n", git_dir_abs);
    // 将contri_block和hash存储到仓库中
    char *contri_block_path = xstrfmt("%s/trustchain/contri_block.json", git_dir_abs);
    char *hash_path = xstrfmt("%s/refs/trustchain/head", git_dir_abs);
    // debug_log("contri_block_path = %s\n", contri_block_path);
    // debug_log("hash_path = %s\n", hash_path);
    
    // // 确保目录存在
    // if (!is_directory(git_dir_abs) && mkdir_in_gitdir(git_dir_abs)){
    //     debug_log("Failed to create trustchain directory111\n");
    // }else{
    //     debug_log("Successfully created trustchain directory\n");
    // }
    
    // 确保contri_block_path的目录存在
    if (safe_create_leading_directories_const(contri_block_path) != SCLD_OK) {
        // debug_log("Failed to create trustchain directory\n");
        free(contri_block_path);
        return -1;
    }
    
    FILE *fp = fopen(contri_block_path, "a+");
    if (!fp) {
        // debug_log("Failed to open contri_block_path\n");
        free(contri_block_path);
        // die("Failed to open contri_block_path\n");
        return -1;
    }
    fwrite(contri_block->buf, 1, contri_block->len, fp);
    fclose(fp);
    free(contri_block_path);


    // 确保refs/trustchain/目录存在
    // if (safe_create_leading_directories_const(hash_path) != SCLD_OK) {
    //     debug_log("Failed to create refs directory\n");
    //     free(hash_path);
    //     return -1;
    // }

    FILE *fp_hash = fopen(hash_path, "w");
    if (!fp_hash) {
        // debug_log("Failed to open hash_path\n");
        free(hash_path);
        return -1;
    }
    fwrite(hex_hash, 1, strlen(hex_hash), fp_hash);
    fclose(fp_hash);
    free(hash_path);
    free(git_dir_abs);
    return 0;
}

int verify_and_store_contri_block(struct strbuf *contri_block, unsigned char hash[32])
{
    //解析contri_block
    json_t *json_obj = json_loads(contri_block->buf, 0, NULL);
    if (!json_obj) {
        return -1;
    }

    json_t *parent_hash = json_object_get(json_obj, "parent_hash");
    const char *parent_hash_value = json_string_value(parent_hash);
    // debug_log("parent_hash_value = %s\n", parent_hash_value);
    json_t *op = json_object_get(json_obj, "op");
    const char *op_value = json_string_value(op);
    // debug_log("op_value = %s\n", op_value);
    json_t *op_key = json_object_get(json_obj, "op_key");
    const char *op_key_value = json_string_value(op_key);
    // debug_log("op_key_value = %s\n", op_key_value);
    json_t *commit_hash = json_object_get(json_obj, "commit_hash");
    const char *commit_hash_value = json_string_value(commit_hash);
    // debug_log("commit_hash_value = %s\n", commit_hash_value);
    json_t *tee_time = json_object_get(json_obj, "tee_time");
    const char *tee_time_value = json_string_value(tee_time);
    // debug_log("tee_time_value = %s\n", tee_time_value);
    json_t *tee_sig = json_object_get(json_obj, "tee_sig");
    const char *tee_sig_hex = json_string_value(tee_sig);
    // debug_log("tee_sig_hex = %s\n", tee_sig_hex);
    

    if (parent_hash_value == NULL || op_value == NULL || op_key_value == NULL || commit_hash_value == NULL || tee_time_value == NULL || tee_sig_hex == NULL) {
        return -1;
    }

    unsigned char tee_sig_binary[256];   
    if (hex_to_bytes(tee_sig_binary, tee_sig_hex, 256)) {
        die("hex_to_bytes failed\n");
        return -1;
    }
    // debug_log("tee_sig_binary = %s\n", tee_sig_binary);
    //将parent_hash，op，commit_hash，op_key，tee_time，tee_sig拼接成一个字符串
    char *msg = xstrfmt("%s%s%s%s%s", parent_hash_value, op_value, commit_hash_value, op_key_value, tee_time_value);
    // debug_log("parent_hash,op,commit_hash,op_key,tee_time,tee_sig 拼接的字符串 msg = %s\n", msg);


    //===========验证tee_sig===============
    //获取TRUSTCHAIN服务的teekey
	// char teekey_path[PATH_MAX];
	// snprintf(teekey_path, sizeof(teekey_path), "%s/trustchain/TEE_KEY.pem", get_git_dir());
    // EVP_PKEY *teekey_pub = load_public_key_from_file(teekey_path);
    // if (!teekey_pub) {
    //     die("Failed to load pub key from teekey str\n");
    //     return -1;
    // }
    // //用公钥验证签名 并返回哈希
    // if (!trustchain_verify_signature_return_hash(msg, teekey_pub, tee_sig_binary, strlen(tee_sig_binary), hash)) {
    //     die("reverify_contri_block: FAILED\n");
    //     return -1;
    // }
    // EVP_PKEY_free(teekey_pub);
    //===========验证tee_sig 结束===============

    //=============将contri_block和hash存储到仓库中=============
    // char *hex_hash = binary_to_hex(hash, 32);
    char *hex_hash = "ec2b3ee7ad1d552c4508e025a2d5ad778290abf9";
    if (store_contri_block_to_repo(contri_block, hex_hash)){
        // debug_log("store contri_block into repo error\n");
    }
    //=============将contri_block和hash存储到仓库中 结束=============

    //=============将contri_block存储到数据库中=============
    if (insert_contri_block_to_db(parent_hash_value, op_value, op_key_value, commit_hash_value, tee_time_value, tee_sig_hex) < 0){
        // debug_log("insert contri_block into db error\n");
    }
    //=============将contri_block存储到数据库中 结束=============


    json_decref(json_obj);
    free(msg);
    return 0;
}


// 插入贡献区块数据到contri_blocks表
int insert_contri_block_to_db(
    const char *parent_hash,
    const char *op,
    const char *op_key,
    const char *commit_hash,
    const char *tee_time,
    const char *tee_sig
) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    
    char query[4096]; // 足够大的缓冲区存储查询语句
    
    // 初始化MySQL连接
    conn = mysql_init(NULL);
    
    if (conn == NULL) {
        // debug_log("mysql_init() failed\n");
        return -1;
    }
    
    // 连接到数据库
    if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, NULL, 0) == NULL) {
        // debug_log("mysql_real_connect() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }
    
    // 构建插入语句
    snprintf(query, sizeof(query), 
        "INSERT INTO contri_blocks ("
        "parent_hash, op, op_key, commit_hash, tee_time, tee_sig"
        ") VALUES ("
        "'%s', '%s', '%s', '%s', '%s', '%s')",
        parent_hash, op, op_key, commit_hash, tee_time, tee_sig);
    
    // 执行查询
    if (mysql_query(conn, query)) {
        // debug_log("mysql_query() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }
    
    // 获取受影响的行数
    int affected_rows = mysql_affected_rows(conn);
    
    // 关闭连接
    mysql_close(conn);
    
    return affected_rows;
}

