/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: error capture, secret wrapping and statement reset for wallet SQLite. */

#include "wallet_sqlite_internal.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include <string.h>

struct zcl_result wsql_fail(struct wallet_sqlite *ws, struct zcl_result r)
{
    if (ws && !r.ok) {
        size_t n = sizeof(ws->last_error) - 1;
        strncpy(ws->last_error, r.message, n);
        ws->last_error[n] = '\0';
    }
    return r;
}

struct zcl_result wsql_encrypt_secret(const uint8_t *plain, size_t plen,
                                      uint8_t **out, size_t *out_len)
{
    if (!out || !out_len)
        return ZCL_ERR(WSQL_NULL_ARG, "Sapling secret output is NULL");
    *out = NULL;
    *out_len = 0;
    if ((!plain && plen > 0) || plen > SIZE_MAX - WKS_HEADER_LEN)
        return ZCL_ERR(WSQL_NULL_ARG, "Sapling secret input is invalid");
    char pass[WLK_MAX_PASS + 1] = {0};
    if (!wallet_lock_copy_passphrase(pass, sizeof(pass))) {
        memory_cleanse(pass, sizeof(pass));
        if (wallet_lock_encrypted_at_rest())
            return ZCL_ERR(WLK_LOCKED,
                           "Sapling secret write refused: encrypted wallet is locked");
        return ZCL_OK; /* Existing plaintext-wallet compatibility. */
    }

    size_t cap = wks_envelope_size(plen);
    uint8_t *buf = zcl_malloc(cap, "wallet_encrypt_buf");
    if (!buf) {
        memory_cleanse(pass, sizeof(pass));
        return ZCL_ERR(WSQL_WRITE_FAIL,
                       "Sapling secret write refused: encryption allocation failed");
    }
    size_t elen = 0;
    bool encrypted = wks_encrypt(plain, plen, pass, wks_default_iterations(),
                                  buf, cap, &elen);
    memory_cleanse(pass, sizeof(pass));
    if (!encrypted) {
        memory_cleanse(buf, cap);
        free(buf);
        return ZCL_ERR(WSQL_WRITE_FAIL,
                       "Sapling secret write refused: encryption failed");
    }
    wallet_lock_note_encrypted_at_rest();
    *out = buf;
    *out_len = elen;
    return ZCL_OK;
}

void wallet_sqlite_reset_all_statements(struct wallet_sqlite *ws)
{
    if (!ws)
        return;
    if (ws->stmt_key_write) sqlite3_reset(ws->stmt_key_write);
    if (ws->stmt_key_read) sqlite3_reset(ws->stmt_key_read);
    if (ws->stmt_key_read_one) sqlite3_reset(ws->stmt_key_read_one);
    if (ws->stmt_key_delete) sqlite3_reset(ws->stmt_key_delete);
    if (ws->stmt_keypool_write) sqlite3_reset(ws->stmt_keypool_write);
    if (ws->stmt_keypool_read) sqlite3_reset(ws->stmt_keypool_read);
    if (ws->stmt_keypool_clear) sqlite3_reset(ws->stmt_keypool_clear);
    if (ws->stmt_tx_write) sqlite3_reset(ws->stmt_tx_write);
    if (ws->stmt_tx_read) sqlite3_reset(ws->stmt_tx_read);
    if (ws->stmt_seed_write) sqlite3_reset(ws->stmt_seed_write);
    if (ws->stmt_seed_read) sqlite3_reset(ws->stmt_seed_read);
    if (ws->stmt_zkey_write) sqlite3_reset(ws->stmt_zkey_write);
    if (ws->stmt_zkey_read) sqlite3_reset(ws->stmt_zkey_read);
    if (ws->stmt_script_write) sqlite3_reset(ws->stmt_script_write);
    if (ws->stmt_script_read) sqlite3_reset(ws->stmt_script_read);
    if (ws->stmt_watch_write) sqlite3_reset(ws->stmt_watch_write);
    if (ws->stmt_watch_read) sqlite3_reset(ws->stmt_watch_read);
    if (ws->stmt_best_block_write) sqlite3_reset(ws->stmt_best_block_write);
    if (ws->stmt_best_block_read) sqlite3_reset(ws->stmt_best_block_read);
    if (ws->stmt_scan_height_write) sqlite3_reset(ws->stmt_scan_height_write);
    if (ws->stmt_scan_height_read) sqlite3_reset(ws->stmt_scan_height_read);
}
