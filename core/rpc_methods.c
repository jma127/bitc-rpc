#include <string.h>

#include "bitc.h"
#include "block-store.h"
#include "hashtable.h"
#include "rpc_methods.h"
#include "util.h"

#define LGPFX "RPCIMPL:"


static struct hashtable *method_handler_ht;


/*
 *-------------------------------------------------------------------------
 *
 * sanity_check --
 *
 *-------------------------------------------------------------------------
 */

static int sanity_check(struct method_invocation_data *mi_data,
                        json_t **error) {

    if (btc->blockStore == NULL) {
        Log(LGPFX" %s: blockstore is null\n", __FUNCTION__);
        *error = json_object();
        json_object_set_new(*error, "name", json_string("InvalidBlockstoreState"));
        return 1;
    }
    return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_get_block_count --
 *
 *-------------------------------------------------------------------------
 */

static void rpc_get_block_count(struct method_invocation_data *mi_data,
                         json_t **result,
                         json_t **error) {
    if (sanity_check(mi_data, error)) {
        return;
    }

    *result = json_object();
    json_object_set_new(*result, "result",
                        json_integer(blockstore_get_height(btc->blockStore)));
}


/*
 *-------------------------------------------------------------------------
 *
 * get_rpc_method_fn --
 *
 *-------------------------------------------------------------------------
 */

method_fn get_rpc_method_fn(const char *name) {
    method_fn fn;

    ASSERT(method_handler_ht != NULL);

    if (!hashtable_lookup(method_handler_ht, name, strlen(name),
                          (void **) &fn)) {
        return NULL;
    }
    return fn;
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_methods_init --
 *
 *-------------------------------------------------------------------------
 */

int rpc_methods_init(void) {
    method_handler_ht = hashtable_create();
    if (method_handler_ht == NULL) {
        return 1;
    }

    #define RPC_REGISTER(name, fn)  \
        do {  \
            hashtable_insert(method_handler_ht, #name, strlen(#name), fn);  \
        } while (0);

    RPC_REGISTER(getblockcount, rpc_get_block_count);

    #undef RPC_REGISTER

    return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_methods_exit --
 *
 *-------------------------------------------------------------------------
 */

void rpc_methods_exit(void) {
}
