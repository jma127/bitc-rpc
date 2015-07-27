#ifndef __RPC_METHODS_H__
#define __RPC_METHODS_H__

#include <jansson.h>

#include "util.h"

struct method_invocation_data {
  json_t *params_data;
};

// Function pointer to an RPC method handler.
//
// It is guaranteed that the second and third parameters point to a NULL value.
// Implementations must set exactly one to a non-NULL value, depending on
// whether or not execution was successful.
typedef void (*method_fn)(struct method_invocation_data *,  // params, etc.
                          json_t **,                        // result object
                          json_t **);                       // error object

method_fn get_rpc_method_fn(const char *name);
int rpc_methods_init(void);
void rpc_methods_exit(void);

#endif /* __RPC_METHODS_H__ */
