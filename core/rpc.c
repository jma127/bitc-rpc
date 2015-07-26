#include <http_parser.h>
#include <jansson.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "util.h"
#include "netasync.h"
#include "config.h"
#include "bitc.h"
#include "rpc.h"
#include "rpc_methods.h"
#include "buff.h"
#include "hashtable.h"

#define LGPFX "RPC:"
#define RPC_RECV_HEADER_BLOCK_SIZE (4)
#define RPC_RECV_BLOCK_SIZE (50)


struct rpc_client_data {
    struct buff *buf;
    http_parser *parser;
    http_parser_settings *parser_settings;
    int64_t offset;
};


static struct netasync_socket *sock;
static const char *auth_str;  // i would mlock this, but since it's already
                              // on disk...


/*
 *-------------------------------------------------------------------------
 *
 * -- http_body_handler
 *
 *-------------------------------------------------------------------------
 */

static int
http_body_handler(http_parser *parser, const char *at, size_t length) {
    struct rpc_client_data *data;

    data = (struct rpc_client_data *) parser->data;
    if (data->offset < 0) {
        data->offset = ((void *) at) - buff_base(data->buf);
        if (data->offset < 0 || data->offset >= buff_curlen(data->buf)) {
            return 1;
        }
    }
    return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_client_data_alloc --
 *
 *-------------------------------------------------------------------------
 */

static struct rpc_client_data *
rpc_client_data_alloc(void)
{
    struct rpc_client_data *data;

    data = safe_malloc(sizeof *data);
    data->buf = buff_alloc();
    data->parser = safe_malloc(sizeof *data->parser);
    http_parser_init(data->parser, HTTP_REQUEST);
    data->parser->data = data;
    data->parser_settings = safe_malloc(sizeof *data->parser_settings);
    http_parser_settings_init(data->parser_settings);
    data->parser_settings->on_body = http_body_handler;
    data->offset = -1;

    return data;
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_client_data_free --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_client_data_free(struct rpc_client_data *data)
{
    ASSERT(data);

    buff_free(data->buf);
    free(data->parser);
    free(data->parser_settings);
    free(data);
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_send_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_send_cb(struct netasync_socket *socket,
            void                   *data,
            int                    err)
{
    Log(LGPFX" %s:%u connection finished\n", __FUNCTION__, __LINE__);
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_send_error_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_send_error_cb(struct netasync_socket *socket,
                  void                   *data,
                  int                    err)
{
    Log(LGPFX" %s:%u send errored (code %d)\n", __FUNCTION__, __LINE__, err);
    rpc_send_cb(socket, data, err);
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_error_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_error_cb(struct netasync_socket *socket,
             void                   *data,
             int                    err)
{
    Log(LGPFX" %s:%u errored (code %d)\n", __FUNCTION__, __LINE__, err);
    netasync_close(socket);
    if (data != NULL) {
        rpc_client_data_free(data);
    }
}


/*
 *-------------------------------------------------------------------------
 *
 * -- send_response
 *
 *-------------------------------------------------------------------------
 */
static void
send_response(struct netasync_socket *socket,
              int http_status,
              json_t *result,
              json_t *error,
              json_t *id) {
    struct buff *resp_str;
    char *obj_str;
    json_t *object;
    char szbuf[sizeof(size_t) * 5];

    resp_str = buff_alloc();
    netasync_set_errorhandler(socket, rpc_send_error_cb, resp_str);

    if (http_status == 401) {
        buff_append_str(resp_str, "HTTP/1.1 401 Unauthorized\r\n"
                                  "WWW-Authenticate: Basic realm=\"bitc\"\r\n"
                                  "Content-Length: 22\r\n"
                                  "\r\n"
                                  "Unauthorized access.\r\n");
        goto exit;
    }

    ASSERT(http_status == 200);

    object = json_object();
    if (result == NULL) {
        json_object_set_new(object, "result", result = json_null());
    } else {
        json_object_set(object, "result", result);
    }
    if (error == NULL) {
        json_object_set_new(object, "error", error = json_null());
    } else {
        json_object_set(object, "error", error);
    }
    if (id == NULL) {
        json_object_set_new(object, "id", id = json_null());
    } else {
        json_object_set(object, "id", id);
    }

    ASSERT(json_is_null(result) != json_is_null(error));

    obj_str = json_dumps(object, 0);
    buff_append_str(resp_str, "HTTP/1.1 200 OK\r\n"
                              "Content-Type: text/json\r\n"
                              "Content-Length: ");
    sprintf(szbuf, "%lu", strlen(obj_str));
    buff_append_str(resp_str, szbuf);
    buff_append_str(resp_str, "\r\n\r\n");
    buff_append_str(resp_str, obj_str);

    free(obj_str);
    json_decref(object);

exit:

    netasync_send(socket, buff_base(resp_str), buff_curlen(resp_str),
                  rpc_send_cb, resp_str);
    free(resp_str);  // free the container without freeing the underlying byte
                     // buffer, which is freed by netasync_send().
}


/*
 *-------------------------------------------------------------------------
 *
 * -- rpc_process_request
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_process_request(struct netasync_socket *socket,
                    struct rpc_client_data *data)
{
    json_t *req_data, *result_data, *resp_error;
    json_t *method_data, *params_data, *id_data;  // borrowed
    json_error_t req_error;
    struct method_invocation_data mi_data;
    void *method_handler;
    int http_status;
    bool auth_failed;

    req_data = result_data = resp_error = NULL;
    http_status = 200;
    auth_failed = 0;
    buff_push_back(data->buf, '\0');

    if (data->offset == 0) {
        auth_failed = 1;
    } else {
        ((char *) buff_base(data->buf))[data->offset - 1] = '\0';
        // sue me
        auth_failed = strstr(buff_base(data->buf), auth_str) == NULL;
    }
    if (auth_failed) {
        Log(LGPFX" %s:%u Request not authenticated\n", __FUNCTION__, __LINE__);
        http_status = 401;
        goto exit;
    }

    req_data = json_loads(buff_base(data->buf) + data->offset, 0, &req_error);
    if (req_data == NULL) {
        Log(LGPFX" %s:%u Invalid JSON in request: %s\n",
            __FUNCTION__, __LINE__, req_error.text);
        resp_error = json_object();
        json_object_set_new(resp_error, "name", json_string("InvalidJSON"));
        goto exit;
    }

    method_data = json_object_get(req_data, "method");
    params_data = json_object_get(req_data, "params");
    id_data = json_object_get(req_data, "id");

    if (id_data == NULL) {
        Log(LGPFX" %s:%u No id provided in request\n",
            __FUNCTION__, __LINE__);
        resp_error = json_object();
        json_object_set_new(resp_error, "name", json_string("NoIDProvided"));
        goto exit;
    }

    if (method_data == NULL || params_data == NULL ||
        !json_is_string(method_data) || !json_is_array(params_data)) {
        Log(LGPFX" %s:%u No method (string) or parameters (array) "
            "provided in request\n", __FUNCTION__, __LINE__);
        resp_error = json_object();
        json_object_set_new(resp_error, "name",
                            json_string("NoMethodOrParamsProvided"));
        goto exit;
    }

    method_handler = get_rpc_method_fn(json_string_value(method_data));
    if (method_handler == NULL) {
        Log(LGPFX" %s:%u Invalid method %s\n", __FUNCTION__, __LINE__,
            json_string_value(method_data));
        resp_error = json_object();
        json_object_set_new(resp_error, "name",
                            json_string("InvalidMethod"));
        goto exit;
    }

    ASSERT(method_handler != NULL);
    ASSERT(params_data != NULL);
    ASSERT(result_data == NULL);
    ASSERT(resp_error == NULL);

    Log(LGPFX" %s:%u Executing %s\n", __FUNCTION__, __LINE__,
        json_string_value(method_data));
    mi_data.params_data = params_data;
    ((method_fn) method_handler)(&mi_data, &result_data, &resp_error);

exit:
    if (http_status != 200) {
        Log(LGPFX" %s:%u Sending HTTP error response\n", __FUNCTION__, __LINE__);
        send_response(socket, http_status, NULL, NULL, NULL);
    } else if (resp_error == NULL) {
        ASSERT(result_data != NULL);
        Log(LGPFX" %s:%u Sending response\n", __FUNCTION__, __LINE__);
        send_response(socket, http_status, result_data, NULL, id_data);
        json_decref(result_data);
    } else {
        ASSERT(result_data == NULL);
        Log(LGPFX" %s:%u Sending error response\n", __FUNCTION__, __LINE__);
        send_response(socket, http_status, NULL, resp_error, id_data);
        json_decref(resp_error);
    }

    if (req_data != NULL) {
        json_decref(req_data);
    }
    rpc_client_data_free(data);
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_receive_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_receive_cb(struct netasync_socket *socket,
               void                   *start,
               size_t                 len,
               void                   *cdata)
{
    struct rpc_client_data *data;
    size_t nparsed;
    int64_t next_read_size;

    data = (struct rpc_client_data *) cdata;
    buff_skip(data->buf, len);
    nparsed = http_parser_execute(data->parser, data->parser_settings, start,
                                  len);
    if (data->parser->upgrade) {
        Log(LGPFX" %s:%u -- got an Upgrade request\n", __FUNCTION__, __LINE__);
        rpc_error_cb(socket, data, 0);
        return;
    } else if (nparsed != len) {
        Log(LGPFX" %s:%u -- error parsing HTTP request: %d (%s: %s)\n",
            __FUNCTION__, __LINE__,
            data->parser->http_errno,
            http_errno_name(data->parser->http_errno),
            http_errno_description(data->parser->http_errno));
        rpc_error_cb(socket, data, 0);
        return;
    }

    next_read_size
      = data->offset < 0
        ? RPC_RECV_HEADER_BLOCK_SIZE
        : MIN(RPC_RECV_BLOCK_SIZE, data->parser->content_length);
    if (next_read_size > 0) {  // Continue reading
        buff_resize(data->buf, buff_curlen(data->buf) + next_read_size);
        netasync_receive(socket, buff_curptr(data->buf), next_read_size, 0,
                         rpc_receive_cb, data);
    } else {  // rpc_process_request
        rpc_process_request(socket, data);
    }
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_accept_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_accept_cb(struct netasync_socket *socket,
              void                   *_data,
              int                     err)
{
   struct rpc_client_data *data;

   ASSERT(err == 0);

   Log(LGPFX" %s:%u -- got a connection.\n", __FUNCTION__, __LINE__);

   data = rpc_client_data_alloc();
   buff_resize(data->buf, RPC_RECV_HEADER_BLOCK_SIZE);

   netasync_set_errorhandler(socket, rpc_error_cb, data);
   netasync_receive(socket, buff_curptr(data->buf), RPC_RECV_HEADER_BLOCK_SIZE,
                    0, rpc_receive_cb, data);
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_exit --
 *
 *-------------------------------------------------------------------------
 */

void
rpc_exit(void)
{
   if (sock != NULL) {
      netasync_close(sock);
      sock = NULL;
   }
   if (auth_str != NULL) {
      free((void *) auth_str);
      auth_str = NULL;
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_init --
 *
 *-------------------------------------------------------------------------
 */

int
rpc_init(void)
{
   struct sockaddr_in addr;
   const char *auth_user, *auth_pass;
   char *tmpbuf, *biobuf;
   BIO *bmem, *b64;
   size_t b64len;
   int err;

   if (config_getbool(btc->config, 0, "rpc.enable") == 0) {
      Log(LGPFX" %s: rpc disabled\n", __FUNCTION__);
      return 0;
   }

   err = 0;
   auth_user = config_getstring(btc->config, "", "rpc.username");
   auth_pass = config_getstring(btc->config, "", "rpc.password");
   if (strlen(auth_pass) < 8) {
      Log(LGPFX" %s: rpc password either not set or too short\n", __FUNCTION__);
      err = 1;
   } else {
      tmpbuf = safe_malloc(strlen(auth_user) + strlen(auth_pass) + 5);
      sprintf(tmpbuf, "%s:%s", auth_user, auth_pass);

      b64 = BIO_new(BIO_f_base64());
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      bmem = BIO_new(BIO_s_mem());
      BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
      bmem = BIO_push(b64, bmem);
      BIO_write(bmem, tmpbuf, strlen(tmpbuf));
      BIO_flush(bmem);
      b64len = BIO_get_mem_data(bmem, &biobuf);

      tmpbuf = safe_realloc(tmpbuf, b64len + 10);
      sprintf(tmpbuf, "Basic ");
      strncpy(tmpbuf + 6, biobuf, b64len);
      tmpbuf[b64len + 6] = '\0';
      auth_str = tmpbuf;
      tmpbuf = NULL;

      BIO_free_all(bmem);
   }

   free((void *) auth_user);
   free((void *) auth_pass);
   if (err != 0) {
      return err;
   }

   sock = netasync_create();

   err = netasync_resolve("localhost", 9990, &addr);
   if (err != 0) {
      Log(LGPFX" failed to resolve: %s (%d)\n", strerror(err), err);
      return err;
   }
   err = netasync_bind(sock, &addr, rpc_accept_cb, NULL);
   if (err != 0) {
      Log(LGPFX" failed to bind: %s (%d)\n", strerror(err), err);
      return err;
   }
   Log(LGPFX" %s: listening on localhost:9990.\n", __FUNCTION__);

   return 0;
}
