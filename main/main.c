/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"
#include "esp_check.h"
#include "improv_wifi.h"
#include <time.h>
#include <sys/time.h>
#if !CONFIG_IDF_TARGET_LINUX
#include <esp_wifi.h>
#include <esp_system.h>
#include "nvs_flash.h"
#include "esp_eth.h"
#endif  // !CONFIG_IDF_TARGET_LINUX

// From MQTT SSL
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_partition.h"
#include "esp_log.h"
#include "mqtt_client.h"
#include "esp_ota_ops.h"

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN  (64)

#if CONFIG_BROKER_CERTIFICATE_OVERRIDDEN == 1
static const uint8_t mqtt_eclipseprojects_io_pem_start[]  = "-----BEGIN CERTIFICATE-----\n" CONFIG_BROKER_CERTIFICATE_OVERRIDE "\n-----END CERTIFICATE-----";
#else
extern const uint8_t mqtt_eclipseprojects_io_pem_start[]   asm("_binary_mqtt_hivemq_cloud_pem_start");
#endif
extern const uint8_t mqtt_eclipseprojects_io_pem_end[]   asm("_binary_mqtt_hivemq_cloud_pem_end");

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "wol";

#define USE_HASHED_ID 1

// ----------------------- MQTT -----------------------
// This value are moved into the Kconfig file
// static const char* MQTT_HOST = "724f4005ddac40d5a4d1586443333e56.s1.eu.hivemq.cloud";
// static const uint16_t MQTT_PORT = 8883;
// static const char* MQTT_USER = "client";
// static const char* MQTT_PASS = "BJa938Cguzds4fx";

static uint8_t mac[6];
static char esp32mac[65];
static char topicCmd[80];
static char macColon[18];

static char page[1024];
static char clientId[40];

// --------------------- SHA-256 ---------------------
static void sha256Hex(const char* input, char* output) {
  uint8_t hash[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mbedtls_md(info, (const unsigned char*)input, strlen(input), hash) != 0) {
    output[0] = 0;
    return;
  }
  for (int i = 0; i < 32; i++) sprintf(output + i * 2, "%02x", hash[i]);
  output[64] = 0;
}

// MQTT
// --------------------- Hex Parsing ---------------------
static uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0;
}

#include <lwip/sockets.h>
#include <arpa/inet.h>

// --------------------- WOL ---------------------
static esp_err_t parse_mac_string(const char *mac_str, uint8_t *mac)
{
    if (!mac_str || !mac) {
        return ESP_ERR_INVALID_ARG;
    }

    int len = strlen(mac_str);
    if (len != 17 && len != 12) {
        return ESP_ERR_INVALID_ARG;
    }

    int idx = 0;
    for (int i = 0; i < len && idx < 6; i++) {
        if (mac_str[i] == ':' || mac_str[i] == '-' || mac_str[i] == '.') {
            continue;
        }
        if (i + 1 >= len) {
            return ESP_ERR_INVALID_ARG;
        }

        mac[idx++] = (hexNibble(mac_str[i]) << 4) | hexNibble(mac_str[i + 1]);
        i++;
    }

    if (idx != 6) {
        return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
}

static esp_err_t send_wol(const char *mac_str)
{
    uint8_t target_mac[6];
    if (parse_mac_string(mac_str, target_mac) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid MAC format: %s", mac_str);
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t packet[102];
    memset(packet, 0xFF, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(&packet[6 + i * 6], target_mac, 6);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket create failed: %d", sock);
        return ESP_FAIL;
    }

    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
        .sin_addr.s_addr = inet_addr("255.255.255.255"),
    };

    ssize_t written = sendto(sock, packet, sizeof(packet), 0,
                             (struct sockaddr *)&dest, sizeof(dest));
    close(sock);

    if (written < 0) {
        ESP_LOGE(TAG, "sendto failed: %d", written);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "WOL magic packet sent to %s", mac_str);
    return ESP_OK;
}


/* An HTTP GET handler */
static esp_err_t mac_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN], dec_param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN] = {0};
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "wol", param, sizeof(param)) == ESP_OK) {
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "WOL request => MAC=%s", dec_param);
                if (send_wol(dec_param) == ESP_OK) {
                    ESP_LOGI(TAG, "WOL packet sent for %s", dec_param);
                } else {
                    ESP_LOGE(TAG, "WOL send failed for %s", dec_param);
                }
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t mac_uri = {
    .uri       = "/mac",
    .method    = HTTP_GET,
    .handler   = mac_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = page
};

/* An HTTP_ANY handler */
static esp_err_t any_handler(httpd_req_t *req)
{
    /* Send response with body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t any = {
    .uri       = "/",
    .method    = HTTP_ANY,
    .handler   = any_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = page
};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl and /mac URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /mac is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket or keeps it open. This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/mac", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/mac URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    } else if (strcmp("/echo", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "404 error message - Bad URI");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0') {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /mac URI");
        httpd_unregister_uri(req->handle, "/mac");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else {
        ESP_LOGI(TAG, "Registering /mac URI");
        httpd_register_uri_handler(req->handle, &mac_uri);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t ctrl = {
    .uri       = "/ctrl",
    .method    = HTTP_PUT,
    .handler   = ctrl_put_handler,
    .user_ctx  = NULL
};

#if CONFIG_EXAMPLE_ENABLE_SSE_HANDLER
/* An HTTP GET handler for SSE */
static esp_err_t sse_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/event-stream");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");

    char sse_data[64];
    while (1) {
        struct timeval tv;
        gettimeofday(&tv, NULL); // Get the current time
        int64_t time_since_boot = tv.tv_sec; // Time since boot in seconds
        esp_err_t err;
        int len = snprintf(sse_data, sizeof(sse_data), "data: Time since boot: %" PRIi64 " seconds\n\n", time_since_boot);
        if ((err = httpd_resp_send_chunk(req, sse_data, len)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send sse data (returned %02X)", err);
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000)); // Send data every second
    }

    httpd_resp_send_chunk(req, NULL, 0); // End response
    return ESP_OK;
}

static const httpd_uri_t sse = {
    .uri       = "/sse",
    .method    = HTTP_GET,
    .handler   = sse_handler,
    .user_ctx  = NULL
};
#endif // CONFIG_EXAMPLE_ENABLE_SSE_HANDLER

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
#if CONFIG_IDF_TARGET_LINUX
    // Setting port as 8001 when building for Linux. Port 80 can be used only by a privileged user in linux.
    // So when a unprivileged user tries to run the application, it throws bind error and the server is not started.
    // Port 8001 can be used by an unprivileged user as well. So the application will not throw bind error and the
    // server will be started.
    config.server_port = 8001;
#endif // !CONFIG_IDF_TARGET_LINUX
    config.lru_purge_enable = true;

    // Save static webpage for the server
    // Add customize HTML page
    snprintf(page,sizeof(page),
    "<!DOCTYPE html><html lang=\"en\"><head>"
    "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">"
    "<title>ESP32 Device</title>"
    "<style>"
    "body{margin:0;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;"
    "background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif}"
    "h2{margin:.5rem 0;font-size:1.2rem;color:#8b949e}"
    "p.mac{font-family:monospace;font-size:2rem;background:#196f3d;color:#fff;padding:.5rem 1rem;"
    "border-radius:12px;border:1px solid #145a2e;margin:.25rem 0}"
    "p.note,a{font-size:.9rem;color:#8b949e;margin-top:.5rem}"
    "a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}"
    "</style></head><body>"
    "<h2>ESP32 MAC Address</h2>"
    "<p class=\"mac\">%s</p>"
    "<p class=\"note\">Copy this MAC for WOL site</p>"
    "<a href=\"https://wol.kreaxv.top/\" target=\"_blank\">wol.kreaxv.top</a>"
    "</body></html>",
    macColon
    );

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &mac_uri);
        httpd_register_uri_handler(server, &ctrl);
        httpd_register_uri_handler(server, &any);
#if CONFIG_EXAMPLE_ENABLE_SSE_HANDLER
        httpd_register_uri_handler(server, &sse); // Register SSE handler
#endif
#if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
#endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

#if !CONFIG_IDF_TARGET_LINUX
static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}
#endif // !CONFIG_IDF_TARGET_LINUX


// MQTT
//
// Note: this function is for testing purposes only publishing part of the active partition
//       (to be checked against the original binary)
//
// static void send_binary(esp_mqtt_client_handle_t client)
// {
//     esp_partition_mmap_handle_t out_handle;
//     const void *binary_address;
//     const esp_partition_t *partition = esp_ota_get_running_partition();
//     esp_partition_mmap(partition, 0, partition->size, ESP_PARTITION_MMAP_DATA, &binary_address, &out_handle);
//     // sending only the configured portion of the partition (if it's less than the partition size)
//     int binary_size = MIN(CONFIG_BROKER_BIN_SIZE_TO_SEND, partition->size);
//     int msg_id = esp_mqtt_client_publish(client, "/topic/binary", binary_address, binary_size, 0, 0);
//     ESP_LOGI(TAG, "binary sent with msg_id=%d", msg_id);
// }

/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 *
 * @param handler_args user data registered to the event.
 * @param base Event base for the handler(always MQTT Base in this example).
 * @param event_id The id for the received event.
 * @param event_data The data for the event, esp_mqtt_event_handle_t.
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32, base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id = 0;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        msg_id = esp_mqtt_client_subscribe(client, topicCmd, 1);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;

    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        // The actual client credentials only are for reading access
        // msg_id = esp_mqtt_client_publish(client, "wol/3772dbfe6966183b2e5ae59f446b02ce733072a38f3accbcfee2ed91ebb3a2b6", "data", 0, 1, 0);
        // ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
        printf("DATA=%.*s\r\n", event->data_len, event->data);
        char dec_param[20];
        snprintf(dec_param, sizeof(dec_param), "%.*s", event->data_len, event->data);
        if (send_wol(dec_param) == ESP_OK) {
                    ESP_LOGI(TAG, "WOL packet sent for %s", dec_param);
                } else {
                    ESP_LOGE(TAG, "WOL send failed for %s", dec_param);
                }
        break;
    case MQTT_EVENT_BEFORE_CONNECT: 
        ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT");

        esp_mqtt_client_config_t config = {
            .broker = {
                .address = {
                    .uri = CONFIG_BROKER_URI, // mqtts://broker:8883
                },
                .verification = {
                    .certificate = (const char *)mqtt_eclipseprojects_io_pem_start,
                    // .skip_cert_common_name_check = true,
                    // .alpn_protos = NULL, // or {"mqtt", NULL} for ALPN if required
                },
            },
            .credentials = {
                .client_id = clientId,
                .username = CONFIG_BROKER_MQTT_USER,
                .authentication = {
                    .password = CONFIG_BROKER_MQTT_PASS,
                }
            },
            // .network.transport = MQTT_TRANSPORT_OVER_SSL,
            .session = {
                .protocol_ver = MQTT_PROTOCOL_V_3_1_1, // V_3_1_1 or V_5 based on broker
            },
        };

        esp_err_t err = esp_mqtt_set_config(client, &config);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_mqtt_set_config failed: %s", esp_err_to_name(err));
        } 
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            ESP_LOGI(TAG, "Last error code reported from esp-tls: 0x%x", event->error_handle->esp_tls_last_esp_err);
            ESP_LOGI(TAG, "Last tls stack error number: 0x%x", event->error_handle->esp_tls_stack_err);
            ESP_LOGI(TAG, "Last captured errno : %d (%s)",  event->error_handle->esp_transport_sock_errno,
                     strerror(event->error_handle->esp_transport_sock_errno));
        } else if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
            ESP_LOGI(TAG, "Connection refused error: 0x%x", event->error_handle->connect_return_code);
        } else {
            ESP_LOGW(TAG, "Unknown error type: 0x%x", event->error_handle->error_type);
        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

static void mqtt_app_start(void)
{
    snprintf(clientId, sizeof(clientId), "wol-%.*s", 16, esp32mac);

    ESP_LOGI(TAG, "ClientID: %s", clientId);

    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker = {
            .address.uri = CONFIG_BROKER_URI,
            .verification.certificate = (const char *)mqtt_eclipseprojects_io_pem_start,
            // .verification.skip_cert_common_name_check = true,
        },
        .credentials = {
            .client_id = clientId,
            .username = CONFIG_BROKER_MQTT_USER,
            .authentication = {
                .password = CONFIG_BROKER_MQTT_PASS,
            }
        },
    };

    ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
}

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_LOGI(TAG, "[APP] Startup..");
    ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());

    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("esp-tls", ESP_LOG_VERBOSE);
    esp_log_level_set("mqtt_client", ESP_LOG_VERBOSE);
    esp_log_level_set("mqtt_example", ESP_LOG_VERBOSE);
    esp_log_level_set("transport_base", ESP_LOG_VERBOSE);
    esp_log_level_set("transport", ESP_LOG_VERBOSE);
    esp_log_level_set("outbox", ESP_LOG_VERBOSE);

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Optional: use improv_wifi component for explicit provisioning instead of example_connect.
     * Uncomment and set your own SSID/PASS if you want library-driven Wi-Fi connect.
     */
    // ESP_ERROR_CHECK(improv_wifi_init());
    // ESP_ERROR_CHECK(improv_wifi_provision("YOUR_SSID", "YOUR_PASSWORD", WIFI_AUTH_WPA2_PSK));

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#if !CONFIG_IDF_TARGET_LINUX
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET
#endif // !CONFIG_IDF_TARGET_LINUX

    // Obtain MAC address
    esp_err_t err = esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "MAC Address: %02x:%02x:%02x:%02x:%02x:%02x", 
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        ESP_LOGE(TAG, "Failed to get MAC address");
    }

    // Make a copy from MAC
    char macHex[13];
    snprintf(macHex, sizeof(macHex), "%02x%02x%02x%02x%02x%02x",
           mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    if (USE_HASHED_ID) sha256Hex(macHex, esp32mac);
    else strncpy(esp32mac, macHex, sizeof(esp32mac));

    // ESP_LOGI(TAG, "MAC Address from ESP32MAC: %s", esp32mac);

    // MQTT tag
    snprintf(topicCmd, sizeof(topicCmd), "wol/%s", esp32mac);

    // Store MAC address in a char array
    snprintf(macColon, sizeof(macColon), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    /* Start the server for the first time */
    server = start_webserver();

    // ESP_LOGI(TAG, "BROKER: %s", CONFIG_BROKER_URI);

    mqtt_app_start();

    while (server) {
        sleep(5);
    }
}
