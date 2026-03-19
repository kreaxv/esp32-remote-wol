#pragma once

#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize NVS, TCP/IP stack and Wi-Fi driver (common path for AP/STA).
 */
esp_err_t improv_wifi_init(void);

/**
 * Start Improv-style provisioning by starting STA and connecting to given credentials.
 */
esp_err_t improv_wifi_provision(const char *ssid, const char *password, wifi_auth_mode_t authmode);

/**
 * Start an AP for setup with SSID/password.
 */
esp_err_t improv_wifi_start_ap(const char *ssid, const char *password, uint8_t channel, wifi_auth_mode_t authmode);

/**
 * Stop Wi-Fi completely.
 */
esp_err_t improv_wifi_stop(void);

#ifdef __cplusplus
}
#endif
