/*
  ESPfuscate - ESP-IDF Example

  Description:
  Demonstrates ESPfuscate usage in ESP-IDF environment.

  Flow:
  - Connect to WiFi using obfuscated credentials
  - Fetch runtime data via HTTP
  - Encrypt and decrypt using RTobf

  Notes:
  - Uses ESP-IDF APIs (esp_http_client, cJSON)
  - No persistent storage

  Author: AndreaDV01
  Library: https://github.com/AndreaDV01/ESPfuscate
*/

#include <string.h>
#include <stdio.h>

extern "C" {
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_client.h"
#include "nvs_flash.h"

#include "cJSON.h"
}

#include "ESPfuscate.h"

// ==============================
// WiFi credentials (compile-time obfuscated)
// ==============================
auto WIFI_SSID = OBF("YOUR_WIFI_SSID");
auto WIFI_PASS = OBF("YOUR_WIFI_PASSWORD");

// ==============================
// Globals
// ==============================
static const char* TAG = "ESPfuscate_IDF_Easy";
static EventGroupHandle_t s_wifi_event_group = nullptr;
static constexpr int WIFI_CONNECTED_BIT = BIT0;
static constexpr int WIFI_FAIL_BIT = BIT1;
static constexpr int WIFI_MAX_RETRY = 20;
static int s_retry_num = 0;

ESPfuscate::RTobf RTO;

// ==============================
// Runtime payload
// ==============================
struct GeoPayload {
    char location[96];
};

// ==============================
// HTTP response buffer
// ==============================
struct HttpResponseBuffer {
    char data[256];
    size_t len = 0;
};

// ==============================
// WiFi event handler
// ==============================
static void wifi_event_handler(void*,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void* event_data) {

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retrying WiFi connection...");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        return;
    }

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        auto* event = static_cast<ip_event_got_ip_t*>(event_data);
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// ==============================
// Init NVS + WiFi
// ==============================
static esp_err_t init_nvs() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

static esp_err_t init_wifi() {
    ESP_ERROR_CHECK(esp_netif_init());
    //ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }
    esp_netif_create_default_wifi_sta();

    s_wifi_event_group = xEventGroupCreate();
    if (!s_wifi_event_group) return ESP_ERR_NO_MEM;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, nullptr));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_start());

    return ESP_OK;
}

// ==============================
// Connect WiFi using OBF()
// ==============================
static bool connect_wifi_obfuscated() {
    auto ssid = WIFI_SSID.decrypt_str();
    auto pass = WIFI_PASS.decrypt_str();

    wifi_config_t wifi_config = {};
    strlcpy(reinterpret_cast<char*>(wifi_config.sta.ssid), ssid.char_data(), sizeof(wifi_config.sta.ssid));
    strlcpy(reinterpret_cast<char*>(wifi_config.sta.password), pass.char_data(), sizeof(wifi_config.sta.password));
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    s_retry_num = 0;

    ESP_ERROR_CHECK(esp_wifi_connect());

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,
        pdFALSE,
        pdMS_TO_TICKS(15000));

    return (bits & WIFI_CONNECTED_BIT);
}

// ==============================
// HTTP event handler
// ==============================
static esp_err_t http_event_handler(esp_http_client_event_t* evt) {
    auto* buf = static_cast<HttpResponseBuffer*>(evt->user_data);
    if (!buf) return ESP_OK;

    if (evt->event_id == HTTP_EVENT_ON_DATA && evt->data && evt->data_len > 0) {
        size_t copy_len = evt->data_len;
        if (buf->len + copy_len >= sizeof(buf->data)) {
            copy_len = sizeof(buf->data) - buf->len - 1;
        }
        if (copy_len > 0) {
            memcpy(buf->data + buf->len, evt->data, copy_len);
            buf->len += copy_len;
            buf->data[buf->len] = '\0';
        }
    }
    return ESP_OK;
}

// ==============================
// Fetch geolocation from IP
// ==============================
static bool fetch_location(GeoPayload& out) {
    HttpResponseBuffer response{};

    esp_http_client_config_t config = {};
    config.url = "http://ip-api.com/json/?fields=status,country,regionName,city";     //HTTP geolocation endpoint without authentication.
    config.event_handler = http_event_handler;
    config.user_data = &response;
    config.timeout_ms = 5000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return false;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status_code != 200) {
        ESP_LOGE(TAG, "HTTP request failed");
        return false;
    }

    cJSON* root = cJSON_Parse(response.data);
    if (!root) {
        ESP_LOGE(TAG, "JSON parse failed");
        return false;
    }

    const cJSON* status = cJSON_GetObjectItem(root, "status");
    const cJSON* city = cJSON_GetObjectItem(root, "city");
    const cJSON* region = cJSON_GetObjectItem(root, "regionName");
    const cJSON* country = cJSON_GetObjectItem(root, "country");

    if (!cJSON_IsString(status) || strcmp(status->valuestring, "success") != 0) {
        cJSON_Delete(root);
        ESP_LOGE(TAG, "API returned invalid status");
        return false;
    }

    char composed[96] = {0};
    snprintf(composed, sizeof(composed), "%s%s%s%s%s",
             (cJSON_IsString(city) && city->valuestring) ? city->valuestring : "",
             (cJSON_IsString(region) && region->valuestring && strlen(region->valuestring)) ? ", " : "",
             (cJSON_IsString(region) && region->valuestring) ? region->valuestring : "",
             (cJSON_IsString(country) && country->valuestring && strlen(country->valuestring)) ? ", " : "",
             (cJSON_IsString(country) && country->valuestring) ? country->valuestring : "");

    memset(&out, 0, sizeof(out));
    strlcpy(out.location, composed, sizeof(out.location));

    cJSON_Delete(root);
    return true;
}

// ==============================
// Main demo logic
// ==============================
static void process_location() {
    GeoPayload geo{};
    if (!fetch_location(geo)) {
        ESP_LOGE(TAG, "Failed to fetch location");
        return;
    }

    ESP_LOGI(TAG, "Fetched: %s", geo.location);

    ESPfuscate::SealedBuffer<sizeof(GeoPayload)> sealed;
    if (RTO.seal(reinterpret_cast<const uint8_t*>(&geo), sizeof(geo), sealed) != ESP_OK) {
        ESP_LOGE(TAG, "seal() failed");
        return;
    }

    ESP_LOGI(TAG, "Encrypted");

    GeoPayload out{};
    if (RTO.open(sealed, reinterpret_cast<uint8_t*>(&out), sizeof(out)) != ESP_OK) {
        ESP_LOGE(TAG, "open() failed");
        return;
    }

    ESP_LOGI(TAG, "Decrypted: %s", out.location);
}

// ==============================
// app_main
// ==============================
extern "C" void app_main(void) {
    ESP_LOGI(TAG, "\n--- ESPfuscate ESP-IDF Easy Example ---");
    ESP_LOGI(TAG, "CTObf: WiFi credentials");
    ESP_LOGI(TAG, "RTobf: runtime geolocation encryption");

    ESP_ERROR_CHECK(init_nvs());
    ESP_ERROR_CHECK(init_wifi());

    if (RTO.begin() != ESP_OK) {
        ESP_LOGE(TAG, "RTO.begin() failed");
        return;
    }

    if (!connect_wifi_obfuscated()) {
        ESP_LOGE(TAG, "WiFi connection failed");
        return;
    }

    process_location();

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}