#include <stdio.h>
#include <inttypes.h>
#include <string.h>

extern "C" {
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/netdb.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "ping/ping_sock.h"
}

#include "ESPfuscate.h"

/*
 * ESP-IDF example equivalent of Arduino_Example.cpp.
 * This example is intentionally C++ because ESPfuscate exposes C++ APIs.
 */

static const char* TAG = "ESPfuscate_IDF";

// Keys (max 15 char per Preferences in Arduino; same logical names here)
#define PREF_NAMESPACE "storage"
#define KEY_SSID "w_ssid"
#define KEY_PASS "w_pass"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define PING_DONE_BIT BIT0

static constexpr int WIFI_MAX_RETRY = 20;

ESPfuscate::RunTimeStore store;
auto target_host_e = OBFUSCATE("www.google.com");

static EventGroupHandle_t s_wifi_event_group = nullptr;
static EventGroupHandle_t s_ping_event_group = nullptr;
static esp_event_handler_instance_t s_wifi_any_id = nullptr;
static esp_event_handler_instance_t s_wifi_got_ip = nullptr;
static bool s_wifi_initialized = false;
static int s_retry_num = 0;

struct StoredSealed {
  uint8_t version;
  uint16_t pt_len;
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ct[64];
};

struct PingStats {
  uint32_t replies;
  uint32_t total_time_ms;
};

static void sealed_to_stored(const ESPfuscate::SealedBuffer<64>& in, StoredSealed& out) {
  out.version = in.version;
  out.pt_len = in.pt_len;
  memcpy(out.nonce, in.nonce.data(), sizeof(out.nonce));
  memcpy(out.tag, in.tag.data(), sizeof(out.tag));
  memset(out.ct, 0, sizeof(out.ct));
  memcpy(out.ct, in.ct, (in.pt_len <= sizeof(out.ct)) ? in.pt_len : sizeof(out.ct));
}

static void stored_to_sealed(const StoredSealed& in, ESPfuscate::SealedBuffer<64>& out) {
  out.version = in.version;
  out.pt_len = in.pt_len;
  memcpy(out.nonce.data(), in.nonce, sizeof(in.nonce));
  memcpy(out.tag.data(), in.tag, sizeof(in.tag));
  memcpy(out.ct, in.ct, sizeof(in.ct));
}

static bool read_line(const char* prompt, char* out, size_t out_len, bool hide_input = false) {
  if (!out || out_len == 0) return false;
  printf("%s", prompt);
  fflush(stdout);

  if (!fgets(out, static_cast<int>(out_len), stdin)) return false;

  size_t len = strlen(out);
  if (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) out[--len] = '\0';
  if (len > 0 && out[len - 1] == '\r') out[len - 1] = '\0';

  if (hide_input) printf("\n");
  return len > 0;
}

static void wifi_event_handler(void*,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void* event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    if (s_retry_num < WIFI_MAX_RETRY) {
      esp_wifi_connect();
      s_retry_num++;
      ESP_LOGI(TAG, "Retry Wi-Fi connection (%d/%d)", s_retry_num, WIFI_MAX_RETRY);
    } else {
      xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    }
    ESP_LOGI(TAG, "Wi-Fi disconnected");
    return;
  }

  if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t* event = static_cast<ip_event_got_ip_t*>(event_data);
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    s_retry_num = 0;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
  }
}

static esp_err_t init_nvs() {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  return err;
}

static esp_err_t init_wifi_sta_once() {
  if (s_wifi_initialized) return ESP_OK;

  ESP_ERROR_CHECK(esp_netif_init());
  esp_err_t err = esp_event_loop_create_default();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;

  esp_netif_create_default_wifi_sta();

  s_wifi_event_group = xEventGroupCreate();
  if (!s_wifi_event_group) return ESP_ERR_NO_MEM;

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, nullptr, &s_wifi_any_id));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, nullptr, &s_wifi_got_ip));

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));  // avoid plaintext creds in Wi-Fi NVS
  ESP_ERROR_CHECK(esp_wifi_start());

  s_wifi_initialized = true;
  return ESP_OK;
}

static bool connect_with_credentials(const char* ssid, const char* pass) {
  if (!ssid || !pass) return false;

  wifi_config_t wifi_config = {};
  strlcpy(reinterpret_cast<char*>(wifi_config.sta.ssid), ssid, sizeof(wifi_config.sta.ssid));
  strlcpy(reinterpret_cast<char*>(wifi_config.sta.password), pass, sizeof(wifi_config.sta.password));
  wifi_config.sta.pmf_cfg.capable = true;
  wifi_config.sta.pmf_cfg.required = false;

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

  xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
  s_retry_num = 0;
  esp_wifi_disconnect();
  esp_wifi_connect();

  EventBits_t bits = xEventGroupWaitBits(
      s_wifi_event_group,
      WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
      pdFALSE,
      pdFALSE,
      pdMS_TO_TICKS(15000));

  if (bits & WIFI_CONNECTED_BIT) {
    ESP_LOGI(TAG, "Connected to AP");
    return true;
  }

  ESP_LOGE(TAG, "Failed to connect to AP");
  return false;
}

static esp_err_t save_credentials_encrypted(const char* ssid, const char* pass) {
  ESPfuscate::SealedBuffer<64> s_ssid;
  ESPfuscate::SealedBuffer<64> s_pass;

  esp_err_t err = store.seal_string(ssid, s_ssid);
  if (err != ESP_OK) return err;
  err = store.seal_string(pass, s_pass);
  if (err != ESP_OK) return err;

  StoredSealed st_ssid = {};
  StoredSealed st_pass = {};
  sealed_to_stored(s_ssid, st_ssid);
  sealed_to_stored(s_pass, st_pass);

  nvs_handle_t nvs = 0;
  err = nvs_open(PREF_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) return err;
  err = nvs_set_blob(nvs, KEY_SSID, &st_ssid, sizeof(st_ssid));
  if (err == ESP_OK) err = nvs_set_blob(nvs, KEY_PASS, &st_pass, sizeof(st_pass));
  if (err == ESP_OK) err = nvs_commit(nvs);
  nvs_close(nvs);
  return err;
}

static esp_err_t load_credentials_encrypted(ESPfuscate::SealedBuffer<64>& s_ssid,
                                            ESPfuscate::SealedBuffer<64>& s_pass) {
  nvs_handle_t nvs = 0;
  esp_err_t err = nvs_open(PREF_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) return err;

  StoredSealed st_ssid = {};
  StoredSealed st_pass = {};
  size_t sz_ssid = sizeof(st_ssid);
  size_t sz_pass = sizeof(st_pass);

  err = nvs_get_blob(nvs, KEY_SSID, &st_ssid, &sz_ssid);
  if (err == ESP_OK) err = nvs_get_blob(nvs, KEY_PASS, &st_pass, &sz_pass);
  nvs_close(nvs);
  if (err != ESP_OK) return err;

  if (sz_ssid != sizeof(st_ssid) || sz_pass != sizeof(st_pass)) return ESP_ERR_INVALID_SIZE;
  if (st_ssid.pt_len > 64 || st_pass.pt_len > 64) return ESP_ERR_INVALID_SIZE;

  stored_to_sealed(st_ssid, s_ssid);
  stored_to_sealed(st_pass, s_pass);
  return ESP_OK;
}

static void handle_provisioning() {
  ESP_LOGI(TAG, "--- Wi-Fi Provisioning Mode ---");

  char ssid[64] = {};
  char pass[64] = {};

  while (!read_line("Insert SSID: ", ssid, sizeof(ssid), false)) {
    ESP_LOGW(TAG, "SSID empty, retry");
  }
  while (!read_line("Insert Password: ", pass, sizeof(pass), true)) {
    ESP_LOGW(TAG, "Password empty, retry");
  }

  esp_err_t err = save_credentials_encrypted(ssid, pass);
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Credentials encrypted and saved in NVS.");
  } else {
    ESP_LOGE(TAG, "Failed to save encrypted credentials: %s", esp_err_to_name(err));
  }
}

static bool try_connect() {
  ESPfuscate::SealedBuffer<64> s_ssid;
  ESPfuscate::SealedBuffer<64> s_pass;

  esp_err_t err = load_credentials_encrypted(s_ssid, s_pass);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Credentials not found/invalid in NVS: %s", esp_err_to_name(err));
    return false;
  }

  ESPfuscate::SecureBuffer<64> ssid;
  ESPfuscate::SecureBuffer<64> pass;

  if (store.open_string(s_ssid, ssid.c_str(), ssid.size()) != ESP_OK ||
      store.open_string(s_pass, pass.c_str(), pass.size()) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to decrypt credentials");
    return false;
  }

  ESP_LOGI(TAG, "Connecting to: %s", ssid.c_str());
  return connect_with_credentials(ssid.c_str(), pass.c_str());
}

static void on_ping_success(esp_ping_handle_t hdl, void* args) {
  auto* stats = static_cast<PingStats*>(args);
  uint32_t elapsed_time = 0;
  uint16_t seqno = 0;
  uint8_t ttl = 0;
  esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_time, sizeof(elapsed_time));
  esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
  esp_ping_get_profile(hdl, ESP_PING_PROF_TTL, &ttl, sizeof(ttl));

  stats->replies++;
  stats->total_time_ms += elapsed_time;
  ESP_LOGI(TAG, "Ping reply seq=%u ttl=%u time=%" PRIu32 " ms", seqno, ttl, elapsed_time);
}

static void on_ping_timeout(esp_ping_handle_t hdl, void*) {
  uint16_t seqno = 0;
  esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
  ESP_LOGW(TAG, "Ping timeout seq=%u", seqno);
}

static void on_ping_end(esp_ping_handle_t, void*) {
  xEventGroupSetBits(s_ping_event_group, PING_DONE_BIT);
}

static void do_ping() {
  auto host = target_host_e.decrypt_string();
  ESP_LOGI(TAG, "Ping to %s", host.c_str());

  struct addrinfo hint = {};
  hint.ai_family = AF_INET;
  struct addrinfo* res = nullptr;

  int err = getaddrinfo(host.c_str(), nullptr, &hint, &res);
  if (err != 0 || !res) {
    ESP_LOGE(TAG, "DNS lookup failed for %s", host.c_str());
    if (res) freeaddrinfo(res);
    return;
  }

  ip_addr_t target_addr = {};
  inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr);
  freeaddrinfo(res);

  esp_ping_config_t ping_config = ESP_PING_DEFAULT_CONFIG();
  ping_config.target_addr = target_addr;
  ping_config.count = 3;
  ping_config.interval_ms = 1000;
  ping_config.timeout_ms = 1000;

  PingStats stats = {};
  esp_ping_callbacks_t cbs = {};
  cbs.cb_args = &stats;
  cbs.on_ping_success = on_ping_success;
  cbs.on_ping_timeout = on_ping_timeout;
  cbs.on_ping_end = on_ping_end;

  esp_ping_handle_t ping = nullptr;
  if (esp_ping_new_session(&ping_config, &cbs, &ping) != ESP_OK) {
    ESP_LOGE(TAG, "Cannot create ping session");
    return;
  }

  if (!s_ping_event_group) s_ping_event_group = xEventGroupCreate();
  xEventGroupClearBits(s_ping_event_group, PING_DONE_BIT);
  esp_ping_start(ping);
  xEventGroupWaitBits(s_ping_event_group, PING_DONE_BIT, pdTRUE, pdFALSE, pdMS_TO_TICKS(10000));
  esp_ping_delete_session(ping);

  if (stats.replies > 0) {
    ESP_LOGI(TAG, "Ping success, average time: %" PRIu32 " ms", stats.total_time_ms / stats.replies);
  } else {
    ESP_LOGW(TAG, "Ping failed");
  }
}

extern "C" void app_main(void) {
  ESP_LOGI(TAG, "\n--- ESPfuscate Security Demo (ESP-IDF) ---");

  ESP_ERROR_CHECK(init_nvs());
  ESP_ERROR_CHECK(init_wifi_sta_once());

  ESP_ERROR_CHECK(store.begin());

  if (!try_connect()) {
    ESP_LOGW(TAG, "Credentials not found or invalid. Starting provisioning...");
    handle_provisioning();
    if (!try_connect()) {
      ESP_LOGE(TAG, "Critical failure after provisioning.");
      return;
    }
  }

  do_ping();

  while (true) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
