#include <Arduino.h>
#include <WiFi.h>
#include <nvs_flash.h>
#include "lib/ESPping/ESPping.h" 

#include "../src/ESPfuscate.h" 


// Compile-time obfuscation example: the target host is obfuscated in the binary and only decrypted at runtime when needed.
auto target_host_e = OBFUSCATE("www.google.com");

//  NVS keys for storing encrypted data
#define NVS_KEY_SSID "w_ssid"
#define NVS_KEY_PASS "w_pass"

// Prototipes
void handle_provisioning();
bool try_connect();
void do_ping();
String readSerial(bool hide_input = false);

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n--- ESPfuscate Security Demo ---");

    // Initialize standard NVS partition
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    // Try to connect using saved credentials. If not found or invalid, start provisioning.
    if (!try_connect()) {
        Serial.println("-Credentials not found or invalid. Starting Provisioning...");
        handle_provisioning();
        if (!try_connect()) {
            Serial.println("-Critical failure after provisioning.");
            return;
        }
    }

    do_ping();
}

void handle_provisioning() {
    Serial.println("\n--- WiFi Provisioning Mode ---");
    Serial.print("Insert SSID: ");
    String ssid = readSerial(false);
    Serial.print("Insert Password: ");
    String pass = readSerial(true);

    ESPfuscate::Sealed s_ssid, s_pass;

    // We encrypt the credentials. Thanks to the hybrid logic, seal_string auto-initializes
    // The AES key is derived from the MAC + Pepper and cleaned immediately after
    ESPfuscate::store.seal_string(ssid.c_str(), s_ssid);
    ESPfuscate::store.seal_string(pass.c_str(), s_pass);

    // We save the 'Sealed' containers in NVS. The actual credentials are never stored in plaintext and only exist in RAM during the brief moment of decryption for connection.
    nvs_handle_t h;
    if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_blob(h, NVS_KEY_SSID, &s_ssid, sizeof(ESPfuscate::Sealed));
        nvs_set_blob(h, NVS_KEY_PASS, &s_pass, sizeof(ESPfuscate::Sealed));
        nvs_commit(h);
        nvs_close(h);
        Serial.println("Credentials encrypted and saved to Flash.");
    }
}

bool try_connect() {
    nvs_handle_t h;
    ESPfuscate::Sealed s_ssid, s_pass;
    size_t sz = sizeof(ESPfuscate::Sealed);

    if (nvs_open("storage", NVS_READONLY, &h) != ESP_OK) return false;
    
    esp_err_t e1 = nvs_get_blob(h, NVS_KEY_SSID, &s_ssid, &sz);
    esp_err_t e2 = nvs_get_blob(h, NVS_KEY_PASS, &s_pass, &sz);
    nvs_close(h);

    if (e1 != ESP_OK || e2 != ESP_OK) return false;

    // We use SecureBuffer to handle decrypted data in RAM securely
    // The destructor will automatically zero out the memory
    ESPfuscate::SecureBuffer<64> ssid, pass;

    // "Zero-Trace" decryption: opens, decrypts, and cleans the store instantaneously
    if (ESPfuscate::store.open_string(s_ssid, ssid.c_str(), ssid.size()) != ESP_OK ||
        ESPfuscate::store.open_string(s_pass, pass.c_str(), pass.size()) != ESP_OK) {
        return false;
    }

    Serial.printf("Connecting to: %s", ssid.c_str());
    WiFi.begin(ssid.c_str(), pass.c_str());

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    bool connected = WiFi.status() == WL_CONNECTED;
    if(connected)  Serial.println("\nConnected!");
    else  Serial.println("\nFailed to connect!");
    return connected;
}

void do_ping() {
    // We decrypt the compile-time obfuscated host
    ESPfuscate::SecureBuffer<64> host;
    target_host_e.decrypt_string(host.c_str(), host.size());

    Serial.printf("\nPing to %s ", host.c_str());
    
    if (Ping.ping(host.c_str(), 3))  Serial.printf("Success! response time: %.0f ms\n", Ping.averageTime());
    else  Serial.println("Failed!");
}

String readSerial(bool hide_input) {
    while (!Serial.available()) delay(10);
    String input = Serial.readStringUntil('\r');
    input.trim();
    if (hide_input) {
        for(uint8_t i = 0; i < input.length(); i++)  Serial.print("*");
        Serial.println("");
    }
    else Serial.println(input);

    return input;
}

void loop() {}
