/*
  ESPfuscate - Arduino Advanced Example

  Description:
  Demonstrates secure persistent storage using RTobf + Preferences.

  Flow:
  - Acquire runtime data
  - Encrypt it using RTobf
  - Store encrypted data in flash
  - Reload and decrypt it

  Notes:
  - Shows real-world usage scenario
  - Includes persistent storage

  Author: AndreaDV01
  Library: https://github.com/AndreaDV01/ESPfuscate
*/

#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include <ESP32Ping.h>

#define USE_ESPFUSCATE true //false

#if USE_ESPFUSCATE
#include <ESPfuscate.h>
#endif


//NO ESP_FUSCATE COMPILATION SIZE ON ESP32-C3:
// - Ram:  38556 B (11.8% Full)
// - Flash:  696248 B (53.1% Full)

//WITH ESP_FUSCATE COMPILATION SIZE on ESP32-C3:
// - Ram:  38732 B (11.8% Full)
// - Flash:  711807 B (54.3% Full)


//platformio.ini configuration example:
/********* platformio.ini *********
platform = espressif32@6.6.0
board = dfrobot_beetle_esp32c3 ;esp32dev  ;esp32-s3-devkitc-1
framework = arduino
monitor_speed = 115200
lib_deps = 
	https://github.com/AndreaDV01/ESPfuscate.git
	https://github.com/marian-craciunescu/ESP32Ping.git

build_unflags = -std=gnu++11
build_flags = -std=gnu++17
    -D OBF_SALT=\"1xgstN4nE1DfdmY9jyUc\"
    -D OBF_PEPPER=\"Nwx4p5ChH2GtQcbx3m8r\"
    -D OBF_KEY=\"NAktMshKUzmsG6EQp24y\"
    ;Quotes may require escaping depending on your environment
****************end***************/

Preferences preferences;


// Compile-time obfuscation
#if USE_ESPFUSCATE
auto obf_host = OBF("www.google.com");
#else
const char* host = "www.google.com";
#endif

// Preferences Keys (max 15 char)
#define PREF_NAMESPACE "cY6vXp0B0h" //"storage"
#define KEY_SSID "cHbNYT8fqg" //"w_ssid"
#define KEY_PASS "jYFQhu4E35" //"w_pass"

// Prototipes
void handle_provisioning();
bool try_connect();
void do_ping();
String readSerial(bool hide_input = false);

#if USE_ESPFUSCATE
ESPfuscate::RTobf RTO; 
#endif

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.printf("\n\n--- ESPfuscate Advanced Demo %s---\n", USE_ESPFUSCATE ? "(with obfuscation)" : "(without obfuscation)");

    #if USE_ESPFUSCATE
    RTO.begin();
    #endif

    // Note: Preferences.begin() internally initializes the NVS partition
    // If credentials are not found, it starts provisioning
    if (!try_connect()) {
        Serial.println("- Credentials not found or invalid. Starting Provisioning...");
        handle_provisioning();
        if (!try_connect()) {
            Serial.println("- Critical failure after provisioning.");
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

    #if USE_ESPFUSCATE
    //64 bytes is enough for typical Wi-Fi credentials; choose a buffer size >= max plaintext length
    ESPfuscate::SealedBuffer<64> s_ssid, s_pass;

    // Encrypt credentials
    RTO.seal(ssid.c_str(), s_ssid);
    RTO.seal(pass.c_str(), s_pass);

    // Save using Preferences (which uses NVS internally)
    preferences.begin(PREF_NAMESPACE, false);
    
    // We use putBytes to save the binary 'Sealed' container
    preferences.putBytes(KEY_SSID, &s_ssid, sizeof(s_ssid));
    preferences.putBytes(KEY_PASS, &s_pass, sizeof(s_pass));
    preferences.end();

    Serial.println("Credentials encrypted and saved to Flash via Preferences.");

    #else
    // Save credentials in plaintext (not recommended)
    preferences.begin(PREF_NAMESPACE, false);
    preferences.putString(KEY_SSID, ssid);
    preferences.putString(KEY_PASS, pass);
    preferences.end();
    Serial.println("Credentials saved to Flash via Preferences (plaintext).");
    #endif
}

bool try_connect() {
    #if USE_ESPFUSCATE
    //64 bytes is enough for typical Wi-Fi credentials; choose a buffer size >= max plaintext length
    ESPfuscate::SealedBuffer<64> s_ssid, s_pass;
    
    preferences.begin(PREF_NAMESPACE, true); //Read-Only mode
    
    // Check if keys exist
    if (!preferences.isKey(KEY_SSID) || !preferences.isKey(KEY_PASS)) {
        preferences.end();
        Serial.println("- Credentials not found in Preferences.");
        return false;
    }

    // Load bytes directly into the Sealed container2
    preferences.getBytes(KEY_SSID, &s_ssid, sizeof(s_ssid));
    preferences.getBytes(KEY_PASS, &s_pass, sizeof(s_pass));
    preferences.end();

    //64 bytes is enough for typical Wi-Fi credentials; choose a buffer size >= max plaintext length
    ESPfuscate::TempBuffer<64> ssid, pass;

    esp_err_t err_ssid = RTO.open(s_ssid, ssid);
    if(err_ssid != ESP_OK) {
        Serial.printf("- Failed to decrypt SSID. ERROR: %s\n", esp_err_to_name(err_ssid));
        return false;
    }

    esp_err_t err_pass = RTO.open(s_pass, pass);
    if(err_pass != ESP_OK) {
        Serial.printf("- Failed to decrypt Password. ERROR: %s\n", esp_err_to_name(err_pass));
        return false;
    }

    Serial.printf("Connecting to: %s", ssid);
    #else
    preferences.begin(PREF_NAMESPACE, true); //Read-Only mode
    if (!preferences.isKey(KEY_SSID) || !preferences.isKey(KEY_PASS)) {
        preferences.end();
        Serial.println("- Credentials not found in Preferences.");
        return false;
    }
    String ssid = preferences.getString(KEY_SSID, "");
    String pass = preferences.getString(KEY_PASS, "");
    preferences.end();
    Serial.printf("Connecting to: %s", ssid.c_str());
    #endif

    //Prevent the WiFi library from automatically saving credentials in flash, since we manage it ourselves with encryption
    WiFi.persistent(false);  //esp_wifi_set_storage(WIFI_STORAGE_RAM);

    WiFi.begin(ssid, pass);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    bool connected = (WiFi.status() == WL_CONNECTED);
    if(connected) Serial.println("\nConnected!");
    else Serial.println("\nFailed to connect!");
    
    return connected;
}

void do_ping() {
    #if USE_ESPFUSCATE
    auto host = obf_host.decrypt_str();
    #endif

    Serial.printf("\nPing to %s ", host);
    
    if (Ping.ping(host, 3))  Serial.printf("Success! response time: %.0f ms\n", Ping.averageTime());
    else  Serial.println("Failed!");
    
}

String readSerial(bool hide_input) {
    while (!Serial.available()) delay(10);
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (hide_input) {
        for(uint8_t i = 0; i < input.length(); i++) Serial.print("*");
        Serial.println("");
    } 
    else Serial.println(input);

    return input;
}

void loop() {}
