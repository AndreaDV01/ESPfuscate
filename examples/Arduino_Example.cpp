#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include "lib/ESPping/ESPping.h" 
#include "../src/ESPfuscate.h" 

Preferences preferences;

// Compile-time obfuscation
auto target_host_e = OBFUSCATE("www.google.com");

// Keys (max 15 char per Preferences)
#define PREF_NAMESPACE "storage"
#define KEY_SSID "w_ssid"
#define KEY_PASS "w_pass"

// Prototipes
void handle_provisioning();
bool try_connect();
void do_ping();
String readSerial(bool hide_input = false);

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n--- ESPfuscate Security Demo (Preferences version) ---");

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

    ESPfuscate::Sealed s_ssid, s_pass;

    // Encrypt credentials
    ESPfuscate::store.seal_string(ssid.c_str(), s_ssid);
    ESPfuscate::store.seal_string(pass.c_str(), s_pass);

    // Save using Preferences (which uses NVS internally)
    preferences.begin(PREF_NAMESPACE, false);
    // We use putBytes to save the binary 'Sealed' container
    preferences.putBytes(KEY_SSID, &s_ssid, sizeof(ESPfuscate::Sealed));
    preferences.putBytes(KEY_PASS, &s_pass, sizeof(ESPfuscate::Sealed));
    preferences.end();

    Serial.println("Credentials encrypted and saved to Flash via Preferences.");
}

bool try_connect() {
    ESPfuscate::Sealed s_ssid, s_pass;
    
    preferences.begin(PREF_NAMESPACE, true); //Read-Only mode
    
    // Check if keys exist
    if (!preferences.isKey(KEY_SSID) || !preferences.isKey(KEY_PASS)) {
        preferences.end();
        return false;
    }

    // Load bytes directly into the Sealed container
    preferences.getBytes(KEY_SSID, &s_ssid, sizeof(ESPfuscate::Sealed));
    preferences.getBytes(KEY_PASS, &s_pass, sizeof(ESPfuscate::Sealed));
    preferences.end();

    ESPfuscate::SecureBuffer<64> ssid, pass;

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
    
    bool connected = (WiFi.status() == WL_CONNECTED);
    if(connected) Serial.println("\nConnected!");
    else Serial.println("\nFailed to connect!");
    
    return connected;
}

void do_ping() {
    ESPfuscate::SecureBuffer<64> host;
    target_host_e.decrypt_string(host.c_str(), host.size());

    Serial.printf("\nPing to %s ", host.c_str());
    
    if (Ping.ping(host.c_str(), 3)) {
        Serial.printf("Success! response time: %.0f ms\n", Ping.averageTime());
    } else {
        Serial.println("Failed!");
    }
}

String readSerial(bool hide_input) {
    while (!Serial.available()) delay(10);
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (hide_input) {
        for(uint8_t i = 0; i < input.length(); i++) Serial.print("*");
        Serial.println("");
    } else {
        Serial.println(input);
    }
    return input;
}

void loop() {}
