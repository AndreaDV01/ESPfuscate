/**
 * ESPfuscate - Secure Web Provisioning
 * 1. OBFUSCATE(): Protects the HTML/Internal strings in the .bin file.
 * 2. Runtime Seal: Encrypts incoming WiFi passwords using hardware-unique keys.
 * 3. Persistence: Saves the encrypted "blob" to Flash (Preferences).
 */

#include <WiFi.h>
#include <WebServer.h>
#include <ESPfuscate.h>
#include <Preferences.h>
#include <ESP32Ping.h> // Standard ESP32 Ping library

// --- COMPILE-TIME OBFUSCATION ---
// These strings will NOT be visible in plain text if someone reads the .bin file.
auto PAGE_TITLE  = OBFUSCATE("ESP32 Secure Config");
auto TARGET_PING = OBFUSCATE("google.com");

WebServer server(80);
Preferences prefs;
ESPfuscate::RunTimeStore store;
ESPfuscate::SealedBuffer<64> sealed_wifi_pw;

struct StoredSealed {
  uint8_t version;
  uint16_t pt_len;
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ct[64];
};

// Global status variables
String connection_status = "Not Connected";
bool is_authenticated = false;

static void sealedToStored(const ESPfuscate::SealedBuffer<64>& in, StoredSealed& out) {
  out.version = in.version;
  out.pt_len = in.pt_len;
  memcpy(out.nonce, in.nonce.data(), sizeof(out.nonce));
  memcpy(out.tag, in.tag.data(), sizeof(out.tag));
  memset(out.ct, 0, sizeof(out.ct));
  memcpy(out.ct, in.ct, (in.pt_len <= sizeof(out.ct)) ? in.pt_len : sizeof(out.ct));
}

static void storedToSealed(const StoredSealed& in, ESPfuscate::SealedBuffer<64>& out) {
  out.version = in.version;
  out.pt_len = in.pt_len;
  memcpy(out.nonce.data(), in.nonce, sizeof(in.nonce));
  memcpy(out.tag.data(), in.tag, sizeof(in.tag));
  memcpy(out.ct, in.ct, sizeof(in.ct));
}

// --- HTML GENERATOR ---
void handleRoot() {
  ESPfuscate::SecureBuffer<20> page_title = PAGE_TITLE.decrypt_string();
  String html = "<html><head><title>" + String(page_title.c_str()) + "</title>";
  html += "<style>body{font-family:sans-serif; padding:20px;} .status{color:blue;}</style></head><body>";
  html += "<h1>Secure WiFi Setup</h1>";
  
  // Status Section
  html += "<div class='status'>";
  html += "<p>Status: <b>" + connection_status + "</b></p>";
  if(WiFi.status() == WL_CONNECTED) {
    ESPfuscate::SecureBuffer<11> ping_target = TARGET_PING.decrypt_string();
    bool success = Ping.ping(ping_target.c_str(), 1);
    html += "<p>Ping to Google: " + String(success ? "OK" : "FAILED") + "</p>";
  }
  html += "</div><hr>";

  // Form Section
  html += "<h3>Update Credentials</h3>";
  html += "<form action='/save' method='POST'>";
  html += "SSID: <input type='text' name='ssid'><br><br>";
  html += "Password: <input type='password' name='pw'><br><br>";
  html += "<input type='submit' value='Encrypted Save & Connect'>";
  html += "</form>";

  // Reset Section
  html += "<hr><form action='/reset' method='POST'>";
  html += "<input type='submit' value='WIPE FLASH MEMORY' style='background:red; color:white;'>";
  html += "</form></body></html>";
  
  server.send(200, "text/html", html);
}

// --- SECURE STORAGE LOGIC ---
void handleSave() {
  String ssid = server.arg("ssid");
  String pass = server.arg("pw");

  if (ssid.length() > 0) {
    // 1. RUNTIME ENCRYPTION: Seal the password immediately
    // It is now locked to THIS specific ESP32 hardware.
    esp_err_t err = store.seal_string(pass.c_str(), sealed_wifi_pw);

    if (err == ESP_OK) {
      // 2. PERSISTENCE: Save the encrypted buffer to Flash (NVS)
      StoredSealed stored_pw{};
      sealedToStored(sealed_wifi_pw, stored_pw);
      prefs.begin("wifi-creds", false);
      prefs.putString("ssid", ssid);
      prefs.putBytes("sealed_pw", &stored_pw, sizeof(stored_pw));
      prefs.end();

      server.send(200, "text/html", "<h1>Encrypted & Saved!</h1><p>Restarting...</p>");
      delay(2000);
      ESP.restart();
    }
  }
}

void handleReset() {
  prefs.begin("wifi-creds", false);
  prefs.clear(); // Wipes all keys/values in this namespace
  prefs.end();
  server.send(200, "text/html", "<h1>Memory Wiped</h1><p>Flash is clean. Restarting...</p>");
  delay(2000);
  ESP.restart();
}

void setup() {
  Serial.begin(115200);
  if (store.begin() != ESP_OK) {
    connection_status = "Secure store init failed";
  }
  prefs.begin("wifi-creds", false);

  // Load SSID
  String savedSSID = prefs.getString("ssid", "");
  
  // Load Sealed Password from Flash
  if (savedSSID != "" && prefs.getBytesLength("sealed_pw") == sizeof(StoredSealed)) {
    StoredSealed stored_pw{};
    prefs.getBytes("sealed_pw", &stored_pw, sizeof(stored_pw));
    storedToSealed(stored_pw, sealed_wifi_pw);
    
    // Decrypt the password ONLY for the connection attempt
    char raw_pw[64];
    if (store.open_string(sealed_wifi_pw, raw_pw, 64) == ESP_OK) {
      WiFi.begin(savedSSID.c_str(), raw_pw);
      Serial.println("Attempting connection with decrypted key...");
      
      // Clear the temporary plain-text array immediately
      memset(raw_pw, 0, 64);
    }
  } else {
    // No credentials? Start Access Point for configuration
    WiFi.softAP("ESP32-Secure-Config");
    connection_status = "Access Point Mode (Ready to Config)";
  }
  prefs.end();

  server.on("/", handleRoot);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/reset", HTTP_POST, handleReset);
  server.begin();
}

void loop() {
  server.handleClient();
  
  // Update status occasionally
  if (WiFi.status() == WL_CONNECTED) {
    connection_status = "Connected to " + WiFi.SSID();
  }
}
