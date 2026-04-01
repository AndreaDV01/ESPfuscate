/*
  ESPfuscate - Arduino Basic Example

  Description:
  Minimal example showing compile-time obfuscation (OBF) and runtime encryption (RTobf).

  Flow:
  - Connect to WiFi using obfuscated credentials
  - Fetch runtime data (geolocation)
  - Encrypt and decrypt the data

  Notes:
  - Designed for simplicity and clarity
  - No persistent storage

  Author: AndreaDV01
  Library: https://github.com/AndreaDV01/ESPfuscate
*/

//#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <ESPfuscate.h>


// --- WiFi credentials (compile-time obfuscated) ---
auto WIFI_SSID = OBF("YOUR_WIFI_SSID");
auto WIFI_PASS = OBF("YOUR_WIFI_PASSWORD");

// --- RT obfuscation ---
ESPfuscate::RTobf RTO;

// --- Runtime payload ---
struct GeoPayload {
  char location[96];
};

ESPfuscate::SealedBuffer<sizeof(GeoPayload)> sealed;
bool hasData = false;

// --- WiFi connect ---
bool connectWiFi() {
  auto ssid = WIFI_SSID.decrypt_str();
  auto pass = WIFI_PASS.decrypt_str();

  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.begin(ssid.char_data(), pass.char_data());

  Serial.printf("Connecting to %s", ssid.char_data());
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) return false;

  Serial.println("connected!");

  return true;
}

// --- Fetch location (IP-based) ---
bool fetchLocation(GeoPayload& out) {
  HTTPClient http;
  http.begin("http://ip-api.com/json/?fields=status,country,regionName,city");

  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    Serial.printf("HTTP error: %d\n", code);
    http.end();
    return false;
  }

  String body = http.getString();
  http.end();

  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    Serial.println("JSON parse failed");
    return false;
  }

  if (doc["status"] != "success") {
    Serial.println("API error");
    return false;
  }

  String city    = doc["city"] | "";
  String region  = doc["regionName"] | "";
  String country = doc["country"] | "";

  String composed;
  if (city.length())    composed += city;
  if (region.length())  composed += (composed.length() ? ", " : "") + region;
  if (country.length()) composed += (composed.length() ? ", " : "") + country;

  memset(&out, 0, sizeof(out));
  composed.toCharArray(out.location, sizeof(out.location));

  return true;
}

// --- Fetch + Encrypt + Decrypt ---
void processLocation() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return;
  }

  GeoPayload geo{};

  if (!fetchLocation(geo)) {
    Serial.println("Fetch failed");
    return;
  }

  Serial.print("Fetched: ");
  Serial.println(geo.location);

  if (RTO.seal((uint8_t*)&geo, sizeof(geo), sealed) != ESP_OK) {
    Serial.println("seal() failed");
    return;
  }

  hasData = true;
  Serial.println("Encrypted");

  GeoPayload out{};
  if (RTO.open(sealed, (uint8_t*)&out, sizeof(out)) != ESP_OK) {
    Serial.println("open() failed");
    return;
  }

  Serial.print("Decrypted: ");
  Serial.println(out.location);
  Serial.println();
}

// --- Setup ---
void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println("\n--- ESPfuscate Easy Example ---");

  if (RTO.begin() != ESP_OK) {
    Serial.println("RTO.begin() failed!");
    return;
  }

  if (!connectWiFi())  Serial.printf("WiFi connection failed");

  Serial.println("Press 'R' to fetch & encrypt location\n");

}

// --- Loop ---
void loop() {
  if (!Serial.available())  return;

  // Listen for 'R' key to trigger location fetch + encrypt + decrypt
  char cmd = Serial.read();
  if (cmd == 'r' || cmd == 'R')  processLocation();
}