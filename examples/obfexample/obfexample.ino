/**
 * ESPfuscate - Basic Usage Example
 * * This example demonstrates how to encrypt a sensitive string (like an API key or WiFi password) 
 * by locking it to the hardware of this specific ESP32. 
 * The resulting encrypted data will ONLY work on this exact chip.
 */

#include <ESPfuscate.h>

// ---------------------------------------------------------
// STEP 0: Define your constant secret data to protect
// ---------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(1000); // Give the Serial Monitor a moment to connect
  Serial.println("\n--- ESPfuscate Basic Demo ---");

  // ---------------------------------------------------------
  // STEP 1: Initialize the Secure Store
  // ---------------------------------------------------------
  // This retrieves the unique root key from the ESP32's NVS 
  // (Non-Volatile Storage) or generates a new one on the very first boot.
  Serial.println("Initializing secure store...");
  if (ESPfuscate::store.begin() != ESP_OK) {
    Serial.println("Error: Failed to initialize RunTimeStore!");
    return; // Stop execution if initialization fails
  }

  // ---------------------------------------------------------
  // STEP 2: ENCRYPTION (Sealing the Data)
  // ---------------------------------------------------------
  // This is the secret you want to protect.
  const char* my_api_key = "SG.x89234jksdf9238LSJD.real_secret_key";
  
  // Create a secure buffer of 64 bytes to hold the encrypted data.
  // This special buffer is smart: it automatically erases itself from RAM 
  // when it is no longer needed, keeping your secrets safe from memory dumps.
  ESPfuscate::SealedBuffer<64> sealed_data;

  Serial.println("\nEncrypting API Key...");
  esp_err_t err = ESPfuscate::store.seal_string(my_api_key, sealed_data);

  if (err == ESP_OK) {
    Serial.println("Success! Key is now encrypted and locked to this ESP32.");
    Serial.print("- Original Text Length: "); 
    Serial.println(sealed_data.pt_len);
    Serial.print("- Max Buffer Capacity:  "); 
    Serial.println(sealed_data.ct_capacity);
  } else {
    Serial.println("Error: Encryption failed!");
    return;
  }

  // ---------------------------------------------------------
  // STEP 3: DECRYPTION (Opening the Data at Runtime)
  // ---------------------------------------------------------
  // Imagine this part of the code runs hours later, or right before 
  // you need to make a secure HTTP request to a server.
  
  char recovered_key[64]; // A standard array to hold the decrypted string
  
  Serial.println("\nDecrypting data...");
  err = ESPfuscate::store.open_string(sealed_data, recovered_key, sizeof(recovered_key));

  if (err == ESP_OK) {
    Serial.print("Recovered Key: ");
    Serial.println(recovered_key);
  } else if (err == ESP_ERR_INVALID_CRC) {
    // This error happens if the data is corrupted, or if someone copied 
    // the encrypted data to a different ESP32 chip.
    Serial.println("Error: Integrity check failed! Hardware mismatch or corrupted data.");
  } else {
    Serial.println("Error: Unknown decryption failure.");
  }

  // ---------------------------------------------------------
  // STEP 4: Automatic Memory Cleanup
  // ---------------------------------------------------------
  // As the 'setup()' function ends, 'sealed_data' goes out of scope. 
  // The library's built-in destructor will now automatically overwrite 
  // the RAM it used with zeros. You don't have to do anything manually!
  Serial.println("\nSetup complete. Secure memory will now be wiped.");
}

void loop() {
  // Nothing to do here for this demo
}