/**
 * ESPfuscate - Esempio d'uso base
 * * Questo esempio mostra come cifrare una stringa sensibile legandola all'hardware
 * dell'ESP32. I dati cifrati risultanti funzioneranno SOLO su questo specifico chip.
 */

#include <ESPfuscate.h>

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n--- ESPfuscate Demo ---");

  // 1. Inizializza lo store. 
  // Recupera la chiave radice dalla NVS (o ne crea una nuova se è il primo avvio).
  if (ESPfuscate::store.begin() != ESP_OK) {
    Serial.println("Errore inizializzazione RunTimeStore!");
    return;
  }

  // --- FASE 1: CIFRATURA (Provisioning) ---
  const char* api_key = "SG.x89234jksdf9238LSJD.real_secret_key";
  
  // Creiamo un buffer cifrato di 64 byte. 
  // Grazie al template, la gestione della RAM e della pulizia è automatica.
  ESPfuscate::SealedBuffer<64> sealed_data;

  Serial.println("Cifratura della chiave API...");
  esp_err_t err = ESPfuscate::store.seal_string(api_key, sealed_data);

  if (err == ESP_OK) {
    Serial.println("Chiave cifrata con successo!");
    Serial.print("Dimensione testo originale: "); Serial.println(sealed_data.pt_len);
    Serial.print("Capacità massima buffer: "); Serial.println(sealed_data.ct_capacity);
  }

  // --- FASE 2: RECUPERO (Runtime) ---
  // Immagina che questo accada ore dopo o in un'altra parte del codice.
  char recovered_key[64];
  
  Serial.println("Decifratura in corso...");
  err = ESPfuscate::store.open_string(sealed_data, recovered_key, sizeof(recovered_key));

  if (err == ESP_OK) {
    Serial.print("Chiave recuperata: ");
    Serial.println(recovered_key);
  } else if (err == ESP_ERR_INVALID_CRC) {
    Serial.println("Errore: Integrità fallita o chiave hardware diversa!");
  }

  // Alla fine di questa funzione, 'sealed_data' viene distrutto.
  // Grazie al distruttore che abbiamo implementato, la RAM viene azzerata 
  // automaticamente impedendo a un malintenzionato di leggerla.
}

void loop() {
  // Niente da fare qui
}