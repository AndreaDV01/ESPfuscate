#include "ESPfuscate.h"

extern "C" {
  #include "esp_system.h"
  #include "esp_err.h"
  #include "nvs.h"
  #include "esp_efuse.h"
  #include "mbedtls/gcm.h"
  #include "mbedtls/hkdf.h"  //#include "mbedtls/md.h"
}

namespace ESPfuscate {

void secure_bzero(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

esp_err_t RunTimeStore::begin(bool force_key_overwrite) {
  LockGuard lock(*this);
  nvs_handle_t h;
  esp_err_t err = nvs_open(OBF_NVS_NAMESPACE, NVS_READWRITE, &h);
  if (err != ESP_OK) return err;

  size_t sz = root_.size();
  err = nvs_get_blob(h, OBF_NVS_ROOTKEY, root_.data(), &sz);

  if (err == ESP_ERR_NVS_NOT_FOUND || sz != root_.size() || force_key_overwrite) {
    esp_fill_random(root_.data(), root_.size());
    err = nvs_set_blob(h, OBF_NVS_ROOTKEY, root_.data(), root_.size());
    if (err == ESP_OK) err = nvs_commit(h);
  }

  nvs_close(h);
  if (err != ESP_OK) return err;

  err = static_cast<esp_err_t>(derive_key_from_root_and_chip());
  key_ready_ = (err == ESP_OK);
  return err;
}

bool RunTimeStore::ready() const {
  return key_ready_;
}

int RunTimeStore::derive_key_from_root_and_chip() {
  uint8_t mac[6] = {0};
  esp_err_t err = esp_efuse_mac_get_default(mac);
  if (err != ESP_OK) return err;

  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) {
    secure_bzero(mac, sizeof(mac));
    return ESP_FAIL;
  }

  static const uint8_t info[] = OBF_HKDF_INFO;
  static const uint8_t pepper[] = OBF_PEPPER;
  //static const uint8_t pepper[] = {(uint8_t*)OBF_PEPPER};

  uint8_t msg[6 + sizeof(info) - 1 + sizeof(pepper) - 1];
  size_t offset = 0;
  
  memcpy(msg + offset, mac, 6);
  offset += 6;
  memcpy(msg + offset, info, sizeof(info) - 1);
  offset += sizeof(info) - 1;
  memcpy(msg + offset, pepper, sizeof(pepper) - 1);

  int rc = mbedtls_md_hmac(md,
                           root_.data(), root_.size(),
                           msg, sizeof(msg),
                           key_.data());
  
  secure_bzero(msg, sizeof(msg));
  secure_bzero(mac, sizeof(mac));

  return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t RunTimeStore::seal_bytes(const uint8_t* pt, size_t pt_len, Sealed& out, const char* aad, size_t aad_len) const {
  // Note: LockGuard needs to be made compatible with const context, or use const_cast
  LockGuard lock(const_cast<RunTimeStore&>(*this));

  if(key_ready_ == false) return ESP_ERR_INVALID_STATE;
  if (!pt && pt_len) return ESP_ERR_INVALID_ARG;
  if (pt_len > out.ct_capacity) return ESP_ERR_INVALID_SIZE; //OBF_MAX_CT

  out.pt_len = static_cast<uint16_t>(pt_len);
  //out.ct_capacity = static_cast<uint16_t>(pt_len);
  esp_fill_random(out.nonce.data(), out.nonce.size());

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_.data(), 256);
  
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt_len,
                                   out.nonce.data(), out.nonce.size(),
                                   reinterpret_cast<const uint8_t*>(aad), aad_len,
                                   pt, out.ct, // out.ct.data(),
                                   out.tag.size(), out.tag.data());
  }
  mbedtls_gcm_free(&gcm);
  
  return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t RunTimeStore::seal_string(const char* pt, Sealed& out, const char* aad, size_t aad_len) const {
  if (!pt) return ESP_ERR_INVALID_ARG;
  return seal_bytes(reinterpret_cast<const uint8_t*>(pt), strlen(pt), out, aad, aad_len);
}

esp_err_t RunTimeStore::open_bytes(const Sealed& in, uint8_t* pt_out, size_t pt_cap, const char* aad, size_t aad_len) const {
  LockGuard lock(const_cast<RunTimeStore&>(*this));

  if(key_ready_ == false) return ESP_ERR_INVALID_STATE;
  if (!pt_out && pt_cap) return ESP_ERR_INVALID_ARG;
  const size_t pt_len = in.pt_len;
  if (pt_len > in.ct_capacity || pt_len > pt_cap) return ESP_ERR_INVALID_SIZE;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_.data(), 256);
  
  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(&gcm, pt_len,
                                  in.nonce.data(), in.nonce.size(),
                                  reinterpret_cast<const uint8_t*>(aad), aad_len,
                                  in.tag.data(), in.tag.size(),
                                  in.ct, pt_out);  //in.ct.data()
  }
  mbedtls_gcm_free(&gcm);

  return (rc == 0) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t RunTimeStore::open_string(const Sealed& in, char* out, size_t out_cap, const char* aad, size_t aad_len) const {
  if (!out || out_cap == 0) return ESP_ERR_INVALID_ARG;
  if (static_cast<size_t>(in.pt_len) + 1 > out_cap) return ESP_ERR_INVALID_SIZE;

  esp_err_t err = open_bytes(in, reinterpret_cast<uint8_t*>(out), in.pt_len, aad, aad_len);
  if (err != ESP_OK) return err;
  out[in.pt_len] = '\0';
  return ESP_OK;
}

void RunTimeStore::flush() {
  LockGuard lock(*this);
  mbedtls_platform_zeroize(key_.data(), key_.size());
  mbedtls_platform_zeroize(root_.data(), root_.size());
  key_ready_ = false;
}

RunTimeStore::~RunTimeStore() {
  flush();
}

} // namespace ESPfuscate