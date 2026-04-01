/*
  ESPfuscate runtime implementation.

  This file contains:
  - runtime key initialization
  - AES-GCM sealing/opening
  - device-bound key derivation
  - secure memory wiping
*/

#include "ESPfuscate.h"

extern "C" {
  #include "esp_mac.h"
  #include "esp_random.h"
  #include "nvs.h"
  #include "mbedtls/gcm.h"
  #include "mbedtls/md.h"
  #include "mbedtls/platform_util.h"
}

namespace ESPfuscate {

esp_err_t RTobf::begin(bool force_key_overwrite) {
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

bool RTobf::ready() const {
  return key_ready_;
}

esp_err_t RTobf::sealBytesImpl(const uint8_t* pt, size_t pt_len, uint8_t ver, uint8_t* ct_out, size_t ct_cap,
                               uint16_t& pt_len_out, uint8_t* nonce, uint8_t* tag, const char* aad, size_t aad_len) const
{
  LockGuard lock(const_cast<RTobf&>(*this));

  if (!key_ready_) return ESP_ERR_INVALID_STATE;
  if (!pt && pt_len) return ESP_ERR_INVALID_ARG;
  if (!ct_out || !nonce || !tag) return ESP_ERR_INVALID_ARG;
  if (pt_len > ct_cap) return ESP_ERR_INVALID_SIZE;
  if (pt_len > 0xFFFFu) return ESP_ERR_INVALID_SIZE;
  if (aad_len>0 && !aad) return ESP_ERR_INVALID_ARG;

  pt_len_out = static_cast<uint16_t>(pt_len);

  esp_fill_random(nonce, detail::nonce_size);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                              key_.data(), 256);

  // Build authenticated AAD = [ version | user_aad ]
  uint8_t aad_buf[aad_len + 1];
  aad_buf[0] = ver; //OBF_FORMAT_VERSION;
  memcpy(aad_buf + 1, aad, aad_len);

  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT, pt_len, nonce, detail::nonce_size,
        aad_buf, aad_len + 1, pt, ct_out, detail::tag_size, tag);
  }

  mbedtls_gcm_free(&gcm);

  return (rc == 0) ? ESP_OK : ESP_FAIL;
}


esp_err_t RTobf::openBytesImpl(const uint8_t* ct, size_t ct_cap, uint8_t ver, uint16_t pt_len, const uint8_t* nonce,
                               const uint8_t* tag, uint8_t* pt_out, size_t pt_cap, const char* aad, size_t aad_len) const
{
  LockGuard lock(const_cast<RTobf&>(*this));

  if (!key_ready_) return ESP_ERR_INVALID_STATE;
  if (!ct || !nonce || !tag) return ESP_ERR_INVALID_ARG;
  if (!pt_out && pt_cap) return ESP_ERR_INVALID_ARG;
  if (aad_len>0 && !aad) return ESP_ERR_INVALID_ARG;

  const size_t plain_len = static_cast<size_t>(pt_len);
  if (plain_len > ct_cap || plain_len > pt_cap)  return ESP_ERR_INVALID_SIZE;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_.data(), 256);

  // Build authenticated AAD = [ version | user_aad ]
  uint8_t aad_buf[aad_len + 1];
  aad_buf[0] = ver; //OBF_FORMAT_VERSION;
  memcpy(aad_buf + 1, aad, aad_len);

  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(
        &gcm, plain_len, nonce, detail::nonce_size,
        aad_buf, aad_len+1, tag, detail::tag_size, ct, pt_out);
  }

  mbedtls_gcm_free(&gcm);

  return (rc == 0) ? ESP_OK : ESP_ERR_INVALID_CRC;
}


void RTobf::flush() {
  LockGuard lock(*this);

  mbedtls_platform_zeroize(key_.data(), key_.size());
  mbedtls_platform_zeroize(root_.data(), root_.size());
  key_ready_ = false;
}

RTobf::~RTobf() {
  flush();
}

int RTobf::derive_key_from_root_and_chip() {
  uint8_t mac[6] = {0};
  esp_err_t err = esp_efuse_mac_get_default(mac);
  if (err != ESP_OK) return err;

  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) {
    detail::wipeBuffer(mac, sizeof(mac));
    return ESP_FAIL;
  }

  static const uint8_t info[] = OBF_KEY;
  static const uint8_t pepper[] = OBF_PEPPER;

  uint8_t msg[6 + sizeof(info) - 1 + sizeof(pepper) - 1];
  size_t offset = 0;

  memcpy(msg + offset, mac, 6);
  offset += 6;

  memcpy(msg + offset, info, sizeof(info) - 1);
  offset += sizeof(info) - 1;

  memcpy(msg + offset, pepper, sizeof(pepper) - 1);

  int rc = mbedtls_md_hmac(
                        md, root_.data(), root_.size(),
                        msg, sizeof(msg), key_.data());

  detail::wipeBuffer(msg, sizeof(msg));
  detail::wipeBuffer(mac, sizeof(mac));

  return (rc == 0) ? ESP_OK : ESP_FAIL;
}

namespace detail {

void wipeBuffer(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--)  *v++ = 0;
}

} // namespace detail

} // namespace ESPfuscate