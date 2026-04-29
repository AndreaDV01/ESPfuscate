/*
  ESPfuscate v0.4.3

  Lightweight security library for ESP32.
  Provides:
  - compile-time obfuscation for string literals
  - runtime authenticated encryption for data generated during execution

  Main components:
  - OBF("...")       -> compile-time obfuscated literals using CTObf
  - CTObf            -> internal compile-time obfuscation container
  - RTobf            -> runtime encryption/decryption manager
  - TempBuffer<N>    -> temporary plaintext buffer (auto-wiped)
  - SealedBuffer<N>  -> encrypted container for storage/transmission

  Notes:
  - Designed for both frameworks Arduino and ESP-IDF 5.x.x (v6.x.x not supported yet)
  - No heap allocations
  - Runtime encryption is device-bound

  Author: AndreaDV01
  Repository: https://github.com/AndreaDV01/ESPfuscate
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
  #include "esp_err.h"
  #include "freertos/FreeRTOS.h"
  #include "freertos/semphr.h"
}

// ==============================
// User config defaults
// ==============================

#ifndef OBF_SALT
  #define OBF_SALT "8nK!4dW#0sT^6HbJr@1"
  #warning "OBF_SALT not defined! Using default build salt. For security reasons, override with -D OBF_SALT=\"random_string\""
#endif

#ifndef OBF_PEPPER
  #define OBF_PEPPER "q7M$1zP@9Lf#2XvR0s8"
  #warning "OBF_PEPPER not defined! Using default pepper. For security reasons, override with -D OBF_PEPPER=\"random_string\""
#endif

#ifndef OBF_KEY
  #define OBF_KEY "vH#ZdVaj6GxE@2U9$20"
  #warning "OBF_KEY not defined! Using default key. For security reasons, override with -D OBF_KEY=\"random_string\""
#endif

#ifndef OBF_NVS_NAMESPACE
  #define OBF_NVS_NAMESPACE "espf_rt"
#endif

#ifndef OBF_NVS_ROOTKEY
  #define OBF_NVS_ROOTKEY "root_key"
#endif


//OBF macro use CTObf constructor to obfuscate the string literal at compile time
#define OBF(str_literal) ESPfuscate::CTObf<sizeof(str_literal)> \
              (str_literal, ESPfuscate::detail::make_obf_occurrence_seed(__FILE__, __LINE__, __COUNTER__))
              
namespace ESPfuscate {

// ==============================
// Utilities
// ==============================

namespace detail {

constexpr uint8_t OBF_FORMAT_VERSION = 1;

constexpr uint8_t nonce_size = 12;
constexpr uint8_t tag_size = 16;

constexpr uint32_t fnv1a32_hash(const char* s, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n-1; ++i) {
    h ^= static_cast<uint8_t>(s[i]);
    h *= 16777619u;
  }
  return h;
}

constexpr uint32_t mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

constexpr uint32_t make_obf_occurrence_seed(const char* file, int line, uint32_t counter) {
  uint32_t h = 2166136261u;

  for (size_t i = 0; file[i] != '\0'; ++i) {
    h ^= static_cast<uint8_t>(file[i]);
    h *= 16777619u;
  }

  h ^= static_cast<uint32_t>(line);
  h *= 16777619u;

  h ^= counter;
  h *= 16777619u;

  h ^= fnv1a32_hash(OBF_SALT, sizeof(OBF_SALT)); //obf_salt_hash();
  h *= 16777619u;

  return mix32(h ^ 0x9E3779B9u);
}

void wipeBuffer(void* ptr, size_t len);

// ==============================
// Compile-time obfuscation
// ==============================

struct XorStream {
  uint32_t state;

  explicit constexpr XorStream(uint32_t seed) : state(seed ? seed : 0xA5A5A5A5u) {}

  constexpr uint8_t next() {
    uint32_t x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    state = x;
    return static_cast<uint8_t>(x & 0xFFu);
  }
};

}

// Temporary plaintext buffer.
// - Holds sensitive data in RAM (e.g. decrypted strings)
// - Automatically wiped (zeroized) when it goes out of scope
// - Use this for short-lived data only
template <size_t N>
struct TempBuffer {
  std::array<uint8_t, N> storage{};

  uint8_t* data() { return storage.data(); }
  const uint8_t* data() const { return storage.data(); }

  char* char_data() { return reinterpret_cast<char*>(storage.data()); }
  const char* char_data() const { return reinterpret_cast<const char*>(storage.data()); }

  operator char*() { return char_data(); }
  operator const char*() const { return char_data(); }

  operator uint8_t*() { return data(); }
  operator const uint8_t*() const { return data(); }

  constexpr size_t size() const { return N; }

  void clear() { detail::wipeBuffer(storage.data(), storage.size()); }

  ~TempBuffer() { clear(); }
};


// Encrypted container for persistent storage.
// - Holds ciphertext + metadata (nonce, tag, length)
// - Safe to store in flash / NVS
// - Must be opened (decrypted) into a TempBuffer before use
template <size_t N>
struct SealedBuffer {
  uint8_t version = detail::OBF_FORMAT_VERSION;
  std::array<uint8_t, detail::nonce_size> nonce{};
  std::array<uint8_t, detail::tag_size> tag{};
  std::array<uint8_t, N> storage{};
  uint16_t pt_len = 0;

  uint8_t* data() { return storage.data(); }
  const uint8_t* data() const { return storage.data(); }

  constexpr size_t size() const { return N; }

  void clear() {
    detail::wipeBuffer(storage.data(), storage.size());
    nonce.fill(0);
    tag.fill(0);
    pt_len = 0;
    version = detail::OBF_FORMAT_VERSION;
  }

  ~SealedBuffer() { clear(); }
};

//Compile Time Obfuscation of string literals
template <size_t N>
class CTObf {
public:
  std::array<uint8_t, N> enc{};

  const uint32_t seed_base;  
  const uint32_t salt_occ;     

  //CTobf constructor with explicit salt occurrence (the use of OBF macro is reccomended)
  constexpr CTObf(const char (&plain)[N], uint32_t salt_occ_):
  seed_base(detail::mix32(detail::fnv1a32_hash(OBF_PEPPER, sizeof(OBF_PEPPER)) ^ static_cast<uint32_t>(N) ^ 0x31415927u)),
  salt_occ(salt_occ_){
    detail::XorStream xs(detail::mix32(seed_base ^ salt_occ));
    for (size_t i = 0; i < N; ++i)  enc[i] = static_cast<uint8_t>(plain[i]) ^ xs.next();
  }

  //returns decrypted buffer (not null-terminated)
  void decrypt(uint8_t* out, size_t out_cap) const {
    if (!out || out_cap < N) return;
    detail::XorStream xs(detail::mix32(seed_base ^ salt_occ));
    for (size_t i = 0; i < N; ++i) {
      out[i] = enc[i] ^ xs.next();
    }
  }

  //returns decrypted string with null terminator (if space allows)
  void decrypt_str(char* out, size_t out_cap) const {
    if (!out || out_cap < N) return;
    decrypt(reinterpret_cast<uint8_t*>(out), out_cap);
    out[N - 1] = '\0';
  }

  //returns decrypted data in a TempBuffer (do not save the result, it will be wiped, for seafty reason, when the TempBuffer goes out of scope)
  TempBuffer<N> decrypt() const {
    TempBuffer<N> out;
    decrypt(out.data(), out.size());
    return out;
  }

  //returns decrypted string in a TempBuffer (do not save the result, it will be wiped, for seafty reason, when the TempBuffer goes out of scope)
  TempBuffer<N> decrypt_str() const {
    TempBuffer<N> out;
    decrypt_str(out.char_data(), out.size());
    return out;
  }
};

//Run Time Obfuscation 
class RTobf {
public:
  RTobf() = default;
  ~RTobf();

  esp_err_t begin(bool force_key_overwrite = false);

  bool ready() const;

  template <size_t N>
  esp_err_t seal(const char* pt, SealedBuffer<N>& out,
                 const char* aad = OBF_KEY,
                 size_t aad_len = sizeof(OBF_KEY) - 1) const;

  template <size_t N>
  esp_err_t seal(const uint8_t* pt, size_t pt_len, SealedBuffer<N>& out,
                 const char* aad = OBF_KEY,
                 size_t aad_len = sizeof(OBF_KEY) - 1) const;

  template <size_t N>
  esp_err_t open(const SealedBuffer<N>& in, TempBuffer<N>& out,
                 const char* aad = OBF_KEY,
                 size_t aad_len = sizeof(OBF_KEY) - 1) const;

  template <size_t N>
  esp_err_t open(const SealedBuffer<N>& in, uint8_t* pt_out, size_t pt_cap,
                      const char* aad = OBF_KEY,
                      size_t aad_len = sizeof(OBF_KEY) - 1) const;

  template <size_t N>
  esp_err_t open(const SealedBuffer<N>& in, char* out, size_t out_cap,
                       const char* aad = OBF_KEY,
                       size_t aad_len = sizeof(OBF_KEY) - 1) const;


private:
  void flush();

  struct LockGuard {
    const RTobf& s;

    explicit LockGuard(const RTobf& store) : s(store) {
      s.ensure_mutex_();
      xSemaphoreTakeRecursive(s.mutex_, portMAX_DELAY);
    }

    ~LockGuard() {
      xSemaphoreGiveRecursive(s.mutex_);
    }

    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
  };

  esp_err_t sealBytesImpl(const uint8_t* pt, size_t pt_len, uint8_t ver, uint8_t* ct_out,
                          size_t ct_cap, uint16_t& pt_len_out, uint8_t* nonce_out,
                          uint8_t* tag_out, const char* aad, size_t aad_len) const;

  esp_err_t openBytesImpl(const uint8_t* ct, size_t ct_cap, uint8_t ver, uint16_t pt_len,
                          const uint8_t* nonce, const uint8_t* tag, uint8_t* pt_out,
                          size_t pt_cap, const char* aad, size_t aad_len) const;

  int derive_key_from_root_and_chip();

  // ---- FreeRTOS recursive mutex ----
  mutable StaticSemaphore_t mutex_buf_{};
  mutable SemaphoreHandle_t mutex_{nullptr};

  void ensure_mutex_() const {
    if (mutex_ == nullptr) {
      mutex_ = xSemaphoreCreateRecursiveMutexStatic(&mutex_buf_);
    }
  }

  std::array<uint8_t, 32> root_{};
  std::array<uint8_t, 32> key_{};
  mutable bool key_ready_ = false;
};

} // namespace ESPfuscate

#include "ESPfuscate.tpp"