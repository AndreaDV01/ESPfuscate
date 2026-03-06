#pragma once
/*
  obf_aesgcm.h (V4.1 split)
  - Header-only: compile-time obfuscation + small utilities
  - Runtime crypto (NVS/HKDF/AES-GCM) implemented in obf_aesgcmX.cpp
*/

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifndef OBF_HKDF_INFO
#define OBF_HKDF_INFO "ESPfuscateV0.1"
#endif

#ifndef OBF_NVS_NAMESPACE
#define OBF_NVS_NAMESPACE "ESPfuscate"
#endif

#ifndef OBF_NVS_ROOTKEY
#define OBF_NVS_ROOTKEY "rk32"
#endif

#ifndef OBF_SALT
#define OBF_SALT "sofnir"//0xA5C3F19Du
#warning "Using default parameter! For better security, define your own OBF_SALT. (ex.: in build flags -DOBF_SALT=0x12345678u)"
#endif

#ifndef OBF_PEPPER
#define OBF_PEPPER "38hx2g03421j4h1g5ap"
#warning "Using default parameter! For better security, define your own OBF_PEPPER. (ex.: in build flags -DOBF_PEPPER=\"my_secret_pepper\" )"
#endif

namespace ESPfuscate {

// -------------------- wipe (best effort) --------------------
void secure_bzero(void* p, size_t n);

// -------------------- compile-time helpers --------------------
constexpr uint32_t fnv1a32(const char* s, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; ++i) {
    h ^= static_cast<uint8_t>(s[i]);
    h *= 16777619u;
  }
  return h;
}

constexpr uint32_t rotl32(uint32_t x, unsigned r) {
  return (x << r) | (x >> (32u - r));
}

constexpr uint32_t mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

static constexpr uint32_t pepper_hash = fnv1a32(OBF_PEPPER, sizeof(OBF_PEPPER) - 1);

struct XorStream {
  uint32_t s;
  constexpr explicit XorStream(uint32_t seed) : s(seed) {}
  constexpr uint8_t next() {
    uint32_t x = s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s = x;
    return static_cast<uint8_t>(x & 0xFFu);
  }
};

constexpr uint32_t salt_from_occurrence(uint32_t counter, uint32_t line, uint32_t file_hash) {
  uint32_t x = 0x9E3779B9u;
  x ^= rotl32(counter * 0x85ebca6bu, 7);
  x ^= rotl32(line    * 0xc2b2ae35u, 11);
  x ^= file_hash;
  x ^= (uint32_t)OBF_SALT;
  return mix32(x);
}

// -------------------- compile-time obfuscated literal --------------------
template <size_t N>
struct ObfLit {
  std::array<uint8_t, N> enc{};
  uint32_t seed_base{0};
  uint32_t salt_occ{0};

  constexpr ObfLit(const char (&plain)[N], uint32_t salt_occ_)
    : seed_base(mix32(pepper_hash ^ uint32_t(N) ^ 0x31415927u)), salt_occ(salt_occ_)
  {
    XorStream xs(mix32(seed_base ^ salt_occ));
    for (size_t i = 0; i < N; ++i)
      enc[i] = static_cast<uint8_t>(plain[i]) ^ xs.next();
  }

  // Raw bytes: no terminator
  inline void decrypt_bytes(uint8_t* out, size_t out_cap) const {
    if (!out || out_cap == 0) return;
    const size_t n = (out_cap < N) ? out_cap : N;
    XorStream xs(mix32(seed_base ^ salt_occ));
    for (size_t i = 0; i < n; ++i) out[i] = enc[i] ^ xs.next();
  }

  SecureBuffer<N> decrypt_bytes() const {
    SecureBuffer<N> buf;
    decrypt_bytes(buf.data(), buf.size());
    return buf;
  }

  // C-string: guarantees '\0'
  inline void decrypt_string(char* out, size_t out_cap) const {
    if (!out || out_cap == 0) return;
    const size_t max_copy = out_cap - 1;
    const size_t n = (max_copy < N) ? max_copy : N;
    XorStream xs(mix32(seed_base ^ salt_occ));
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<char>(enc[i] ^ xs.next());
    out[n] = '\0';
  }

  SecureBuffer<N> decrypt_string() const {
    SecureBuffer<N> buf;
    decrypt_string(buf.c_str(), buf.size());
    return buf;
  }

  static constexpr size_t plain_size = N;
};

#define OBFUSCATE_FILEHASH (ESPfuscate::fnv1a32(__FILE__, sizeof(__FILE__) - 1))
#define OBFUSCATE_SALT_OCC (ESPfuscate::salt_from_occurrence((uint32_t)__COUNTER__, (uint32_t)__LINE__, (uint32_t)OBFUSCATE_FILEHASH))
#define OBFUSCATE(str_lit) (ESPfuscate::ObfLit<sizeof(str_lit)>(str_lit, (uint32_t)OBFUSCATE_SALT_OCC))

//-------------------- SecureBuffer RAII --------------------
template <size_t N>
struct SecureBuffer {
  std::array<uint8_t, N> b{};
  uint8_t* data() { return b.data(); }
  const uint8_t* data() const { return b.data(); }
  char* c_str() { return reinterpret_cast<char*>(b.data()); }
  size_t size() const { return b.size(); }
  ~SecureBuffer() { secure_bzero(b.data(), b.size()); }
};

// -------------------- sealed container --------------------
struct Sealed {
    uint8_t version = 1;
    std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 16> tag{};
    uint8_t* ct = nullptr;   
    uint16_t ct_capacity = 0; 
    uint16_t pt_len = 0;    

    protected:
        Sealed(uint8_t* storage, uint16_t cap) : ct(storage), ct_capacity(cap) {}
};

// La classe "Plug & Play" per l'utente: alloca la memoria sullo stack
template <size_t N>
struct SealedBuffer : public Sealed {
    uint8_t storage[N]; // La memoria fisica è qui!

    SealedBuffer() : Sealed(storage, N) {
        memset(storage, 0, N);
    }

    ~SealedBuffer() {
        // Pulizia automatica della memoria quando esce dallo scope
        ESPfuscate::secure_bzero(storage, N);
    }
};

// -------------------- runtime engine (implemented in .cpp) --------------------
class RunTimeStore {
public:
  // NVS init must be done by the application (nvs_flash_init), but this is harmless.
  esp_err_t begin(bool force_key_overwrite = false);

  bool ready() const;

  esp_err_t seal_bytes(const uint8_t* pt, size_t pt_len, Sealed& out, const char* aad = OBF_HKDF_INFO, size_t aad_len = sizeof(OBF_HKDF_INFO) - 1) const;

  esp_err_t seal_string(const char* pt, Sealed& out, const char* aad = OBF_HKDF_INFO, size_t aad_len = sizeof(OBF_HKDF_INFO) - 1) const;

  // Open arbitrary bytes (no terminator)
  esp_err_t open_bytes(const Sealed& in, uint8_t* pt_out, size_t pt_cap, const char* aad = OBF_HKDF_INFO, size_t aad_len = sizeof(OBF_HKDF_INFO) - 1) const;

  // Open as C-string: guarantees '\0' (requires out_cap >= in.pt_len + 1)
  esp_err_t open_string(const Sealed& in, char* out, size_t out_cap, const char* aad = OBF_HKDF_INFO, size_t aad_len = sizeof(OBF_HKDF_INFO) - 1) const;

  void flush();

  ~RunTimeStore();

private:  // Internal function to derive the encryption key from root and chip info. Called by begin() if needed.

  int derive_key_from_root_and_chip();

  std::array<uint8_t, 32> root_{};
  std::array<uint8_t, 32> key_{};
  bool key_ready_{false};

// Simple mutex for thread safety (e.g. if begin() is called while another operation is in progress)
  StaticSemaphore_t mutex_buf_{};
  SemaphoreHandle_t mutex_{nullptr};

  inline void ensure_mutex_() {
    if (mutex_ == nullptr)  mutex_ = xSemaphoreCreateMutexStatic(&mutex_buf_);
  }

  struct LockGuard {
    RunTimeStore& s;
    explicit LockGuard(RunTimeStore& store) : s(store) {
      s.ensure_mutex_();
      xSemaphoreTake(s.mutex_, portMAX_DELAY);
    }
    ~LockGuard() {
      xSemaphoreGive(s.mutex_);
    }
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
  };
};

} // namespace ESPfuscate
