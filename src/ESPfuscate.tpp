/*
  ESPfuscate template implementation.

  This file contains inline/template wrappers for:
  - seal()
  - open()
  - typed buffer helpers

  The heavy cryptographic logic is implemented in ESPfuscate.cpp
  to reduce template code duplication.
*/
#pragma once

extern "C" {
  #include "esp_err.h"
}

namespace ESPfuscate {

template <size_t N>
esp_err_t RTobf::seal(const char* pt, SealedBuffer<N>& out,
                             const char* aad, size_t aad_len) const {
    if (!pt) return ESP_ERR_INVALID_ARG;
    return seal(reinterpret_cast<const uint8_t*>(pt), std::strlen(pt), out, aad, aad_len);
}

template <size_t N>
esp_err_t RTobf::seal(const uint8_t* pt, size_t pt_len, SealedBuffer<N>& out,
                             const char* aad, size_t aad_len) const {
    return sealBytesImpl(pt, pt_len, out.version,
                         out.data(), out.size(),
                         out.pt_len, out.nonce.data(),
                         out.tag.data(), aad, aad_len);
}

template <size_t N>
esp_err_t RTobf::open(const SealedBuffer<N>& in, TempBuffer<N>& out,
                             const char* aad, size_t aad_len) const {
    return open(in, out.data(), out.size(), aad, aad_len);
}

template <size_t N>
esp_err_t RTobf::open(const SealedBuffer<N>& in, uint8_t* pt_out, size_t pt_cap,
                                  const char* aad, size_t aad_len) const {
    if(in.version != detail::OBF_FORMAT_VERSION) return ESP_ERR_INVALID_VERSION;
        
    return openBytesImpl(in.data(), in.size(), in.version,
                         in.pt_len, in.nonce.data(), in.tag.data(),
                         pt_out, pt_cap, aad, aad_len);
}

template <size_t N>
esp_err_t RTobf::open(const SealedBuffer<N>& in, char* out, size_t out_cap,
                                   const char* aad, size_t aad_len) const {
    if (!out || out_cap == 0) return ESP_ERR_INVALID_ARG;
    if (static_cast<size_t>(in.pt_len) + 1 > out_cap) return ESP_ERR_INVALID_SIZE;

    esp_err_t err = open(in, reinterpret_cast<uint8_t*>(out), in.pt_len, aad, aad_len);
    if (err != ESP_OK) return err;

    out[in.pt_len] = '\0';
    return ESP_OK;
}

} // namespace ESPfuscate