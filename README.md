<p align="center">
  <img src="docs/image.jpg" alt="ESPfuscate logo" width="800">
</p>

# 🛡️ ESPfuscate

[![PlatformIO Registry](https://img.shields.io/badge/PlatformIO-Registry-orange?logo=platformio)](https://registry.platformio.org/)
[![Framework](https://img.shields.io/badge/Framework-Arduino%20%7C%20ESP--IDF-blue)](https://github.com/espressif/esp-idf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Compile Verification](https://github.com/AndreaDV01/ESPfuscate/actions/workflows/compile.yml/badge.svg?event=push)](https://github.com/AndreaDV01/ESPfuscate/actions/workflows/compile.yml)

**ESPfuscate** is a lightweight security library for the ESP32 ecosystem designed to protect sensitive strings such as API keys, WiFi credentials, and authentication tokens.

It combines **compile-time obfuscation** and **hardware-bound runtime encryption** to make firmware extraction and cloning attacks significantly harder.

**ESPfuscate** is compatible with both **Arduino** and **ESP-IDF** frameworks and is designed to have **minimal runtime overhead**.

---

## 💭 The problem
Many ESP32 projects embed secrets directly inside the firmware.

When a global variable or `#define` is declared, that value ends up directly inside the compiled `firmware.bin` file in **plain text**.

This becomes critical when those values include API endpoints, passwords, tokens, or other sensitive data, because it's as easy as open the file `.bin` as a text file to read them.

## 💡 The solution
Espressif already solved this problem with ***Flash Encryption***, but it has 2 major limitations.

#### 1️⃣ The encryption is on the HW
The encryption is executed on the ESP32 after the uploading process, so your binary file is still vulnerable, if not in the HW.

#### 2️⃣ It's not reversible
If you activate this feature you are burning an Efuse forever *( for security reason )*, so no afterthoughts.

## 🚀 So why ESPfuscate?

**ESPfuscate** is intended for simple or moderately sensitive applications, when you want to protect secrets without building an unbreakable security system.

You can always redesign or upgrade the security strategy of your device without permanently locking the hardware. This is precious in small projects or first iterations.



**ESPfuscate** addresses this problem with a **two-layer protection model**.


#### 1️⃣ Compile-Time Obfuscation
Secret strings are transformed during compilation so they never appear in plaintext inside the final firmware binary.

#### 2️⃣ Hardware-Bound Encryption
At runtime, secrets are encrypted using an AES-256-GCM key derived from:

- a **device root key stored in NVS**
- the **unique ESP32 eFuse MAC address**
- optional **build-time SALT and PEPPER**

This ensures that encrypted data generated on one device **cannot be decrypted on another device**.

---

## ✨ Key Features

| Feature | Implementation | Benefit |
| :--- | :--- | :--- |
| Cryptography | AES-256-GCM | Authenticated encryption (confidentiality + integrity) |
| Key Derivation | HMAC-SHA256 | Secure hardware-bound key derivation |
| Memory Safety | `mbedtls_platform_zeroize` | Sensitive data wiped from RAM after use |
| Deterministic Memory Usage | Template-based buffers | No heap allocations (`malloc` / `new`) |
| Hardware Binding | eFuse MAC address | Prevents firmware cloning attacks |

---

## 📦 Installation

### PlatformIO (Recommended)

Add the library to your `platformio.ini`:

```ini
lib_deps =
    https://github.com/AndreaDV01/ESPfuscate.git
```

---

## 🔧 Build-Time Security Customization

**ESPfuscate** allows customizing the key derivation parameters at build time.

Define your own SALT and PEPPER values in your build configuration.

Example for PlatformIO:

```ini
build_flags =
    -DOBF_SALT=\"MyCustomSalt_8923\"
    -DOBF_PEPPER=\"SuperSecretCompanyPepper_2024\"
```

These values ensure that firmware builds are **globally unique**.

⚠️ **Important**

Changing these values after a device has already encrypted data will make previously encrypted data unreadable.

---

## 🧠 Threat Model

**ESPfuscate** is designed to protect against:

- firmware extraction
- flash memory dumps
- firmware cloning attacks
- static analysis of firmware binaries

**ESPfuscate** does NOT protect against:

- physical compromise of the device
- runtime debugging attacks
- invasive hardware attacks
- full system compromise

For production systems, **ESPfuscate** should be used **together with ESP32 hardware security features**.

---

## 🔐 Recommended Security Setup

For maximum protection combine **ESPfuscate** with:

- **ESP32 Flash Encryption**
- **Secure Boot**
- **Encrypted OTA updates**

See the official Espressif documentation:

https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/security/index.html

---

## 🛠️ Contributing

Contributions, issues, and feature requests are welcome.

If you plan to propose significant changes, please open an issue first to discuss the design.

---

## 📄 License

This project is licensed under the **MIT License**.
