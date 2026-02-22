# ESPfuscate

ESPfuscate is a lightweight security utility for ESP32-based systems
designed to protect sensitive data stored on the device and reduce
exposure of secrets in firmware binaries.

It combines runtime encryption with compile-time string obfuscation to
provide layered protection suitable for embedded environments with
limited resources.

------------------------------------------------------------------------

## Features

-   AES-256-GCM authenticated encryption
-   Device-bound key derivation
-   Compile-time string obfuscation
-   OTA credential protection
-   ESP-IDF and Arduino compatible
-   Designed for low overhead embedded deployment

------------------------------------------------------------------------

## Security Model

ESPfuscate is designed to protect:

-   WiFi credentials
-   API tokens
-   OTA authentication data
-   Local configuration secrets

It mitigates:

-   Flash dumping
-   Firmware extraction
-   Static binary inspection
-   Accidental credential exposure

It does NOT protect against:

-   Physical invasive attacks
-   Compromised bootloaders
-   Fully privileged runtime attackers

Security in embedded systems is always layered. ESPfuscate is one layer,
not the entire defense strategy.

------------------------------------------------------------------------

## Flash Encryption (IMPORTANT)

ESP32 Flash Encryption is the strongest protection available against
firmware extraction.

Without Flash Encryption: - Encrypted data blobs can still be copied
from flash - Attackers can perform offline analysis - Reverse
engineering risk remains significant

With Flash Encryption enabled: - Flash contents are encrypted at rest -
Keys never leave the chip - Firmware dumping becomes significantly
harder

ESPfuscate is designed to work without Flash Encryption, but enabling
Flash Encryption is strongly recommended for production devices.

------------------------------------------------------------------------

## OTA Server Security (CRITICAL)

Securing OTA updates is mandatory.

If the OTA server is compromised, attackers can deploy malicious
firmware regardless of device-side protections.

Recommended protections:

-   HTTPS with certificate validation
-   Signed firmware images
-   Server authentication tokens
-   Restricted OTA endpoints
-   Update integrity verification

Device encryption alone cannot protect against a malicious firmware
update.

OTA security must be treated as part of the trusted computing base.

------------------------------------------------------------------------

## Compile-Time Obfuscation

Compile-time obfuscation hides plaintext strings from firmware binaries.

This protects against:

-   Basic reverse engineering
-   Firmware string scanning
-   Credential harvesting from extracted binaries

Important clarification:

Obfuscation is NOT encryption.

It prevents easy discovery, not determined analysis.

------------------------------------------------------------------------

## Key Derivation

Keys are derived per-device using hardware identifiers and a build-time
secret (PEPPER).

This ensures:

-   Each device has unique encryption keys
-   Data copied between devices cannot be decrypted
-   No static keys embedded in firmware

The PEPPER must be supplied at build time and never committed to version
control.

------------------------------------------------------------------------

## Best Practices

-   Enable Flash Encryption in production
-   Use secure OTA infrastructure
-   Protect build secrets
-   Use different credentials per device when possible
-   Restrict physical access to hardware
-   Audit firmware update pipelines

Security is a system property, not a library feature.

------------------------------------------------------------------------

## Limitations

-   Not a full secure element replacement
-   Does not prevent side-channel attacks
-   Does not replace secure boot
-   Does not protect against privileged firmware execution

------------------------------------------------------------------------

## License

Specify your license here (MIT / Apache 2.0 / etc).


platformio.ini example:

[env:OBFUSCATE_ESP32]
platform = espressif32
board = esp32dev ;esp32-s3-devkitc-1 ;dfrobot_beetle_esp32c3
framework = arduino

build_unflags = -std=gnu++11

build_flags = -std=gnu++17
              ;-DOBF_BUILD_SALT=0X3F2A91C7
              ;-DOBF_PEPPER=\mypepper\"
              ;-DOBF_MAX_CT=256

monitor_speed = 115200

