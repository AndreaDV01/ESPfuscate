idf_component_register(
    SRCS "src/ESPfuscate.cpp"
    INCLUDE_DIRS "src"
    REQUIRES mbedtls nvs_flash esp_hw_support
)