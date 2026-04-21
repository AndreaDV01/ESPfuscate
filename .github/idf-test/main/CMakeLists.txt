idf_component_register(
    SRCS "main.cpp"
    INCLUDE_DIRS "."
    REQUIRES ESPfuscate esp_http_client esp_wifi esp_event esp_netif nvs_flash
)