#ifndef APP_MQTT_H
#define APP_MQTT_H

#include <stdint.h>
#include <stdbool.h>

typedef enum
{
    APP_MQTT_DISCONNECTED = 0x00,
    APP_MQTT_RESOLVING_HOST_NAME,
    APP_MQTT_CONNECTING,
    APP_MQTT_CONNTECTED,
    APP_MQTT_LOGINED
} app_mqtt_state_t;

void app_mqtt_client_init(void);

#endif /* APP_MQTT_H */
