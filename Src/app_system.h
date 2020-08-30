#ifndef APP_SYSTEM_H
#define APP_SYSTEM_H

#include <stdint.h>

typedef struct
{
    Parameter_t Parameters;
    ServerState_t ServerState;
    RTC_PERIPHERAL *Rtc;
    GlobalStatus_t GLStatus;
    app_ota_info_t ota;
    FileTransfer_t FileTransfer;
} System_t;

#endif /* APP_SYSTEM_H */

