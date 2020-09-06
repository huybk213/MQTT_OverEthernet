#ifndef APP_DEBUG_H
#define APP_DEBUG_H

#include "SEGGER_RTT.h"

#define	DebugPrint(String...)	SEGGER_RTT_printf(0, String)

#endif /* APP_DEBUG_H */
