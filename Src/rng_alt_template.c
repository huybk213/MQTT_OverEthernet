
/**
  *  Portions COPYRIGHT 2018 STMicroelectronics, All Rights Reserved
  *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
  *
  ******************************************************************************
  * @file    rng_alt_template.c
  * @author  MCD Application Team
  * @brief   mbedtls alternate entropy data function.
  *          the mbedtls_hardware_poll() is customized to use the STM32 RNG
  *          to generate random data, required for TLS encryption algorithms.
  *
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2018 STMicroelectronics
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under Apache 2.0 license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  * https://opensource.org/licenses/Apache-2.0
  *
  ******************************************************************************
  */

#include "mbedtls/entropy_poll.h"
#include "mbedtls/platform.h"
#include "stdint.h"
#include MBEDTLS_CONFIG_FILE

/*
 * include the correct headerfile depending on the STM32 family */

#include "main.h"

extern RNG_HandleTypeDef RngHandle;
int mbedtls_hardware_poll( void *Data, unsigned char *Output, size_t Len, size_t *oLen )
{
  uint32_t index;
  uint32_t randomValue;
		
  for (index = 0; index < Len/4; index++)
  {
    if (HAL_RNG_GenerateRandomNumber(&RngHandle, &randomValue) == HAL_OK)
    {
      *oLen += 4;
      memset(&(Output[index * 4]), (int)randomValue, 4);
    }
    else
    {
      assert_failed(__FILE__, __LINE__);
    }
  }
  
  return 0;
}


//char ran_buf[64];
////char *temp = �somerandom stringi havegivenasthesource�;
//int mbedtls_platform_std_nv_seed_read( unsigned char *buf, size_t buf_len )
//{
//    rand_hw_rng_get(buf, buf_len);
//    return( buf_len );
//}

//int mbedtls_platform_std_nv_seed_write( unsigned char *buf, size_t buf_len )
//{
//    memcpy(ran_buf, buf, buf_len > 64 ? 64 : buf_len);
//    return( buf_len );
//}
