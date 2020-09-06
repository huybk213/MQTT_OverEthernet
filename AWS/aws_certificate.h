#ifndef AWS_CERTIFICATE_H
#define AWS_CERTIFICATE_H

#include "stdint.h"

/**
 * @brief Get your AWS broker ARN
 */
const char * aws_get_arn(void);

/**
 * @brief Get your AWS ROOTCA certificate string
 */
const unsigned char * aws_certificate_get_root_ca(void);

/**
 * @brief Get your AWS ROOTCA certificate string
 */
const unsigned char * aws_certificate_get_client_cert(void);

/**
 * @brief Get your AWS ROOTCA certificate string
 */
const unsigned char * aws_certificate_get_client_key(void);

/**
 * @brief Get your AWS MQTT port
 */
uint16_t aws_get_mqtt_port(void);

#endif /* AWS_CERTIFICATE_H */
