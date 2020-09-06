#include "aws_certificate.h"

// Replace your broker here
const char * m_arn = "ats.iot.ap-southeast-1.amazonaws.com";

// Replace your port
const uint16_t m_mqtt_port = 8883;

// Replace your cert here
static const unsigned char * m_root_ca = "-----BEGIN CERTIFICATE-----\n\
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n\
rqXRfboQnoZsG4q5WTP468SQvvG5\n\
-----END CERTIFICATE-----";

// Replace your cert here
static const unsigned char * m_client_cert = "-----BEGIN CERTIFICATE-----\n\
MIIDWjCCAkKgAwIBAgIVAIbb/R9GqyZ2cDjeZaqifS9zRGXjMA0GCSqGSIb3DQEB\n\
-----END CERTIFICATE-----";

// Replace your cert here
static const unsigned char * m_private_key = "-----BEGIN RSA PRIVATE KEY-----\n\
-----END RSA PRIVATE KEY-----";

const unsigned char * aws_certificate_get_root_ca(void)
{
    return m_root_ca;
}


const unsigned char * aws_certificate_get_client_cert(void)
{
    return m_client_cert;
}

const unsigned char * aws_certificate_get_client_key(void)
{
    return m_private_key;
}

const char * aws_get_arn(void)
{
    return m_arn;
}

uint16_t aws_get_mqtt_port(void)
{
    return m_mqtt_port;
}

