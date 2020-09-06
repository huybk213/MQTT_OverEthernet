#include "aws_certificate.h"

const char * m_arn = "a2fpu8zc49udz1-ats.iot.ap-southeast-1.amazonaws.com";
const uint16_t m_mqtt_port = 8883;

static const char * m_root_ca = "-----BEGIN CERTIFICATE-----\n\
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n\
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n\
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n\
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n\
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n\
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n\
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n\
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n\
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n\
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n\
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n\
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n\
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n\
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n\
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n\
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n\
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n\
rqXRfboQnoZsG4q5WTP468SQvvG5\n\
-----END CERTIFICATE-----";

static const char * m_client_cert = "-----BEGIN CERTIFICATE-----\n\
MIIDWjCCAkKgAwIBAgIVAIbb/R9GqyZ2cDjeZaqifS9zRGXjMA0GCSqGSIb3DQEB\n\
CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n\
IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0yMDA3MDcwNDU2\n\
MjlaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n\
dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9HZKJTXMYH66JFwer\n\
b1LeoyJK7D0hQUG6ioDqHaCpwuAXPB+styW3kUzxp5TfE7ut1MqwRoylXGo0/qzf\n\
mL08AMGACmXa/WsbU2nhNKH/q9MbluNLT/k8TbvkhBJ4JslXXgtIyP/QOaUHh8aj\n\
EH8P8JJwcFg9dSxVzxb+OgzyRciqexQ/Dga/yq2u91Ie/QUdknynk1PdStewPnMM\n\
HHPZO+JFJxA4wAZ7G7ZY0NZY3i/aiJF0TgSbyIML2118mjVh0GGnEeFxQuN5vP2E\n\
mqelgZ2dj1CMxjIb0SuLR1zVkCxt4EGjWdJQXbkoRtTO582dX+sFJt1J2/zzpRIb\n\
bn99AgMBAAGjYDBeMB8GA1UdIwQYMBaAFFJEaISt+QJLn05x8h7kXmC5WaQpMB0G\n\
A1UdDgQWBBTDbhvXhcvLAL4IF3VFplJmYp6oAjAMBgNVHRMBAf8EAjAAMA4GA1Ud\n\
DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAkoyQM99ZVZKkgkzQN5pii64M\n\
2yZpWt2fWjpe6iyX5ljzCEi7WdX0un0bzTjPw/GKLSiBnQXnpNnKQfvdvxmHP8A+\n\
O4ecT5o+xuMxKlqHdnd1TR3vbvr+kdc82CMnIwL7FopGN6D6uWrDDtwL2H1bhx+B\n\
bGhXYcZjXAIzkKJcc/nTcn4kgZKUvT0TEE2HT6F/nw4IBstWuStq+mSszQZf5uMy\n\
zsW6qalZUWZf+BuAErKTw57UVFsJQG5IncSDWaObn70GCkrLNIHBrpPNIF5UO8Jt\n\
7oFF/5CFcihDKxuueTjBeaOlmnhXy951sQSG3tBo8SyxrM09IMK4krTUHVV/aQ==\n\
-----END CERTIFICATE-----";

static const char * m_private_key = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAvR2SiU1zGB+uiRcHq29S3qMiSuw9IUFBuoqA6h2gqcLgFzwf\n\
rLclt5FM8aeU3xO7rdTKsEaMpVxqNP6s35i9PADBgApl2v1rG1Np4TSh/6vTG5bj\n\
S0/5PE275IQSeCbJV14LSMj/0DmlB4fGoxB/D/CScHBYPXUsVc8W/joM8kXIqnsU\n\
Pw4Gv8qtrvdSHv0FHZJ8p5NT3UrXsD5zDBxz2TviRScQOMAGexu2WNDWWN4v2oiR\n\
dE4Em8iDC9tdfJo1YdBhpxHhcULjebz9hJqnpYGdnY9QjMYyG9Eri0dc1ZAsbeBB\n\
o1nSUF25KEbUzufNnV/rBSbdSdv886USG25/fQIDAQABAoIBAHO5rPooUs3oVT2+\n\
wgq+TM/AtDN07NN0w2wLZWfeSXqYrdiKCjf+uy3h1FvsWMVJpgdxt7a29Uobi0Jy\n\
tgb9yI73R3G66yle+jP2j0wokRmLY9v2MZDcl3+3ccscptCvq3WzLuSTWzdojvxU\n\
sdEHPznZ1ULI/LZfBYpc940KqPF3hM5Y+ruc/ETdRtX4ekfdzt6FObv6wbphNMRG\n\
vW0UkNq52TclCIYij+W+hiaM3ZEv+/CcJZJDgp+sBLC8nSs+iuaygeQ+iaMJJmKd\n\
wMjod+0Nfc7qfcrJYkMwhWKLG22HqXUhmwDGQxtxTI37XIPwcWyPKPu++O5bzw7W\n\
aYwb5QECgYEA6gk52FqDaqPJFh3zstVw15DshFHus7BIcVQ1JP8D3Q9eAnxH7HDL\n\
HAAd8/heg4F2cyh5uRzEyrVPGLtPsddFzH7fK9P4aGbzzgb44D1FepyUw/NLM0zc\n\
+cTM5tttjrXZvzzqbcW8UvL6SDeQbm2N1fZ5+Qnaw3qyGeV07KztY7UCgYEAzt0e\n\
p5Bvfm1y1eYYthy1wTVMFxG+/bK8V0+NthoN7dzYsPMdi8joQ4orFQWuTSJjNd/Q\n\
TKHU+o5+foHEHPcDeuE49LjMEYRXgDSxZu0WxDWtM8VHWj3FfepT7fSId9DyfPC/\n\
zDC+nYjenYbMs0q/gYBjymLPka5ZI/78drbvGakCgYBlDqTOuo7inmS3SymvACFg\n\
w/CNVn+3UZiGbzEfj4qQixEyC45XF4FsztQgRBAzwtRt931QJI8JZO8Jo+BOz8ER\n\
A3vEhhxOoJ4ISdRvp6V3w2MtlcHUHg2RQJyl1vxg0j97J4em7Opb+xV915hjRqUn\n\
Te3vToULQdDkA8PQav96vQKBgQCVUMRUvQvNXSEbxjemE/kZmefvau7KXt5Vw2WN\n\
wSa2v8dlikaUZJNKVQwd43jZ0m18MK5A8jsyE/K4S+CL67yGUNV0x4L9TeJ+9wnq\n\
Ok5JmFkJ2mdTeuz3o1Grm+t5WMf/aSN4NuMQAQB3Ahr1e4nZ5xugtUwQYqGTOvVu\n\
l0Lk6QKBgQC2fJhM8deM1WLkMgVH+dSUB8J1lRCH48eys/nVE1DASl97xomV8zAa\n\
QWxXz9GeUY1+ExQNFqC/u294hIg6IY9aKktToraKk5tmyAaRQhqSl7CABzlQgWlQ\n\
jvRIj29HDnkQw0poT/1/1ePSL6xHkVWMwqraffRmLayFCfxVFxAwbQ==\n\
-----END RSA PRIVATE KEY-----";

const char * aws_certificate_get_m_root_ca(void)
{
    return m_root_ca;
}

/**
 * @brief Get your AWS ROOTCA certificate string
 */
const char * aws_certificate_get_client_cert(void)
{
    return m_client_cert;
}

/**
 * @brief Get your AWS ROOTCA certificate string
 */
const char * aws_certificate_get_client_key(void)
{
    return m_private_key;
}

const char * aws_get_arn(void)
{
    return m_arn;
}

const uint16_t aws_get_mqtt_port(void)
{
    return m_mqtt_port;
}

