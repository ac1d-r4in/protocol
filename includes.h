#pragma once

#define IP "127.0.0.1"
#define PORT 8000

#define CURVE25519_KEY_LEN 32
#define CHACHA20_KEY_LEN 32
#define CHACHA20_NONCE_LEN 12

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring> // Для memset
#include <unistd.h> // Для close
#include <arpa/inet.h> // Для сокетов
#include <sys/socket.h>

#include "XMSS/XMSS.h" // Подпись XMSS
#include "CURVE25519/curve25519.h"
#include "CHACHA20/chacha20.h"

#include "handling.h"