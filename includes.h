#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring> // Для memset
#include <unistd.h> // Для close
#include <arpa/inet.h> // Для сокетов
#include <sys/socket.h>

#include "XMSS/XMSS.h" // Подпись XMSS
#include "XMSS_handling.h"

#define IP "127.0.0.1"
#define PORT 8080