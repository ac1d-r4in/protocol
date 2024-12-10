#include "includes.h"

std::vector<unsigned char> stringToVector(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}