#ifndef CHACHA20_H
#define CHACHA20_H

#include <iomanip>

class ChaCha20 {
public:
    static void encrypt(uint8_t* output, const uint8_t* key_bytes, const uint8_t* nonce_bytes, const uint8_t* plaintext, size_t len);

private:
    static uint32_t left_rotate(uint32_t value, size_t n);
    static void q_round(uint32_t* state, size_t a, size_t b, size_t c, size_t d);
    static void inner_block(uint32_t* state);
    static void chacha20_block(const uint32_t* key, uint32_t counter, const uint32_t* nonce, uint32_t* output);
    static void serialize(const uint32_t* state_array, uint8_t* output);
    static void bytes_to_uint32_array(const uint8_t* data, uint32_t* output, size_t length);

    static const uint32_t CONSTANTS[4];
};

#endif // CHACHA20_H

const uint32_t ChaCha20::CONSTANTS[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

uint32_t ChaCha20::left_rotate(uint32_t value, size_t n) {
    n %= 32;
    return (value << n) | (value >> (32 - n));
}

void ChaCha20::q_round(uint32_t* state, size_t a, size_t b, size_t c, size_t d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = left_rotate(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = left_rotate(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = left_rotate(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = left_rotate(state[b], 7);
}

void ChaCha20::inner_block(uint32_t* state) {
    q_round(state, 0, 4, 8, 12);
    q_round(state, 1, 5, 9, 13);
    q_round(state, 2, 6, 10, 14);
    q_round(state, 3, 7, 11, 15);

    q_round(state, 0, 5, 10, 15);
    q_round(state, 1, 6, 11, 12);
    q_round(state, 2, 7, 8, 13);
    q_round(state, 3, 4, 9, 14);
}

void ChaCha20::chacha20_block(const uint32_t* key, uint32_t counter, const uint32_t* nonce, uint32_t* output) {
    uint32_t state_array[16];
    for (int i = 0; i < 4; i++) {
        state_array[i] = CONSTANTS[i];
    }
    for (int i = 4; i < 12; i++) {
        state_array[i] = key[i-4];
    }
    state_array[12] = counter;
    for (int i = 13; i < 16; i++) {
        state_array[i] = nonce[i-13];
    }

    uint32_t working_state[16];
    for (int i = 0; i < 16; i++) {
        working_state[i] = state_array[i];
        output[i] = state_array[i];
    }

    for (int c = 0; c < 10; c++) {
        inner_block(working_state);
    }

    for (int i = 0; i < 16; i++) {
        output[i] += working_state[i];
    }
}

void ChaCha20::serialize(const uint32_t* state_array, uint8_t* output) {
    for (int i = 0; i < 16; ++i) {
        output[i * 4]     = (state_array[i] & 0x000000FF);
        output[i * 4 + 1] = (state_array[i] & 0x0000FF00) >> 8;
        output[i * 4 + 2] = (state_array[i] & 0x00FF0000) >> 16;
        output[i * 4 + 3] = (state_array[i] & 0xFF000000) >> 24;
    }
}

void ChaCha20::bytes_to_uint32_array(const uint8_t* data, uint32_t* output, size_t length) {
    // Преобразуем каждые 4 байта в один uint32_t с учетом little-endian порядка
    for (size_t i = 0; i < length / 4; i++) {
        output[i] = data[i * 4] | (data[i * 4 + 1] << 8) | (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24);
    }
}

void ChaCha20::encrypt(uint8_t* output, const uint8_t* key_bytes, const uint8_t* nonce_bytes, const uint8_t* plaintext, size_t len) {
    
    uint32_t key[8];
    uint32_t nonce[3];

    uint8_t counter = 1;

    bytes_to_uint32_array(key_bytes, key, 32);
    bytes_to_uint32_array(nonce_bytes, nonce, 12);
    
    // uint8_t* ciphertext = new uint8_t[len];
    for (int j = 0; j < floor(len/64); ++j) {
        uint32_t block_output[16];
        uint8_t keystream[64];
        chacha20_block(key, counter+j, nonce, block_output);
        serialize(block_output, keystream);

        const uint8_t* block = plaintext + j * 64;
        for (size_t i = 0; i < 64; ++i) {
            output[i+j*64] = block[i] ^ keystream[i];
        }
    }

    if (len % 64 != 0) {
        uint32_t block_output[16];
        uint8_t keystream[64];
        chacha20_block(key, counter + (len / 64), nonce, block_output);
        serialize(block_output, keystream);
        const uint8_t* block = plaintext + (len / 64) * 64;
        for (size_t i = 0; i < len % 64; i++) {
            output[i + (len / 64) * 64] = block[i] ^ keystream[i];
        }
    }
}

// int main() {

//     uint8_t key[32] = {
//         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
//     };
//     uint8_t nonce[12] = {
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
//         0x00, 0x00, 0x00, 0x00
//     };
//     uint32_t counter = 1;

//     uint8_t plaintext[] = {
//         0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
//         0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
//         0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
//         0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
//         0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
//         0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
//         0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
//         0x74, 0x2e
//     };

//     size_t plaintext_len = sizeof(plaintext) / sizeof(plaintext[0]);

//     uint8_t* ciphertext = chacha20_encrypt(key, counter, nonce, plaintext, plaintext_len);

//     std::cout << ">>>>>>> Ciphertext: >>>>>>>\n\n";
//     for (size_t i = 0; i < plaintext_len; ++i) {
//         std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i] << " ";
//         if ((i + 1) % 16 == 0) std::cout << std::endl;
//     }
//     std::cout <<  std::endl << std::endl << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << std::endl;

//     // Освобождение памяти
//     delete[] ciphertext;

//     return 0;
// }
