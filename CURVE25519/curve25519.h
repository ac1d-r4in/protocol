#ifndef CURVE25519_H
#define CURVE25519_H

#include <stdio.h>
#include <string.h>
#include <random>

typedef unsigned char u8;
typedef long long i64;
typedef i64 field_elem[16];
typedef unsigned long long u64;

class Curve25519 {
private:
    static const field_elem _121665;
    static const u8 _9[32];

    static void scalarmult(u8 *out, const u8 *scalar, const u8 *point);
    static void randombytes(u8 *buf, u64 size);
    static void unpack25519(field_elem out, const u8 *in);
    static void carry25519(field_elem elem);
    static void fadd(field_elem out, const field_elem a, const field_elem b);
    static void fsub(field_elem out, const field_elem a, const field_elem b);
    static void fmul(field_elem out, const field_elem a, const field_elem b);
    static void finverse(field_elem out, const field_elem in);
    static void swap25519(field_elem p, field_elem q, int bit);
    static void pack25519(u8 *out, const field_elem in);
    static void scalarmult_base(u8 *out, const u8 *scalar);
    // static void print_hex(const char *label, const u8 *data, size_t size);

public:
    static void generate_keypair(u8 *pk, u8 *sk);
    static void x25519(u8 *out, const u8 *pk, const u8 *sk);
};

#endif

const field_elem Curve25519::_121665 = {0xDB41, 1};
// extern void randombytes(u8 *, u64);
const u8 Curve25519::_9[32] = {9};

void Curve25519::randombytes(u8 *buf, u64 size) {
    std::random_device rd; // Источник случайности
    std::mt19937 gen(rd()); // Генератор случайных чисел
    std::uniform_int_distribution<> dis(0, 255); // Диапазон: 0-255 (байты)

    for (u64 i = 0; i < size; ++i) {
        buf[i] = static_cast<u8>(dis(gen)); // Заполняем массив случайными байтами
    }
}

// Преобразует 32-байтовое число (массив in из 32 байт) в представление, состоящее из 16 элементов 16-битных целых чисел (field_elem).
// В результате out будет массивом из 16 чисел, каждое из которых занимает 16 бит.
void Curve25519::unpack25519(field_elem out, const u8 *in) {
    int i;
    for (i = 0; i < 16; ++i) 
        out[i] = in[2*i] + ((i64) in[2*i + 1] << 8);
    out[15] &= 0x7fff;
}

// Реализует перенос (carry) в 16-битной арифметике.
// Если значение элемента превышает  2^{16} , то старшие биты переносятся к следующему элементу.
// Для последнего элемента (i == 15), перенос возвращается к первому элементу с коэффициентом 38. 
// Это связано с особенностями арифметики кривой Curve25519 (практика уменьшения чисел за модулем  2^{255} - 19 ).
void Curve25519::carry25519(field_elem elem) {
    int i;
    i64 carry;
    for (i = 0; i < 16; ++i) {
        carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if (i < 15) 
            elem[i + 1] += carry; 
        else 
            elem[0] += 38 * carry;
    }
}

// Выполняет покомпонентное сложение двух чисел в представлении field_elem.
void Curve25519::fadd(field_elem out, const field_elem a, const field_elem b) /* out = a + b */ {
    int i;
    for (i = 0; i < 16; ++i) 
        out[i] = a[i] + b[i];
}

// Выполняет покомпонентное вычитание двух чисел в представлении field_elem.
void Curve25519::fsub(field_elem out, const field_elem a, const field_elem b) /* out = a - b */ {
    int i;
    for (i = 0; i < 16; ++i) 
        out[i] = a[i] - b[i];
}

// Выполняет умножение двух чисел в представлении field_elem с последующей редукцией по модулю  2^{255} - 19 .
void Curve25519::fmul(field_elem out, const field_elem a, const field_elem b) /* out = a * b */ {
    i64 i, j, product[31];
    for (i = 0; i < 31; ++i) 
        product[i] = 0;
    for (i = 0; i < 16; ++i) {
        for (j = 0; j < 16; ++j) 
            product[i + j] += a[i] * b[j];
    }
    for (i = 0; i < 15; ++i) 
        product[i] += 38 * product[i + 16];
    for (i = 0; i < 16; ++i) 
        out[i] = product[i];
    carry25519(out);
    carry25519(out);
}

// Вычисляет мультипликативный обратный элемент  x^{-1} \mod (2^{255} - 19) .
void Curve25519::finverse(field_elem out, const field_elem in) {
    field_elem c;
    int i;
    for (i = 0; i < 16; ++i) 
        c[i] = in[i];
    for (i = 253; i >= 0; i--) {
        fmul(c, c, c);
        if (i != 2 && i != 4) 
            fmul(c, c, in);
    }
    for (i = 0; i < 16; ++i) 
        out[i] = c[i];
}

// Условно меняет значения массивов p и q в зависимости от значения бита bit.
void Curve25519::swap25519(field_elem p, field_elem q, int bit) {
    i64 t, i, c = ~(bit - 1);
    for (i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

// Преобразует число в представлении field_elem обратно в массив из 32 байт (формат, удобный для передачи).
void Curve25519::pack25519(u8 *out, const field_elem in) {
    int i, j, carry;
    field_elem m, t;
    for (i = 0; i < 16; ++i) 
        t[i] = in[i];
    carry25519(t); 
    carry25519(t); 
    carry25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(t, m, 1 - carry);
    }
    for (i = 0; i < 16; ++i) {
        out[2 * i] = t[i] & 0xff;
        out[2 * i + 1] = t[i] >> 8;
    }
}

// Выполняет скалярное умножение со стандартной базовой точкой {д} , где  x = 9 .
void Curve25519::scalarmult_base(u8 *out, const u8 *scalar) {
    scalarmult(out, scalar, _9);
}

// Генерирует пару ключей:
// Приватный ключ (sk) — случайное 32-байтовое значение.
// Публичный ключ (pk) — результат умножения приватного ключа на базовую точку: pk = sk * {д}
void Curve25519::generate_keypair(u8 *pk, u8 *sk) {
  randombytes(sk, 32);  // Генерация приватного ключа   !!!
  scalarmult_base(pk, sk);
}

// Используется для вычисления общего секрета. Работает как у отправителя, так и у получателя:
// У отправителя: out = sk * pk_recipient
// У получателя: out = sk_recipient * pk_sender
// Результат  out  — общий секрет, который затем может быть использован для шифрования сообщений.
void Curve25519::x25519(u8 *out, const u8 *pk, const u8 *sk) {
  scalarmult(out, sk, pk);
}

// Выполняет скалярное умножение
void Curve25519::scalarmult(u8 *out, const u8 *scalar, const u8 *point) {
    u8 clamped[32];
    i64 bit, i;
    field_elem a, b, c, d, e, f, x;
    for (i = 0; i < 32; ++i) clamped[i] = scalar[i];
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;
    unpack25519(x, point);
    for (i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        bit = (clamped[i >> 3] >> (i & 7)) & 1;
        swap25519(a, b, bit);
        swap25519(c, d, bit);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fmul(d, e, e);
        fmul(f, a, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fmul(b, a, a);
        fsub(c, d, f);
        fmul(a, c, _121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fmul(b, e, e);
        swap25519(a, b, bit);
        swap25519(c, d, bit);
    }
    finverse(c, c);
    fmul(a, a, c);
    pack25519(out, a);
}

// int main() {
//     // Инициализация libsodium
//     if (sodium_init() < 0) {
//         printf("Не удалось инициализировать libsodium.\n");
//         return 1;
//     }

//     // Буферы для ключей и общего секрета
//     u8 alice_private[32], alice_public[32];
//     u8 bob_private[32], bob_public[32];
//     u8 shared_secret_alice[32], shared_secret_bob[32];

//     // Генерация ключей для Алисы
//     generate_keypair(alice_public, alice_private);
//     print_hex("Публичный ключ Алисы", alice_public, 32);
//     print_hex("Приватный ключ Алисы", alice_private, 32);

//     // Генерация ключей для Боба
//     generate_keypair(bob_public, bob_private);
//     print_hex("Публичный ключ Боба", bob_public, 32);
//     print_hex("Приватный ключ Боба", bob_private, 32);

//     // Алиса вычисляет общий секрет, используя свой приватный ключ и публичный ключ Боба
//     x25519(shared_secret_alice, bob_public, alice_private);
//     print_hex("Общий секрет (Алиса)", shared_secret_alice, 32);

//     // Боб вычисляет общий секрет, используя свой приватный ключ и публичный ключ Алисы
//     x25519(shared_secret_bob, alice_public, bob_private);
//     print_hex("Общий секрет (Боб)", shared_secret_bob, 32);

//     // Проверка, что оба секрета совпадают
//     if (memcmp(shared_secret_alice, shared_secret_bob, 32) == 0) {
//         printf("Тест пройден: общий секрет совпадает.\n");
//     } else {
//         printf("Ошибка: общий секрет не совпадает!\n");
//     }

//     return 0;
// }