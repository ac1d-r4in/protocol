#ifndef XMSS_H
#define XMSS_H

#include <vector>
#include <algorithm>
#include <random>
#include <map>

#endif

enum xmsstreetype{
    H = 0, F = 1
};

const int w = 16;
const int d = 3;
const int h = 3;
const int k = 3;
const int n = 256;
const int a = 4;

class WOTS {

public:
    WOTS(std::vector<unsigned char> key, std::vector<unsigned char> prf);
    std::vector<unsigned char> getPublicKey();
    std::vector<unsigned char> getSign(std::vector<unsigned char> msg);
    bool Check(std::vector<unsigned char> pk, std::vector<unsigned char> msg, std::vector<unsigned char> sign);
    std::vector<unsigned char> ADRS;
    std::vector<unsigned char> skeys;
};


class XMSS {

public:
    XMSS(std::vector<unsigned char> seed, std::vector<unsigned char>& prf, int level = 0, int num = 8);
    xmsstreetype type;
    bool ispath;
    XMSS* xmsl, *xmsr;
    WOTS* wot;
    int number;
    std::vector<unsigned char> ADRS;
    std::vector<unsigned char> SIGN;

    static bool Verify(std::vector<unsigned char> msg, std::vector<unsigned char> sign, std::vector<unsigned char> pk);
    std::vector<unsigned char> getPublicKey() const;
    std::vector<unsigned char> getSignature(std::vector<unsigned char> msg);
    std::vector<unsigned char> getSign(std::map<int, std::vector<unsigned char>> sito);

private:    
    std::vector<unsigned char> computePublicKey();
    std::vector<unsigned char> publicKey;
};



bool Cmp (std::vector<unsigned char> v1, std::vector<unsigned char> v2) {
    bool flag = true;

    for (int i = 0; i < v1.size(); ++i) {
        if (!(v1[i] == v2[i])) {
            flag = false;
            break;
        }
    }

    return flag;
}

unsigned long long rotl(unsigned long long value, int shift) {
    return (value << shift) | (value >> (64 * CHAR_BIT - shift));
}

int P[25] = {0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21};

int ROT[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

std::vector<unsigned char> Part(std::vector<unsigned char> msg, int k, int n) {
    std::vector<unsigned char> r;
    for (int i = k * n / 8; i < k * n / 8 + n / 8; ++i) {
        r.push_back(msg[i]);
    }
    return r;
}

std::vector<unsigned char> PRF(std::vector<unsigned char> prf) {

  std::random_device rd;
  std::mt19937_64 gen(rd());

  int c = 0;
  while (c < prf.size() / 8) {
    unsigned long long randomValue = gen();
    for (int i = 0; i < 8; ++i) {
      prf[c * 8 + i] ^= (randomValue >> (i * 8)) & 0xFF;
      c++;

      if (c == prf.size() / 8) break;
    }
  }
  return prf;

}

void Perm(std::vector<unsigned char>& state, int Round) {

    int lane_size = 8;
    int width = 200;
    //load
    std::vector<unsigned long long> state64;
    for (int i = 0; i < 25; ++i) {
        unsigned long long num = 0;
        for (int j = 0; j < 8; ++j) {
            num = (num << 8) | state[i * 8 + j];
        }
        state64.push_back(num);
    }

    //Theta
    std::vector<unsigned long long> C(5, 0);
    std::vector<unsigned long long> D(5, 0);


    for (size_t i = 0; i < 25; i += 5) {
      C[0] ^= state64[i + 0];
      C[1] ^= state64[i + 1];
      C[2] ^= state64[i + 2];
      C[3] ^= state64[i + 3];
      C[4] ^= state64[i + 4];
    }

    D[0] = C[4] ^ rotl(C[1], 1);
    D[1] = C[0] ^ rotl(C[2], 1);
    D[2] = C[1] ^ rotl(C[3], 1);
    D[3] = C[2] ^ rotl(C[4], 1);
    D[4] = C[3] ^ rotl(C[0], 1);

    for (size_t i = 0; i < 25; i += 5) {
      state64[i + 0] ^= D[0];
      state64[i + 1] ^= D[1];
      state64[i + 2] ^= D[2];
      state64[i + 3] ^= D[3];
      state64[i + 4] ^= D[4];
    }

    //Rho

    for (size_t i = 0; i < 25; i++) {
      state64[i] = rotl(state64[i], ROT[i]);
    }

    // Pi

    std::vector<unsigned long long> tmp(25, 0);

    for (int i = 0; i < 25; ++i) {
        tmp[i] = state64[P[i]];
    }

    for (int i = 0; i < 25; ++i) {
        state64[i] = tmp[i];
    }

    //Chi

    for (size_t i = 0; i < 5; i++) {
      const size_t ix5 = i * 5;

      const uint64_t t0 = state64[ix5 + 0];
      const uint64_t t1 = state64[ix5 + 1];

      state64[ix5 + 0] ^= (~t1 & state64[ix5 + 2]);
      state64[ix5 + 1] ^= (~state64[ix5 + 2] & state64[ix5 + 3]);
      state64[ix5 + 2] ^= (~state64[ix5 + 3] & state64[ix5 + 4]);
      state64[ix5 + 3] ^= (~state64[ix5 + 4] & t0);
      state64[ix5 + 4] ^= (~t0 & t1);
    }

    //Iota

    switch (Round) {
            case 0: { state64[0] ^= 0x0000000000000001; break; }
            case 1: { state64[0] ^= 0x0000000000008082; break; }
            case 2: { state64[0] ^= 0x800000000000808A; break; }
            case 3: { state64[0] ^= 0x8000000080008000; break; }
            case 4: { state64[0] ^= 0x000000000000808B; break; }
            case 5: { state64[0] ^= 0x0000000080000001; break; }
            case 6: { state64[0] ^= 0x8000000080008081; break; }
            case 7: { state64[0] ^= 0x8000000000008009; break; }
            case 8: { state64[0] ^= 0x000000000000008A; break; }
            case 9: { state64[0] ^= 0x0000000000000088; break; }
            case 10: { state64[0] ^= 0x0000000080008009; break; }
            case 11: { state64[0] ^= 0x000000008000000A; break; }
            case 12: { state64[0] ^= 0x000000008000808B; break; }
            case 13: { state64[0] ^= 0x800000000000008B; break; }
            case 14: { state64[0] ^= 0x8000000000008089; break; }
            case 15: { state64[0] ^= 0x8000000000008003; break; }
            case 16: { state64[0] ^= 0x8000000000008002; break; }
            case 17: { state64[0] ^= 0x8000000000000080; break; }
            case 18: { state64[0] ^= 0x000000000000800A; break; }
            case 19: { state64[0] ^= 0x800000008000000A; break; }
            case 20: { state64[0] ^= 0x8000000080008081; break; }
            case 21: { state64[0] ^= 0x8000000000008080; break; }
            case 22: { state64[0] ^= 0x0000000080000001; break; }
            case 23: { state64[0] ^= 0x8000000080008008; break; }
            default: { break; }
        }

    //save
    for (int i = 0; i < 25; ++i) {
        for (int j = 0; j < 8; ++j) {
            state[i*8 + j] = char((state64[i] >> (8 * j)) % 256);
        }
    }

}

std::vector<unsigned char> keccak (std::vector<unsigned char> msg, int n) {
    unsigned char rate = 136;
    unsigned char capacity = 64;
    std::vector<unsigned char> paddedMessage = msg;

    std::vector<unsigned char> state(rate + capacity, 0);

    paddedMessage.push_back(0x01);
    while (paddedMessage.size() % rate != 0) { paddedMessage.push_back(0x00); }

    for (size_t i = 0; i < paddedMessage.size() / rate; ++i) {

        for (int j = 0; j < rate; ++j) {
          state[j] ^= paddedMessage[i * rate + j];
        }

        for (int k = 0; k < 24; ++k) {
            Perm(state, k);
        }

    }


    std::vector<unsigned char> result;

    while (result.size() < n) {

        for (int i = 0; i < rate; ++i){
            result.push_back(state[i]);

            if (result.size() == n) return result;
        }

        for (int k = 0; k < 24; ++k) {
            Perm(state, k);
        }
    }
}

std::vector<unsigned char> Con(std::vector<unsigned char> a, std::vector<unsigned char> b) {
    for (int i = 0; i < b.size(); ++i)
        a.push_back(b[i]);
    return a;
}

bool WOTS::Check(std::vector<unsigned char> pk, std::vector<unsigned char> msg, std::vector<unsigned char> sign) {

    std::vector<unsigned char> PK;
    for (int i = 0; i < skeys.size(); ++i) {
        std::vector<unsigned char> p14, p58, p;

        p58.push_back((sign[i] & 0b00001111) << 4);
        p14.push_back(sign[i] & 0b11110000);

        for (int j = 0; j < w - (msg[i] & 0b00001111); ++j) {
            p14 = keccak(p14, 1);
            p14[0] &= 0b11110000;
        }

        for (int j = 0; j < w - ((msg[i] & 0b11110000) >> 4); ++j) {
            p58 = keccak(p58, 1);
            p58[0] &= 0b11110000;
        }

        p.push_back(p14[0] | (p58[0] >> 4));

        PK.push_back(p[0]);
    }


    return Cmp(pk, PK);
}

WOTS::WOTS(std::vector<unsigned char> key, std::vector<unsigned char> prf) {

    ADRS = PRF(prf);
    std::vector<unsigned char> KA;
    for (int i = 0; i < ADRS.size(); ++i) KA.push_back(ADRS[i]);
    for (int i = 0; i < key.size(); ++i) KA.push_back(key[i]);
    skeys = keccak(KA, 32);
}

std::vector<unsigned char> WOTS::getPublicKey () {
    std::vector<unsigned char> PK;

    for (int i = 0; i < skeys.size(); ++i) {
        std::vector<unsigned char> p14, p58, p;

        p58.push_back((skeys[i] & 0b00001111) << 4);
        p14.push_back(skeys[i] & 0b11110000);

        for (int j = 0; j < w; ++j) {
            p14 = keccak(p14, 1);
            p14[0] &= 0b11110000;
        }

        for (int j = 0; j < w; ++j) {
            p58 = keccak(p58, 1);
            p58[0] &= 0b11110000;
        }

        p.push_back(p14[0] | (p58[0] >> 4));

        PK.push_back(p[0]);
    }

    return PK;
}

std::vector<unsigned char> WOTS::getSign(std::vector<unsigned char> msg) {
    std::vector<unsigned char> sign;

    for (int i = 0; i < skeys.size(); ++i) {
        std::vector<unsigned char> p14, p58, p;

        p58.push_back((skeys[i] & 0b00001111) << 4);
        p14.push_back(skeys[i] & 0b11110000);

        for (int j = 0; j < (msg[i] & 0b00001111); ++j) {
            p14 = keccak(p14, 1);
            p14[0] &= 0b11110000;
        }

        for (int j = 0; j < ((msg[i] & 0b11110000) >> 4); ++j) {
            p58 = keccak(p58, 1);
            p58[0] &= 0b11110000;
        }

        p.push_back(p14[0] | (p58[0] >> 4));

        sign.push_back(p[0]);
    }

    return sign;
}

int Pow2 (int a) {
    int r = 1;
    for (int i = 0; i < a; ++i) r *= 2;
    return r;
}

XMSS::XMSS (std::vector<unsigned char> seed, std::vector<unsigned char>& prf, int level, int num) {
    if (level < a) {
        type = H;
        ADRS = PRF(prf);
        xmsl = new XMSS(seed, prf, level + 1, num - Pow2(a - level - 1) / 2);
        xmsr = new XMSS(seed, prf, level + 1, num + Pow2(a - level - 1) / 2);
    }
    else {
        number = num;
        type = F;
        wot = new WOTS(seed, prf);
    }

    this->publicKey = this->computePublicKey();
}

std::vector<unsigned char> XMSS::computePublicKey() {
    if (type == H) {
        std::vector<unsigned char> l = xmsl->computePublicKey();
        std::vector<unsigned char> r = xmsr->computePublicKey();

        return keccak(Con(l, r), 32);
    }
    else {
        return wot->getPublicKey();
    }
}

std::vector<unsigned char> XMSS::getPublicKey() const {
    return this->publicKey;
}

std::vector<unsigned char> XMSS::getSignature(std::vector<unsigned char> msg) {
    std::map<int, std::vector<unsigned char>> sito;
    sito[0] = keccak(msg, 32);
    return getSign(sito);
}

std::vector<unsigned char> XMSS::getSign(std::map<int, std::vector<unsigned char>> sito) {
    SIGN.clear();
    if (type == H) {
        std::vector<unsigned char> l = xmsl->getSign(sito);
        std::vector<unsigned char> r = xmsr->getSign(sito);

        ispath = xmsl->ispath || xmsr->ispath;
        if (ispath) {
            if (xmsl->ispath) {

                SIGN = Con(xmsl->SIGN, r);


            }
            else {

                SIGN = Con(xmsr->SIGN, l);


            }
        }
        for (int i = 0; i < r.size(); ++i) {
            l.push_back(r[i]);
        }
        return keccak(l, 32);
    }
    else {

        std::map<int, std::vector<unsigned char>>::iterator it = sito.find(number - 1);
        if (it == sito.end()) {
            ispath = false;
            SIGN = wot->getPublicKey();
            return SIGN;

        }
        else {
            ispath = true;

            SIGN = wot->getSign(it->second);
            std::vector<unsigned char> si = wot->getPublicKey();
            for (int i = 0; i < si.size(); ++i) SIGN.push_back(si[i]);
            return si;
        }
    }

}

bool XMSS::Verify(std::vector<unsigned char> msg, std::vector<unsigned char> sign, std::vector<unsigned char> pk) {
    unsigned long cunt = 0;
    std::vector<unsigned char> digest = keccak(msg, 32);
    std::vector<unsigned char> wpk, wsign;
    WOTS w(digest, digest);
    for (int i = 0; i < 32; ++i) {
        wsign.push_back(sign[cunt]);
        cunt++;
    }
    for (int i = 0; i < 32; ++i) {
        wpk.push_back(sign[cunt]);
        cunt++;
    }

    if (w.Check(wpk, digest, wsign)) {

        std::vector<unsigned char> h, p;
        p = wpk;
        for (int i = 0; i < a; ++i) {
            h.clear();

            for (int i = 0; i < 32; ++i) {
                h.push_back(sign[cunt]);
                cunt++;
            }

            p = keccak(Con(p, h), 32);
        }

        return Cmp(p, pk);

    }
    else {
        return false;
    }
}

