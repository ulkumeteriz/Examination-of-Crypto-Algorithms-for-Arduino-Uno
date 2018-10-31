#include <Crypto.h>
#include <CryptoLW.h>
#include <Ascon128.h>
#include <MemoryFree.h>
#include "utility/ProgMemUtil.h"

#define MAX_PLAINTEXT_LEN 43
#define MAX_AUTHDATA_LEN 17

struct TestVector
{
    const char *name;
    uint8_t key[16];
    uint8_t plaintext[MAX_PLAINTEXT_LEN];
    uint8_t ciphertext[MAX_PLAINTEXT_LEN];
    uint8_t authdata[MAX_AUTHDATA_LEN];
    uint8_t iv[16];
    uint8_t tag[16];
    size_t authsize;
    size_t datasize;
};

static TestVector const testVectorAscon128_1 PROGMEM = {
    .name        = "Ascon128 #1",
    .key         = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .plaintext   = {0x61, 0x73, 0x63, 0x6f, 0x6e},
    .ciphertext  = {0x86, 0x88, 0x62, 0x14, 0x0e},
    .authdata    = {0x41, 0x53, 0x43, 0x4f, 0x4e},
    .iv          = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .tag         = {0xad, 0x65, 0xf5, 0x94, 0x22, 0x58, 0xda, 0xd5,
                    0x3c, 0xaa, 0x7a, 0x56, 0xf3, 0xa2, 0x92, 0xd8},
    .authsize    = 5,
    .datasize    = 5
};


TestVector testVector;

Ascon128 acorn;

byte buffer[128];

bool testCipher_N(Ascon128 *cipher, const struct TestVector *test, size_t inc)
{
    size_t posn, len;
    uint8_t tag[16];

    if (!inc)
        inc = 1;

    cipher->clear();
    if (!cipher->setKey(test->key, 16)) {
        Serial.print("setKey ");
        return false;
    }
    if (!cipher->setIV(test->iv, 16)) {
        Serial.print("setIV ");
        return false;
    }

    memset(buffer, 0xBA, sizeof(buffer));

    for (posn = 0; posn < test->authsize; posn += inc) {
        len = test->authsize - posn;
        if (len > inc)
            len = inc;
        cipher->addAuthData(test->authdata + posn, len);
    }

    for (posn = 0; posn < test->datasize; posn += inc) {
        len = test->datasize - posn;
        if (len > inc)
            len = inc;
        cipher->encrypt(buffer + posn, test->plaintext + posn, len);
    }

    if (memcmp(buffer, test->ciphertext, test->datasize) != 0) {
        Serial.print(buffer[0], HEX);
        Serial.print("->");
        Serial.print(test->ciphertext[0], HEX);
        return false;
    }

    cipher->computeTag(tag, sizeof(tag));
    if (memcmp(tag, test->tag, sizeof(tag)) != 0) {
        Serial.print("computed wrong tag ... ");
        return false;
    }

    cipher->setKey(test->key, 16);
    cipher->setIV(test->iv, 16);

    for (posn = 0; posn < test->authsize; posn += inc) {
        len = test->authsize - posn;
        if (len > inc)
            len = inc;
        cipher->addAuthData(test->authdata + posn, len);
    }

    for (posn = 0; posn < test->datasize; posn += inc) {
        len = test->datasize - posn;
        if (len > inc)
            len = inc;
        cipher->decrypt(buffer + posn, test->ciphertext + posn, len);
    }

    if (memcmp(buffer, test->plaintext, test->datasize) != 0)
        return false;

    if (!cipher->checkTag(tag, sizeof(tag))) {
        Serial.print("tag did not check ... ");
        return false;
    }

    return true;
}

void testCipher(Ascon128 *cipher, const struct TestVector *test)
{
    bool ok;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" ... ");

    ok  = testCipher_N(cipher, test, test->datasize);
    ok &= testCipher_N(cipher, test, 1);
    ok &= testCipher_N(cipher, test, 2);
    ok &= testCipher_N(cipher, test, 5);
    ok &= testCipher_N(cipher, test, 8);
    ok &= testCipher_N(cipher, test, 13);
    ok &= testCipher_N(cipher, test, 16);

    if (ok)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void perfCipherSetKey(Ascon128 *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" SetKey ... ");

    start = micros();
    for (count = 0; count < 1000; ++count) {
        cipher->setKey(test->key, 16);
        cipher->setIV(test->iv, 16);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / 1000.0);
    Serial.print("us per operation, ");
    Serial.print((1000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");
}

void perfCipherEncrypt(Ascon128 *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" Encrypt ... ");

    cipher->setKey(test->key, 16);
    cipher->setIV(test->iv, 16);
    start = micros();
    for (count = 0; count < 500; ++count) {
        cipher->encrypt(buffer, buffer, 128);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (128.0 * 500.0));
    Serial.print("us per byte, ");
    Serial.print((128.0 * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt(Ascon128 *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" Decrypt ... ");

    cipher->setKey(test->key, 16);
    cipher->setIV(test->iv, 16);
    start = micros();
    for (count = 0; count < 500; ++count) {
        cipher->decrypt(buffer, buffer, 128);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (128.0 * 500.0));
    Serial.print("us per byte, ");
    Serial.print((128.0 * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherAddAuthData(Ascon128 *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" AddAuthData ... ");

    cipher->setKey(test->key, 16);
    cipher->setIV(test->iv, 16);
    start = micros();
    memset(buffer, 0xBA, 128);
    for (count = 0; count < 500; ++count) {
        cipher->addAuthData(buffer, 128);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (128.0 * 500.0));
    Serial.print("us per byte, ");
    Serial.print((128.0 * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherComputeTag(Ascon128 *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" ComputeTag ... ");

    cipher->setKey(test->key, 16);
    cipher->setIV(test->iv, 16);
    start = micros();
    for (count = 0; count < 1000; ++count) {
        cipher->computeTag(buffer, 16);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / 1000.0);
    Serial.print("us per operation, ");
    Serial.print((1000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");
}

void perfCipher(Ascon128 *cipher, const struct TestVector *test)
{
    perfCipherSetKey(cipher, test);
    perfCipherEncrypt(cipher, test);
    perfCipherDecrypt(cipher, test);
    perfCipherAddAuthData(cipher, test);
    perfCipherComputeTag(cipher, test);
}

void setup()
{
    Serial.begin(9600);

    Serial.println();

    Serial.print("State Size ... ");
    Serial.println(sizeof(Ascon128));
    Serial.println();

    Serial.println("Test Vectors:");
    testCipher(&acorn, &testVectorAscon128_1);

    Serial.println();

    Serial.println("Performance Tests:");
    perfCipher(&acorn, &testVectorAscon128_1);

    Serial.print("Free Memory: ");
    Serial.print(freeMemory());
    Serial.println(" bytes");
}

void loop()
{
}
