#include <Crypto.h>
#include <SHA256.h>
#include <string.h>
#include <MemoryFree.h>

#define HASH_SIZE 32
#define BLOCK_SIZE 64

struct TestHashVector
{
    const char *name;
    const char *key;
    const char *data;
    uint8_t hash[HASH_SIZE];
};


static TestHashVector const testVectorSHA256_1 = {
    "SHA-256 #1",
    0,
    "abc",
    {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
     0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
     0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
     0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
};

SHA256 sha256;

byte buffer[128];

bool testHash_N(Hash *hash, const struct TestHashVector *test, size_t inc)
{
    size_t size = strlen(test->data);
    size_t posn, len;
    uint8_t value[HASH_SIZE];

    hash->reset();
    for (posn = 0; posn < size; posn += inc) {
        len = size - posn;
        if (len > inc)
            len = inc;
        hash->update(test->data + posn, len);
    }
    hash->finalize(value, sizeof(value));
    if (memcmp(value, test->hash, sizeof(value)) != 0)
        return false;

    return true;
}

void testHash(Hash *hash, const struct TestHashVector *test)
{
    bool ok;

    Serial.print(test->name);
    Serial.print(" ... ");

    ok  = testHash_N(hash, test, strlen(test->data));
    ok &= testHash_N(hash, test, 1);
    ok &= testHash_N(hash, test, 2);
    ok &= testHash_N(hash, test, 5);
    ok &= testHash_N(hash, test, 8);
    ok &= testHash_N(hash, test, 13);
    ok &= testHash_N(hash, test, 16);
    ok &= testHash_N(hash, test, 24);
    ok &= testHash_N(hash, test, 63);
    ok &= testHash_N(hash, test, 64);

    if (ok)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void perfHash(Hash *hash)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    Serial.print("Hashing ... ");

    for (size_t posn = 0; posn < sizeof(buffer); ++posn)
        buffer[posn] = (uint8_t)posn;

    hash->reset();
    start = micros();
    for (count = 0; count < 500; ++count) {
        hash->update(buffer, sizeof(buffer));
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (sizeof(buffer) * 500.0));
    Serial.print("us per byte, ");
    Serial.print((sizeof(buffer) * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void setup()
{
    Serial.begin(9600);

    Serial.println();

    Serial.print("State Size ...");
    Serial.println(sizeof(SHA256));
    Serial.println();

    Serial.println("Test Vectors:");
    testHash(&sha256, &testVectorSHA256_1);

    Serial.println();

    Serial.println("Performance Tests:");
    perfHash(&sha256);

    Serial.print("Free Memory: ");
    Serial.print(freeMemory());
    Serial.println(" bytes");
}

void loop()
{
}

