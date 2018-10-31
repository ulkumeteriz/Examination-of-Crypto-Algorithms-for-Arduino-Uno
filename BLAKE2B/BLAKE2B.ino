#include <Crypto.h>
#include <BLAKE2b.h>
#include <string.h>
#include <MemoryFree.h>


#define HASH_SIZE 64
#define BLOCK_SIZE 128

struct TestHashVector
{
    const char *name;
    const char *data;
    uint8_t hash[HASH_SIZE];
};

// Test vectors generated with the reference implementation of BLAKE2b.
static TestHashVector const testVectorBLAKE2b_1 PROGMEM = {
    "BLAKE2b #1",
    "",
    {0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
     0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
     0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
     0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
     0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
     0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
     0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
     0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce}
};


BLAKE2b blake2b;

byte buffer[BLOCK_SIZE + 2];

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
    TestHashVector vec;

    memcpy_P(&vec, test, sizeof(vec));
    test = &vec;

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
    for (count = 0; count < 1000; ++count) {
        hash->update(buffer, sizeof(buffer));
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (sizeof(buffer) * 1000.0));
    Serial.print("us per byte, ");
    Serial.print((sizeof(buffer) * 1000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

// Deterministic sequences (Fibonacci generator).  From RFC 7693.
static void selftest_seq(uint8_t *out, size_t len, uint32_t seed)
{
    size_t i;
    uint32_t t, a , b;

    a = 0xDEAD4BAD * seed;              // prime
    b = 1;

    for (i = 0; i < len; i++) {         // fill the buf
        t = a + b;
        a = b;
        b = t;
        out[i] = (t >> 24) & 0xFF;
    }
}

// Incremental version of above to save memory.
static void selftest_seq_incremental(BLAKE2b *blake, size_t len, uint32_t seed)
{
    size_t i;
    uint32_t t, a , b;

    a = 0xDEAD4BAD * seed;              // prime
    b = 1;

    for (i = 0; i < len; i++) {         // fill the buf
        t = a + b;
        a = b;
        b = t;
        buffer[i % 128] = (t >> 24) & 0xFF;
        if ((i % 128) == 127)
            blake->update(buffer, 128);
    }

    blake->update(buffer, len % 128);
}


void setup()
{
    Serial.begin(9600);

    Serial.println();

    Serial.print("State Size ...");
    Serial.println(sizeof(BLAKE2b));
    Serial.println();

    Serial.println("Test Vectors:");
    testHash(&blake2b, &testVectorBLAKE2b_1);

    Serial.println();

    Serial.println("Performance Tests:");
    perfHash(&blake2b);

    Serial.print("Free Memory: ");
    Serial.print(freeMemory());
    Serial.println(" bytes");
    
}

void loop()
{
}
