#include <aes.h>
#include <aes128_dec.h>
#include <aes128_enc.h>
#include <aes192_dec.h>
#include <aes192_enc.h>
#include <aes256_dec.h>
#include <aes256_enc.h>
#include <AESLib.h>
#include <aes_dec.h>
#include <aes_enc.h>
#include <aes_invsbox.h>
#include <aes_keyschedule.h>
#include <aes_sbox.h>
#include <aes_types.h>
#include <bcal-basic.h>
#include <bcal-cbc.h>
#include <bcal-cmac.h>
#include <bcal-ofb.h>
#include <bcal_aes128.h>
#include <bcal_aes192.h>
#include <bcal_aes256.h>
#include <blockcipher_descriptor.h>
#include <gf256mul.h>
#include <keysize_descriptor.h>
#include <memxor.h>

#include <SpritzCipher.h>

#include <EEPROM.h>

/*
Functions to remember:
bitRead
bitWrite
bitwise operators
*/

/* Optimized Variables in Bloom Filter:
m == Number of bits in bloom filter
n == Number of inserted elements in the set associated with the bloom filter
k == Number of hash functions
e == % chance of a false-positive

Let e = 1%, n = 100 members (100 nodes)...
m = - (n * ln(e)) / (ln(2))^2   -->   m = 958 bits = 30 uint8_t variables
k =   (m/n) * ln(2)              -->   k = 6.64 (7)

The bloom filter must be a uint32_t array of 30 members.
There must be k = 7 hashes performed (7 indexes of the bloom filter per member)
*/

// CONSTANTS
#define SET_SIZE 4
#define ARRAY_SIZE 128
#define M 1024
#define HASH_SIZE 32

#define BITS_PER_BYTE 8 // Number of bits in bitArray

//The array of bits
uint8_t bitArray[ARRAY_SIZE];
// OLD PUF (Commented Out old)
const uint8_t sramPUF[4][16] = {
  { 0xBE, 0x59, 0x37, 0xF8, 0xC6, 0x3E, 0xA7, 0xAA, 0xED, 0xB9, 0x9F, 0xBA, 0xBB, 0xEB, 0xB5, 0x35 }, //A
  //{ 0xFA, 0xF3, 0x31, 0x93, 0xEC, 0xED, 0xE8, 0x1F, 0xAD, 0x93, 0x3A, 0xB2, 0x7E, 0x3, 0xEF, 0x1D },  //B
  { 0xFE, 0xAF, 0xC5, 0xBE, 0xB2, 0x36, 0x38, 0x7A, 0x2F, 0xFF, 0xBD, 0x9C, 0xEF, 0xF6, 0xD0, 0xCE }, //B
  //{ 0xF3, 0xCD, 0xF5, 0xF5, 0xDE, 0xFC, 0xFD, 0x39, 0x77, 0x98, 0xF6, 0x71, 0xBE, 0xFB, 0x3F, 0xF1 }, //C
  { 0xBF, 0xFC, 0x8E, 0xF6, 0xF4, 0x6F, 0x76, 0x3B, 0xBB, 0x73, 0xF1, 0xEF, 0x7D, 0xE5, 0x1A, 0x3D }, //C
  //{ 0x74, 0x6F, 0xE6, 0x97, 0xDF, 0x86, 0xBB, 0xBE, 0xDF, 0xAC, 0xCE, 0xFE, 0x77, 0x5F, 0x6F, 0xD6 }  //D
  { 0xE7, 0x9F, 0xD9, 0xAB, 0x69, 0x69, 0xFE, 0x6D, 0x77, 0xD5, 0x9D, 0xF3, 0x6F, 0xBD, 0xAD, 0xED }  //D
};

/* NEW
const uint8_t sramPUF[4][16] = {
  { 0xBE, 0x59, 0x37, 0xF8, 0xC6, 0x3E, 0xA7, 0xAA, 0xED, 0xB9, 0x9F, 0xBA, 0xBB, 0xEB, 0xB5, 0x35 }, //A
  { 0xFE, 0xAF, 0xC5, 0xBE, 0xB2, 0x36, 0x38, 0x7A, 0x2F, 0xFF, 0xBD, 0x9C, 0xEF, 0xF6, 0xD0, 0xCE },  //B
  { 0xBF, 0xFC, 0x8E, 0xF6, 0xF4, 0x6F, 0x76, 0x3B, 0xBB, 0x73, 0xF1, 0xEF, 0x7D, 0xE5, 0x1A, 0x3D }, //C
  { 0xE7, 0x9F, 0xD9, 0xAB, 0x69, 0x69, 0xFE, 0x6D, 0x77, 0xD5, 0x9D, 0xF3, 0x6F, 0xBD, 0xAD, 0xED }  //D
};
*/

spritz_ctx hash_ctx;

//Functions to encrypt a node's ID into the bitarray
void encryptNode(const uint8_t node); 
void print2BloomFilter(uint8_t index);

void getIndexes(uint16_t* indexes, const uint8_t node);

//Functions to see if a node's ID is in the bitarray
bool isValid(const uint8_t node);


//WARNING! ONLY PRINT TO EEPROM WHEN INTENTIONALLY PUTTING DATA INTO EEPROM!
//EEPROM has limited lifespan. Print to it sparringly!
void print2EEPROM();

void setup() {
  Serial.begin(115200);
  Serial.println("Starting... Bloom Filter ...");
  for (int i = 0; i < ARRAY_SIZE; i++) {
    bitArray[i] = 0;
  }
  
  for (int i = 0; i < 4; i++) {
    encryptNode(i);
  }

  for (int i = 0; i < ARRAY_SIZE; i++) {
    Serial.print(bitArray[i], BIN);
    Serial.print(" ");
    if (i%8 == 0) {
      Serial.println();
    }
  }
  Serial.println();
  for (int i = 0; i < 4; i++) {
    if (isValid(i)) {
      Serial.print(i+1);
      Serial.println(" is in the Bloom Filter.");
    }
    else {
      Serial.println("Bloom Filter Failed!");
    }
  }


  print2EEPROM();
  Serial.println();
  Serial.println();
  
  for (int i = 0; i < ARRAY_SIZE; i++) {
    Serial.print(EEPROM[i + 16], BIN);
    Serial.print(" ");
    if (i%8 == 0) {
      Serial.println();
    }
  }
}

void loop() {
  /*EMPTY LOOP*/
}


void encryptNode(const uint8_t node) {
  // Find 7 derivations of that hash, using the later 10 bits of the hash (the bloom filter only goes up to 1024 bits)
  uint16_t index[7];
  getIndexes(index, node);
  
  for (int i = 0; i < 7; i++) {
    print2BloomFilter(index[i]);  
  }

  for (int i = 0; i < 7; i++) {
    Serial.print(index[i]);
    Serial.print(" ");
  }
  Serial.println();
    
}

void getIndexes(uint16_t* indexes, const uint8_t node) {
  const uint8_t k = 7; //Number of indexes to be made from the hash
  //Hash the node ID
  uint8_t hash[9];
  spritz_hash(hash, 9, sramPUF[node], 16);

  // Split the hash into 10-bit pieces in the following order:
  //1111 1111 1100 0000 -> Shift 6 to right
  //0011 1111 1111 0000 -> 4 to right
  //0000 1111 1111 1100 -> 2 to right
  //0000 0011 1111 1111 -> 0 to right
  //*Skip the next byte, it's all been used up*
  //Repeat

  uint8_t filterA;
  uint8_t filterB;
  uint8_t temp;
  uint8_t x = 0;
  for (int i = 0; i < k; i++) {
    filterA = 255 >> (i*2) % 8;
    filterB = 255 << (8 - (((i*2) % 8) + 2));

    indexes[i] = filterA & hash[i+x];
    indexes[i] = indexes[i] << 8;
    
    temp = filterB & hash[i+x+1];
    indexes[i] = indexes[i] | temp;
    
    indexes[i] = indexes[i] >> (8 - ((i*2)%8 + 2));
    //If a hash byte is all used up by the index, skip that byte for the next index.
    if (filterB == 255) { 
      x++;
    }
  }
}


void print2BloomFilter(uint16_t index) {
  uint8_t byteNum = index / BITS_PER_BYTE;      // Index of the byte to be written to
  uint8_t bitNum = index % BITS_PER_BYTE;       // Index of the bit within the byte
  
  bitWrite(bitArray[byteNum], bitNum, 1);
}


bool isValid(const uint8_t node) {
  //Get the indexes derived from the hash of this node's ID
  uint16_t index[7];
  getIndexes(index, node);

  //For each index, check if the index is a 1.
  for (int i = 0; i < 7; i++) {
    uint8_t byteNum = index[i] / BITS_PER_BYTE;      // Index of the byte to be read
    uint8_t bitNum = index[i] % BITS_PER_BYTE;       // Index of the bit to be read from within the byte
    
    //If the index is not a 1, then this node isn't valid.
    if (!bitRead(bitArray[byteNum], bitNum)) {
      return false;
    }
  }

  return true;
}
void print2EEPROM() {
  //Indexes 0 to 15 are SRAM PUF readings / Node IDs.
  //Indexes 16 to 143 will be the Bloom Filter
  for (int i = 0; i < ARRAY_SIZE; i++) {
    EEPROM[i + 16] = bitArray[i];
  }
}
