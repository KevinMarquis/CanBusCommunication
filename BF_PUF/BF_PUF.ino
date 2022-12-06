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

//! PUF Variables:
//We can change the value of ResetPUF to true if we actually want to go through and reset the PUF.
bool ResetPUF = false;
char ResetNodeID[1] = "A";  // This is the letter corresponding to the node we want to reset.  Hardcode this value.

// List of SRAM values at startup
// Address is dynamic. When globals are added/removed, the base address changes.
unsigned char bytes[ 1024 ] __attribute__ ((section (".noinit")));
//Initializes the char array, called "bytes"

/*
'A' == Uno-14402
'B' == Uno-14162
'C' == Uno-14168
'D' == Uno-14154
*/

//! PUF VARIABLES END.

// CONSTANTS
#define SET_SIZE 4
#define ARRAY_SIZE 128
#define M 1024
#define HASH_SIZE 32

#define BITS_PER_BYTE 8 // Number of bits in bitArray

//The array of bits
//This is the bloom filter!
uint8_t bitArray[ARRAY_SIZE];

//We can change the value of ResetBloom to true if we actually want to go through and reset the BloomFilter.
bool ResetBloom = false;

//! We may be able to omit this array entirely when we combine the programs.
const uint8_t sramPUF[4][16] = {
  { 0xBE, 0x59, 0x37, 0xF8, 0xC6, 0x3E, 0xA7, 0xAA, 0xED, 0xB9, 0x9F, 0xBA, 0xBB, 0xEB, 0xB5, 0x35 }, //A
  { 0xFE, 0xAF, 0xC5, 0xBE, 0xB2, 0x36, 0x38, 0x7A, 0x2F, 0xFF, 0xBD, 0x9C, 0xEF, 0xF6, 0xD0, 0xCE }, //B
  { 0xBF, 0xFC, 0x8E, 0xF6, 0xF4, 0x6F, 0x76, 0x3B, 0xBB, 0x73, 0xF1, 0xEF, 0x7D, 0xE5, 0x1A, 0x3D }, //C
  { 0xE7, 0x9F, 0xD9, 0xAB, 0x69, 0x69, 0xFE, 0x6D, 0x77, 0xD5, 0x9D, 0xF3, 0x6F, 0xBD, 0xAD, 0xED }  //D
};

spritz_ctx hash_ctx;

//! PUF FUNCTIONS:


//Use this function whenever you need to check the base address of the SRAM readings array
void printBaseAddress() {
    Serial.print("BASE ADDRESS: ");
    Serial.print((unsigned long) bytes);
}

void printStableBytes() {
    for (int i = 0; i < 16; i++) {
        Serial.print(EEPROM[i], HEX);
        Serial.print(";");
    }
    Serial.println(" ");
}

void fillStableBytes(char input) {
    // Matrix of stable indexes previously found in the SRAM at a specific base address.
    // The base address:
    int stableIndexes[4][16] = {
            {2,5,10,14,15,21,22,24,31,32,33,37,38,43,49,54},     /*Uno-14402*/
            {1,6,8,9,11,12,14,15,18,19,21,23,39,40,42,45},  /*Uno-14162*/
            {2,4,5,7,13,16,22,27,34,35,36,41,43,44,45,48},                  /*Uno-14168*/
            {1,2,3,9,12,17,21,22,23,28,30,33,35,43,47,49}                   /*Uno-14154*/
    };

    //Convert the character ID from 'A' to 'D' into an int from 0 to 3.
    input = toupper(input);
    int unoIndex = (int)(input) - (int)('A');

    //Find stable values within bytes.
    for (int i = 0; i < 16; i++) {
        EEPROM[i] = bytes[stableIndexes[unoIndex][i]];
    }

    EEPROM[16] = input; //Put the Arduino's letter into the EEPROM's 17th member

}

void printSRAM() {
    for (int i = 0; i < 1024; i++) {
        Serial.print((unsigned int) bytes[i], HEX);

        if ((i+1) % 512) { Serial.print(';'); }
        else { Serial.println(';'); }
    }
}

void PUFsetup() {
    Serial.println("Resetting PUF...");
    Serial.println("\n\n");

    printBaseAddress();
    Serial.println(" ");
    printSRAM();

    Serial.println("\n");
    //! Programmer must input the letter associated with their Uno device
    fillStableBytes(ResetNodeID);  //Not really a fan of having to hardcode the letter.  Fine for now, but this is something I'd like to change.
    printStableBytes();
}

//! PUF FUNCTIONS END.

//! Bloom Functions:
//Functions to encrypt a node's ID into the bitarray
void encryptNode(const uint8_t node); 
void print2BloomFilter(uint8_t index);

void getIndexes(uint16_t* indexes, const uint8_t node);

//Functions to see if a node's ID is in the bitarray
bool isValid(const uint8_t node);


//WARNING! ONLY PRINT TO EEPROM WHEN INTENTIONALLY PUTTING DATA INTO EEPROM!
//EEPROM has limited lifespan. Print to it sparringly!
void print2EEPROM();



void Bloomsetup() {
  Serial.println("Resetting Bloom Filter...");

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

void setup() {
    Serial.begin(115200);
    Serial.println("STARTING BF_PUF...");
    Serial.println("\n\n");

    printf("Reset PUF: %s\n", ResetPUF ? "true" : "false");  // Check and make sure this actually works.
    printf("Reset Bloom Filter: %s\n", ResetBloom ? "true" : "false");  // Check and make sure this actually works.

    if (ResetPUF);{
        PUFsetup();
    }

    if (ResetBloom){
        Bloomsetup();
    }

    Serial.println("BF_PUF Complete");

}
