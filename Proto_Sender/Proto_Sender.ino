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

#include <mcp_can.h>
#include <mcp_can_dfs.h>

#include <EEPROM.h>

/* NODE WIRING:
 *  To connect a node to an MCP2515, use this tutorial
 *  https://www.electronicshub.org/arduino-mcp2515-can-bus-tutorial/
 *  When connecting 2 MCP2515, use either the J2 or J3 pins.
 *  To connect 4 MCP2515:
 *    Suppose MCP2515 A, B, C, and D.
 *    Connect A to B and C to D using the HIGH and LOW pins on J2.
 *    Connect A to D and B to C using the HIGH and LOW pins on J3.
 *    (Forms a circle with the wires)
*/

//CONSTANTS |-----------------------------------------------------------------------------------------------------------------------------
// Message & Key Sizes
#define MSG_SIZE     4
#define MSGS_PER_KEY 4
#define KEY_SIZE     16 //MSG_SIZE * MSGS_PER_KEY      

#define NUM_NODES    3  //Number of Receivers

#define CAN_MAX      64

//Diffie-Hellman Variables
//const uint8_t prime = 2147483647;
const uint8_t prime = 251;
const unsigned int generator = 16807; 

//Pins & LEDs
#define SPI_CS_PIN 10
#define LED        8
#define ledON      true

// Node IDs. The first byte of each node's SRAM PUF reading
//uint8_t nodeID[4] = {0xD3, 0xFA, 0xF3, 0x74};  <- This is old
uint8_t nodeID[4] = {0xBE, 0xFE, 0xBF, 0xE7};
uint8_t thisID = EEPROM[0];


// Hashing Variables
#define HASH_SIZE 20
uint8_t hash[NUM_NODES][HASH_SIZE];



uint8_t DIFFIE_KEY[NUM_NODES][KEY_SIZE];
uint8_t msgCounter[NUM_NODES];
uint8_t responderID;
MCP_CAN CAN(SPI_CS_PIN);

//FUNCTIONS |-----------------------------------------------------------------------------------------------------------------------------
// KEY GENERATION 
uint8_t keyGen(int i);                            // Generates 1 byte, "a", of the 16-byte key. 
uint8_t mulMod(uint8_t a, uint8_t b, uint8_t m);  // (a*b) mod m
uint8_t powMod(uint8_t b, uint8_t e, uint8_t m);  // (b^e) mod m


// Bloom Filter Functions
bool isValid(uint8_t* puf);     
void getIndexes(uint16_t* indexes, uint8_t* puf);

// COMMUNICATION FUNCTIONS 


void sendMsg(uint8_t* msg, int msgLength, uint8_t receiverID);


void receiveMsg(uint8_t* msg, uint8_t msgLength);
void printMsg(uint8_t* msg);

// SENDER-SPECIFIC FUNCTIONS 
void recordMsg(uint8_t* msg);
void printKeys();

uint8_t findNode(const uint8_t msgID);

void verifyThisNode();

// SETUP & LOOP |+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void setup() {
  Serial.begin(115200);
  pinMode(LED,OUTPUT);

  // Delay until data can be read.
  while (CAN_OK != CAN.begin(CAN_500KBPS)) {             // init can bus : baudrate = 500k
    Serial.println("CAN BUS Shield init fail");
    Serial.println("Init CAN BUS Shield again");
    delay(100);
  }

  // Message Storage Arrays
  uint8_t privateKey[KEY_SIZE];   //One quarter of the private key
  uint8_t msgSent[MSG_SIZE];      //One quarter of a message sent
  uint8_t response[CAN_MAX];     // Needs to be bigger
  
  for (int i = 0; i < NUM_NODES; i++) {
    msgCounter[i] = 0;
  }

  //Alice removes her ID from the set of receiverIDs
  for (int i = 0; i < NUM_NODES+1; i++) {
    if (nodeID[i] == thisID) {
      for (int x = i; x < NUM_NODES; x++) {
        nodeID[x] = nodeID[x+1];
      }
    }
  }

  // Alice generates her private key
  for (int i = 0; i < KEY_SIZE; i++) {
    privateKey[i] = keyGen(i);
  }
  
  response[0] = 's';
  
  Serial.println();
  Serial.println("WAITING FOR RECEIVERS...");
  // Wait until every receiving node is ready
  for (int i = 0; i < NUM_NODES; i++) {
    while (response[0] != 'Y') {
      receiveMsg(response, 1);
    }
    response[0] = 's';
    Serial.print("Node #");
    Serial.print(i+1);
    Serial.println(" is Ready!");
    
  }
  msgSent[0] = 'G';
  sendMsg(msgSent, MSG_SIZE, thisID);

  Serial.println("Starting KeyGen");
// SEND MESSAGE |-------------------------------------------------------------------------------------------------------------------------
  // Alice (sender) sends a message to Bob (receiver)
  for (int i = 0; i < MSGS_PER_KEY; i++) {
    
    // Alice generates a message
    for ( int x = 0; x < MSG_SIZE; x++ ){
      msgSent[x] = powMod(generator, privateKey[(i*MSG_SIZE) + x], prime); // This is Alice's half-encrypted shared key
    }
 
    // Alice sends the message
    delay(200);
    sendMsg(msgSent, MSG_SIZE, thisID);
  }
    Serial.println("Starting Key Receipt");
// RECEIVES RESPONSE |--------------------------------------------------------------------------------------------------------------------
  // Alice (sender) receives responses from every Bob (receivers)
  for (int i = 0; i < (NUM_NODES * MSG_SIZE); i++) {
    Serial.print("Msg #");
    Serial.println(i);
    receiveMsg(response, MSG_SIZE);
    printMsg(response);
    
    // Alice Processes the response using her own private key
    for (int x = 0; x < MSG_SIZE; x++) {
      uint8_t keyPiece = privateKey[msgCounter[findNode(responderID)]] + x;
      response[x] = powMod(response[x], keyPiece, prime);
    }

    recordMsg(response);
  }

  printKeys();
  Serial.println("\n\n---------- | RESYNCHRONIZATION |----------\n");
  //Receivers always finish their work before the sender.  So, sender will send a resync request to receivers when he is ready.
  response[0] = 'Y';
  Serial.println("Sending OK to resync");
  // Declare that this node is ready to resync
  //for (ID in )
  sendMsg(response, 1, thisID);
  response[0] = 's';

  //Resync before Bloom Filter test.  This may solve the issue regarding a desync that causes Bloom Filter failures.
  Serial.println();
  Serial.println("RESYNCHRONIZING NODES");
  Serial.println("WAITING FOR RECEIVERS...");
  // Wait until every receiving node is ready
  for (int i = 0; i < NUM_NODES; i++) {
      while (response[0] != 'Y') {
          receiveMsg(response, 1);
      }
      response[0] = 's';
      Serial.print("Node #");
      Serial.print(i+1);
      Serial.println(" is Ready!");

  }

  msgSent[0] = 'G';
  sendMsg(msgSent, MSG_SIZE, thisID);

  Serial.println("\n\n---------- | BLOOM FILTER |----------\n");
  //A message with a false ID is purposefully sent to the node to see if the filter is working.
  sendMsg(msgSent, MSG_SIZE, 'X');
  verifyThisNode();
  sendMsg(msgSent, MSG_SIZE, nodeID[0]);
  verifyThisNode();

  Serial.println();
  Serial.println();
  Serial.println("---------- | HASHING |----------");
  int i = 0;
  while (i < 10){
      unsigned long time = millis();
      Serial.print("Time: ");
      Serial.println(time/1000);
      Serial.println("\n");

      unsigned char arr[] = "56789";
      sendMsg(arr,       5, thisID);

      for (int i = 0; i < NUM_NODES; i++) {
          char stmp[16] = "1234567890123456";
          spritz_mac(hash[i], HASH_SIZE, stmp, sizeof(stmp), DIFFIE_KEY[i], KEY_SIZE);
          aes128_enc_single(DIFFIE_KEY[i], stmp);
          sendMsg(stmp,      8, nodeID[i]);
          sendMsg(&stmp[8],  8, nodeID[i]);
          delay(200);
      }

      Serial.println();



      for (int i = 0; i < NUM_NODES; i++) {
          sendMsg(hash[i],     8, nodeID[i]);
          sendMsg(&hash[i][8],  8, nodeID[i]);
          sendMsg(&hash[i][16], 4, nodeID[i]);
          delay(500);
          i += 1
      }
  }
}




void loop() {



}

//KEY GENERATION FUNCTIONS |--------------------------------------------------------------------------------------------------------------

// Generates 1 byte, "a" of this node's 16-byte private key
// Returns a random value from 1 to the selected prime number
uint8_t keyGen(int i) {
  randomSeed((unsigned int) EEPROM[i]);
  delay(200);

  return random(1, prime);
}

uint8_t mulMod(uint8_t a, uint8_t b, uint8_t m) { // (a*b) mod m
  uint8_t result = 0;             // Final Result
  uint8_t runningCount = b % m;   // Equals b * 2^i

  // Search all 8 bits of a
  for (int i = 0; i < 8; i++) {
    if (i > 0) {
      runningCount = (runningCount << 1) % m;
    }

    if (bitRead(a,i)) {
      result = (result%m + runningCount%m) % m; // ? Are the Extra "%m" redundant ?
    }
  }
  return result;
}

uint8_t powMod(uint8_t b, uint8_t e, uint8_t m) {
  uint8_t result;     // Final Result
  uint8_t pow;        // pow = (b ^ (2 ^ i)) % m
  uint8_t e_i = e;    // Temporary Version of e
  uint8_t i;          // current bit position being processed of e. Only used for debugging
  
  // 1.) Check the base cases, to save time.
  if ( b == 0 || m == 0 ) {
    return 0;
  }

  // If e = 0, there are no 1s to process.
  if ( e == 0 ) {
    return 1;
  }

  // 2.) Initialize Variables
  b = b % m;
  pow = b;
  result = 1;

  // Process the bits in e
  //Note: mulMod will overflow if its multiplied inputs have more than 32 bits.
  while (e_i) {
    if (e_i & 1) { //If the current bit is set to 1...
      // This overflows if numbits(b) + numbits(pow) > 32 bits
      result = mulMod(result, pow, m); // r = (r * pow) mod m
    }

    // This overflows if numbits(b) + numbits(pow) > 32 bits
    pow = mulMod(pow,pow,m); // (pow * pow) % m

    e_i = e_i >> 1;
    i++;
  }
  // Now, r = (b^e) mod m, if no overflow occurred.
  return result;
}


// Bloom Filter Functions |---------------------------------------------------------------------------------------------------------------
bool isValid(uint8_t* puf) {
  // After the unknown node sends its SRAM PUF, make a hash from the PUF.
  uint16_t index[7];
  getIndexes(index, puf);

  //For each index, check if the index is a 1.
  for (int i = 0; i < 7; i++) {
    uint8_t byteNum = index[i] / 8;      // Index of the byte to be read
    uint8_t bitNum = index[i] % 8;       // Index of the bit to be read from within the byte
    
    //If the index is not a 1, then this node isn't valid.
    if (!bitRead(EEPROM[byteNum+16], bitNum)) {
      return false;
    }
  }

  return true;
}

void getIndexes(uint16_t* indexes, uint8_t* puf) {
  //The puf is 16 bytes long, the index is 7 bytes long.
  const uint8_t k = 7; //Number of indexes to be made from the hash

  //Hash the SRAM PUF (First 16 Bytes)
  uint8_t hash[9];
  spritz_hash(hash, 9, puf, 16);

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


// MESSAGE COMMUNICATION FUNCTIONS |------------------------------------------------------------------------------------------------------
void sendMsg(uint8_t* msg, int msgLength, uint8_t receiverID) {
  CAN.sendMsgBuf(receiverID, 0, msgLength, msg);
  delay(200);
}

uint8_t temp[CAN_MAX];
void receiveMsg(uint8_t* msg, uint8_t msgLength) {
  while(CAN_MSGAVAIL != CAN.checkReceive());
  
  byte len = MSG_SIZE;
  CAN.readMsgBuf(&len, temp);
  responderID = CAN.getCanId();

  for (int i = 0; i < msgLength; i++) {
    msg[i] = temp[i];
  }
  
}

void verifyThisNode() {
    Serial.println("Starting Node Verification...");
  uint8_t message;
  for (int i = 0; i < NUM_NODES; i++) {
      Serial.println("Starting Message Receipt");
    receiveMsg(message, 1);
  }
  uint8_t thisPuf[16];
  for (int i = 0; i < 16; i++) {
    thisPuf[i] = EEPROM[i];
  }
  if (message = 'Y') {
    sendMsg(thisPuf, 8, thisID);
    sendMsg(&thisPuf[8], 8, thisID);
  }
}

void printMsg(uint8_t* msg) {
  Serial.print("Message Sent By: 0x");
  Serial.println(responderID);

  
  Serial.print("Message: ");
  for (int i = 0; i < MSG_SIZE; i++) {
    Serial.print(msg[i]);
    Serial.print(" ");
  }
  Serial.println("\n");

  
}

void recordMsg(uint8_t* msg) {
    Serial.println("Starting recordMSG");
  unsigned int numID = findNode(responderID);

  for (int j = 0; j < MSG_SIZE; j++) {
    DIFFIE_KEY[numID][j + msgCounter[numID]] = msg[j];
  }
  
  //Increment the corresponding responder's counter.
  msgCounter[numID] += MSG_SIZE;
}

//Print keys in order
void printKeys() {
  Serial.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  Serial.println("KEYS MADE:");
  for (int i = 0; i < sizeof(DIFFIE_KEY); i++) { //4 Bytes per message
    Serial.print((unsigned int) DIFFIE_KEY[i/KEY_SIZE][i%KEY_SIZE]);
    
    if ((i+1)%KEY_SIZE == 0){
      Serial.println(" ");
    }
    
    else {
      Serial.print(" ");
    }
  }
}

uint8_t findNode(const uint8_t msgID) {
  for (int x = 0; x < NUM_NODES; x++) {
    if (msgID == nodeID[x]) {
      return x;
    }
  }

  Serial.print("ERROR IN FINDNODE");
  return 2000;
}

//If a sender's ID doesn't match any known ID's, alert the node.
