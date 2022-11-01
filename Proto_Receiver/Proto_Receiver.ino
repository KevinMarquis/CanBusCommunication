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

//DIFFIE-HELLMAN |--------------------------------------------------------------------------------------------------------------
/* Diffie-Hellman Method: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
Suppose nodes "Alice" & "Bob", and suppose Eavesdropper "Eve"
Alice & Bob want to communicate without Eve being able to impersonate one of them.
So they need to make a shared symmetric key across a public channel (the CAN bus), without Eve figuring out what the key is.

For this example, consider the receiver "Bob".
1.) Alice & Bob have secret colors (Private keys)
2.) Alice & Bob agree on a common paint (receiver & generator)
3.) Respectively, Alice & Bob mix the common paint w/ their secret colors.
4.) Bob receives a mixture from Alice.
5.) Bob shares his mixture w/ Alice publicly.
6.) Bob mixes Alice's mixture w/ his own secret color.
7.) Bob now has the common secret mixture (shared symmetric key).
*/
//CONSTANTS |-----------------------------------------------------------------------------------------------------------------------------
// Message & Key Sizes
#define MSG_SIZE     4
#define MSGS_PER_KEY 4
#define KEY_SIZE     16 //MSG_SIZE * MSGS_PER_KEY

#define CAN_MAX 64

//Diffie-Hellman Variables
//const uint8_t prime = 2147483647;
const uint8_t prime = 251;
const unsigned int generator = 16807;

uint8_t nodeID[4] = {0xBE, 0xFE, 0xBF, 0xE7};
uint8_t thisID = EEPROM[0];
uint8_t trueSenderID;
uint8_t senderID = 'X';

// Pins & LEDs
#define SPI_CS_PIN 10
#define LED        8


// Hashing Variables
#define HASH_SIZE 20
#define BUF_SIZE 16
#define ARR_SIZE 5

int loopCount = 9999;
int startTime;
int stopTime;



MCP_CAN CAN(SPI_CS_PIN);
uint8_t DIFFIE_KEY[KEY_SIZE]; //Receivers only hold their own key. Makes it simpler for now.



//FUNCTIONS |-----------------------------------------------------------------------------------------------------------------------------
// KEY GENERATION
uint8_t keyGen(int i);                            // Generates 1 byte, "a", of the 16-byte key.
uint8_t mulMod(uint8_t a, uint8_t b, uint8_t m);  // (a*b) mod m
uint8_t powMod(uint8_t b, uint8_t e, uint8_t m);  // (b^e) mod m

// Bloom Filter Functions
bool isValid(uint8_t* puf);
void getIndexes(uint16_t* indexes, uint8_t* puf);

// COMMUNICATION FUNCTIONS
void sendMsg(uint8_t* msg);
void receiveMsg(uint8_t* msg, uint8_t msgLength);
void printMsg(uint8_t* msg);
uint8_t msgReceived[MSG_SIZE];    //The 1st 4 members are what's needed
uint8_t response[MSG_SIZE];      //One quarter of a message sent
uint8_t privateKey[KEY_SIZE];

bool isFishy();

// SETUP & LOOP |+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void setup() {
  Serial.begin(115200);
  pinMode(LED,OUTPUT);
  Serial.println("Starting Receiver Mode...");

  // Delay until data can be read.
  while (CAN_OK != CAN.begin(CAN_500KBPS)) {             // init can bus : baudrate = 500k
    Serial.println("CAN BUS Shield init fail");
    Serial.println("Init CAN BUS Shield again");
    delay(100);
  }

  //uint8_t msgReceived[MSG_SIZE];    //The 1st 4 members are what's needed
  //uint8_t response[MSG_SIZE];      //One quarter of a message sent
  //uint8_t privateKey[KEY_SIZE];

  Serial.println("Starting Private Key Generation...");
  // Bob generates his private key
  for (int i = 0; i < KEY_SIZE; i++) {
    privateKey[i] = keyGen(i); //privateKey = 0 -> keyGen(i) = 0
    DIFFIE_KEY[i] = 0;
  }
  response[0] = 'Y';
  Serial.println("Sending OK to receive");
  // Declare that this node is ready to receive messages
  sendMsg(response);
  Serial.println("OK Sent!");
  while (msgReceived[0] != 'G') {
    receiveMsg(msgReceived, 1);
  }
  trueSenderID = senderID;

  Serial.println("Ready to Go!");


// RECEIVES MESSAGE |---------------------------------------------------------------------------------------------------------------------
  // Bob (receiver) gets a message from Alice (sender)
  for (int i = 0; i < MSGS_PER_KEY; i++) {
    receiveMsg(msgReceived, MSG_SIZE);

    //Bob (receiver) does the second layer of encryption on the received message, to get the shared key
    for ( int x = 0; x < MSG_SIZE; x++) {
      msgReceived[x] = powMod(msgReceived[x], privateKey[(i*MSG_SIZE) + x], prime);
      DIFFIE_KEY[(i*MSG_SIZE) + x] = msgReceived[x];
    }
  }

// RESPONDS |-----------------------------------------------------------------------------------------------------------------------------
  // Bob (receiver) responds to Alice (sender)
  srand(EEPROM[0]); //Randomizes delay times for responses
  for ( int i = 0; i < MSGS_PER_KEY; i++) {
    // Bob makes the response
    for ( int x = 0; x < MSG_SIZE; x++ ){
      response[x] = powMod(generator, privateKey[(i*4) + x], prime); // This is Bob's half-encrypted shared key
    }

    //Bob sends the response
    sendMsg(response);
  }

// PRINT OUT |----------------------------------------------------------------------------------------------------------------------------
  //Print out the Key
  Serial.print("SHARED KEY:");
  for (int c = 0; c < KEY_SIZE; c++) {
    Serial.print(" ");
    Serial.print(DIFFIE_KEY[c]);
  }
    Serial.println("\n\n---------- | RESYNCHRONIZATION |----------\n");
    Serial.println();
    Serial.println("Awaiting Resync Request from Sender...");
    while (response[0] != 'Y') {
        receiveMsg(response, 1);
    }
    response[0] = 's';
    Serial.println("RESYNC REQUEST RECEIVED!");

    //Take extra step to resync with sender.  This might solve desync issues causing Bloom Filter failures.
    Serial.println();
    Serial.println("RESYNCHRONIZING WITH SENDER");
    response[0] = 'Y';
    Serial.println("Sending OK to receive");
    // Declare that this node is ready to receive messages
    sendMsg(response);
    Serial.println("OK Sent!");
    while (msgReceived[0] != 'G') {
        receiveMsg(msgReceived, 1);
    }

    Serial.println("Ready to Go!");

  Serial.println("\n\n---------- | BLOOM FILTER |----------\n");


  //A message with a false ID is purposefully sent to the node to see if the filter is working.
  receiveMsg_BLOOM(msgReceived, MSG_SIZE);

  receiveMsg_BLOOM(msgReceived, MSG_SIZE);
  Serial.println("\n\n---------- | HASHING |----------\n");
  int i = 0;  //Define iterator for hashing tests
  while (i <= 10){
      unsigned char arr[ARR_SIZE] = "56789";
      unsigned char arr1[ARR_SIZE] = "00000";

      uint8_t buf[BUF_SIZE];

      byte rHash[HASH_SIZE + 16]; //Received Hash
      uint8_t hash[HASH_SIZE];


      while (!spritz_compare(arr, arr1, ARR_SIZE)) {
          receiveMsg(arr1, ARR_SIZE);
      }
      if (loopCount == 9999) {
          startTime = millis();
          Serial.println("Timer Started");
      }

      senderID = 'X';
      // The Message
      while (senderID != thisID) {
          receiveMsg(buf, 8);
      }
      receiveMsg(&buf[8], 8);
      aes128_dec_single(DIFFIE_KEY, buf);

      senderID = 'X';
      // The Hash of the Message
      while (senderID != thisID) {
          receiveMsg(rHash, 8);
      }
      receiveMsg(&rHash[8], 8);
      receiveMsg(&rHash[16], 4);


      spritz_mac(hash, HASH_SIZE, buf, BUF_SIZE, DIFFIE_KEY, KEY_SIZE);

      if (!spritz_compare(hash, rHash, HASH_SIZE)) {
          Serial.print("Failed - ");
          Serial.println(((stopTime - startTime)/10000.0) - 1200);
      }
      else {
          Serial.print("\nSuccess!! The correct message is received");
      }

      Serial.print("\nCount: ");
      Serial.println(loopCount);
      if (loopCount == 0) {
          stopTime = millis();
          Serial.print("Time in mili seconds : ");
          Serial.println(((stopTime - startTime)/10000.0) - 1200);
          Serial.print("Time in seconds : ");
          Serial.println((((stopTime - startTime)/10000.0) - 1200)/1000.0);
          loopCount = 9999;
      }
      loopCount--;
      i += 1;
  }
  Serial.println("END SETUP.  ENTER LOOP\n");
}

void loop() {

  //CAN.readMsgBuf(&len,buf);
  receiveMsg(msgReceived, MSG_SIZE);
  int state = 1;

  switch(state) {
      //States 0-99 are for standard operation
      //States 100-200 are for testing purposes
      //States 900-999 are for error handling/exceptions

      case 0:
          //Resynchronization with sender
          Serial.println("RESYNC REQUEST RECEIVED!");
          Serial.println("\n\n---------- | RESYNCHRONIZATION |----------\n");
          Serial.println();
          response[0] = 's';

          //Take extra step to resync with sender.  This might solve desync issues causing Bloom Filter failures.
          response[0] = 'Y';
          Serial.println("Sending OK to receive");
          // Declare that this node is ready to receive messages
          sendMsg(response);
          Serial.println("OK Sent!");
          while (msgReceived[0] != 'G') {
              receiveMsg(msgReceived, 1);
          }

          Serial.println("Ready to Go!");


      case 1:
          // Check Message and decrypt using private key
          // RECEIVES MESSAGE |---------------------------------------------------------------------------------------------------------------------
          // Bob (receiver) gets a message from Alice (sender)
          for (int i = 0; i < MSGS_PER_KEY; i++) {
              receiveMsg(msgReceived, MSG_SIZE);

              //Bob (receiver) does the second layer of encryption on the received message, to get the shared key
              for ( int x = 0; x < MSG_SIZE; x++) {
                  msgReceived[x] = powMod(msgReceived[x], privateKey[(i*MSG_SIZE) + x], prime);
                  DIFFIE_KEY[(i*MSG_SIZE) + x] = msgReceived[x];
              }
          }

          if (msgReceived[0] == 'R'){
              state = 0; //Resync state
          }
          else {
              state = 2;  //Change to response state
          }

      case 2:
          // Respond to sender
          srand(EEPROM[0]); //generate random delay times for responses
          for ( int i = 0; i < MSGS_PER_KEY; i++) {
              // Bob makes the response
              for ( int x = 0; x < MSG_SIZE; x++ ){
                  response[x] = powMod(generator, privateKey[(i*4) + x], prime); // This is Bob's half-encrypted shared key
              }

              //Bob sends the response
              sendMsg(response);
          }

          //Switch to state 101 is for testing purposes
          state = 101;

      case 101:
          //Print out the Key
          Serial.print("SHARED KEY:");
          for (int c = 0; c < KEY_SIZE; c++) {
              Serial.print(" ");
              Serial.print(DIFFIE_KEY[c]);
          }

      case 102:
          //Bloom Filter testing
          //We should be able to fold this receiveBloom function into the normal receive function.  For now, it will be left separate.
          receiveMsg_BLOOM(msgReceived, MSG_SIZE);

  }


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
    Serial.println("Starting isValid:");
  // After the unknown node sends its SRAM PUF, make a hash from the PUF.
  uint16_t index[7];
  getIndexes(index, puf);
  Serial.println("SRAM PUF hashed.");

  Serial.println("Running through index, check for 1");
  //For each index, check if the index is a 1.
  for (int i = 0; i < 7; i++) {
    uint8_t byteNum = index[i] / 8;      // Index of the byte to be read
    Serial.print("Value of Byte: ");
    Serial.println(byteNum);

    uint8_t bitNum = index[i] % 8;       // Index of the bit to be read from within the byte
    Serial.print("Value of Bit: ");
    Serial.println(bitNum);

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

// COMMUNICATION FUNCTIONS |------------------------------------------------------------------------------------------------------
void sendMsg(uint8_t* msg) {
  delay(10 * (rand() % 500 + 1)); //Delay for 0.1 to 5 seconds
  CAN.sendMsgBuf(thisID, 0, MSG_SIZE, msg);
}

uint8_t temp[CAN_MAX];
void receiveMsg(uint8_t* msg, uint8_t msgLength) {
  while(CAN_MSGAVAIL != CAN.checkReceive());

  byte len = MSG_SIZE;
  CAN.readMsgBuf(&len, temp);
  senderID = CAN.getCanId();

  for (int i = 0; i < msgLength; i++) {
    msg[i] = temp[i];
  }
}

//This is an experimental function, to test the bloom filter.
void receiveMsg_BLOOM(uint8_t* msg, uint8_t msgLength) {
  while(CAN_MSGAVAIL != CAN.checkReceive());

  byte len = MSG_SIZE;
  CAN.readMsgBuf(&len, temp);
  senderID = CAN.getCanId();
  bool senderIsValid = true;

  if (isFishy()) {
    uint8_t yes[4] = {'Y', 'Y', 'Y', 'Y'};
    sendMsg(yes);

    uint8_t fishyPuf[16];

    senderID = 'X';
    while (senderID != trueSenderID) {
      receiveMsg(fishyPuf, 8);
    }
    receiveMsg(&fishyPuf[8], 8);

    senderIsValid = isValid(fishyPuf);
  }
  else {
    uint8_t no[4] = {'N', 'N', 'N', 'N'};
    sendMsg(no);
  }

  if (senderIsValid) {
    for (int i = 0; i < msgLength; i++) {
      msg[i] = temp[i];
    }
    Serial.println("SAFE NODE!");
  }
  else {
    Serial.println("CORRUPT NODE!");
  }

}

bool isFishy() {
    Serial.println("Running isFishy()...");
  for (int i = 0; i < 4; i++) {
      //DEBUG CODE:
      if (i==0){
          Serial.println("Checking against Node A");      }
      else if (i==1){
          Serial.println("Checking against Node B");      }
      else if (i==2){
          Serial.println("Checking against Node C");      }
      else if (i==3){
          Serial.println("Checking against Node D");
      }
    if (senderID != nodeID[i] && senderID != 0) { //ALL_RECEIVE = 0 in sender program
        Serial.println("isFishy determined TRUE");
        return true;
    }
  }
    Serial.println("isFishy determined FALSE");
    return false;
}

void printMsg(uint8_t* msg) {
  Serial.print("Alice's Message:");
  for (int a = 0; a < MSG_SIZE; a++) {
    Serial.print(" ");
    Serial.print(msg[a]);
  }
  Serial.println("\n");
}
