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

#define NUM_NODES    3  //Number of Receivers

#define CAN_MAX 64

bool is_Sender = false;
bool is_Receiver = false;

//Diffie-Hellman Variables
//const uint8_t prime = 2147483647;
const uint8_t prime = 251;
const unsigned int generator = 16807;

uint8_t nodeID[4] = {0xBE, 0xFE, 0xBF, 0xE7};
uint8_t thisID = EEPROM[0];
uint8_t trueSenderID;
uint8_t senderID = 'X';
uint8_t TestSenderID = 'X';  //This is a testing variable.  We can remove it later.

const uint8_t sramPUF[4][16] = {
        { 0xBE, 0x59, 0x37, 0xF8, 0xC6, 0x3E, 0xA7, 0xAA, 0xED, 0xB9, 0x9F, 0xBA, 0xBB, 0xEB, 0xB5, 0x35 }, //A
        { 0xFE, 0xAF, 0xC5, 0xBE, 0xB2, 0x36, 0x38, 0x7A, 0x2F, 0xFF, 0xBD, 0x9C, 0xEF, 0xF6, 0xD0, 0xCE }, //B
        { 0xBF, 0xFC, 0x8E, 0xF6, 0xF4, 0x6F, 0x76, 0x3B, 0xBB, 0x73, 0xF1, 0xEF, 0x7D, 0xE5, 0x1A, 0x3D }, //C
        { 0xE7, 0x9F, 0xD9, 0xAB, 0x69, 0x69, 0xFE, 0x6D, 0x77, 0xD5, 0x9D, 0xF3, 0x6F, 0xBD, 0xAD, 0xED }  //D
};

// Pins & LEDs
#define SPI_CS_PIN 10
#define LED        8
#define ledON      true


// Hashing Variables
#define HASH_SIZE 20
#define BUF_SIZE 16
#define ARR_SIZE 5
uint8_t hash[NUM_NODES][HASH_SIZE];


int loopCount = 9999;
int startTime;
int stopTime;



MCP_CAN CAN(SPI_CS_PIN);
//TODO: Address the Diffie_Key situation.  We want to combine the programs, so decide whether receivers should hold only own key or all.
uint8_t DIFFIE_KEY[KEY_SIZE]; //Receivers only hold their own key. Makes it simpler for now.

uint8_t DIFFIE_KEY[NUM_NODES][KEY_SIZE];
uint8_t msgCounter[NUM_NODES];
uint8_t responderID;

///FUNCTIONS |-----------------------------------------------------------------------------------------------------------------------------
// KEY GENERATION
uint8_t keyGen(int i);                            // Generates 1 byte, "a", of the 16-byte key.
uint8_t mulMod(uint8_t a, uint8_t b, uint8_t m);  // (a*b) mod m
uint8_t powMod(uint8_t b, uint8_t e, uint8_t m);  // (b^e) mod m

// Bloom Filter Functions
bool isValid(uint8_t* puf);
void getIndexes(uint16_t* indexes, uint8_t* puf);

// COMMUNICATION FUNCTIONS
//void sendMsg(uint8_t* msg);  Don't need this old definition anymore.
void printMsg(uint8_t* msg);

uint8_t msgReceived[MSG_SIZE];    //The 1st 4 members are what's needed
uint8_t response[MSG_SIZE];      //One quarter of a message sent  //TODO: Compare with sender's response array
uint8_t privateKey[KEY_SIZE];

//! Sender Comms functions
void sendMsg(uint8_t* msg, int msgLength, uint8_t receiverID);  //TODO: We have two function definitions for sendMsg.  We can combine them into one, and then just have preset parameters for if its a receiving node.
void receiveMsg(uint8_t* msg, uint8_t msgLength);  // Use one function definition (the two receive functions were the same)

/// SENDER-SPECIFIC FUNCTIONS
void recordMsg(uint8_t* msg);
void printKeys();
uint8_t findNode(const uint8_t msgID);
void verifyThisNode();


bool isFishy();

/// Message Storage Arrays
uint8_t privateKey[KEY_SIZE];   //One quarter of the private key
uint8_t msgSent[MSG_SIZE];      //One quarter of a message sent
uint8_t response[CAN_MAX];     // Needs to be bigger  //TODO: Compare with receiver's response array.

/// SETUP & LOOP |+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void setup() {
    Serial.begin(115200);
    pinMode(LED,OUTPUT);

    Serial.println("Starting Sender/Receiver...")

    // Delay until data can be read.
    while (CAN_OK != CAN.begin(CAN_500KBPS)) {             // init can bus : baudrate = 500k
        Serial.println("CAN BUS Shield init fail");
        Serial.println("Init CAN BUS Shield again");
        delay(100);
    }


    if ((thisID == 0xBE) or (thisID == 0xFE) or (thisID == 0xBF)){  // If we are running on nodes A, B, or C
        is_Receiver = true;
        is_Sender = false;
        state = 1;  //TODO: Verify that we are starting in the correct state
    }
    else if (thiID == 0xE7){  // If we are running on node D
        is_Receiver = false;
        is_Sender = true;
        state = 51; //TODO: Verify that we are starting in the correct state
    }

    printf("Receiver?: %s\n", is_Receiver ? "true" : "false");  // Check and make sure this actually works.
    printf("Sender?: %s\n", is_Sender ? "true" : "false");  // Check and make sure this actually works.

    if (is_Receiver);{
        Receiver_setup();
    }

    else if (is_Sender){
        Sender_setup();
    }

    Serial.println("Sender/Receiver Setup Complete");

}

void Sender_setup() {
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
        //Serial.print("Number of Nodes: ");
        //Serial.println(NUM_NODES);
        //Serial.print("Current iterator value: ");
        //Serial.println(i);
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

}
void Receiver_setup() {
  Serial.println("Starting Receiver Mode...");

  // Delay until data can be read.
  while (CAN_OK != CAN.begin(CAN_500KBPS)) {             // init can bus : baudrate = 500k
    Serial.println("CAN BUS Shield init fail");
    Serial.println("Init CAN BUS Shield again");
    delay(100);
  }

  Serial.println("\n\nStarting Private Key Generation...");
  // Bob generates his private key
  for (int i = 0; i < KEY_SIZE; i++) {
    privateKey[i] = keyGen(i); //privateKey = 0 -> keyGen(i) = 0
    DIFFIE_KEY[i] = 0;
  }
  response[0] = 'Y';
  Serial.println("Sending OK to receive");
  // Declare that this node is ready to receive messages
  sendMsg(response, MSG_SIZE, thisID);  //Changed here to fit the new SendMSG Function
  Serial.println("OK Sent!");
  while (msgReceived[0] != 'G') {
    receiveMsg(msgReceived, 1);
  }
  trueSenderID = senderID;

  Serial.println("Ready to Go!");

  Serial.println("END SETUP.  ENTER LOOP\n");
}

void Sender_setup() {

    Serial.println("PRINTING OUT BLOOM FILTER (TROUBLESHOOT CHECK):\n");
    for (int i = 0; i < 128; i++) {
        Serial.print(EEPROM[i + 16]);
    }


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
        //Serial.print("Number of Nodes: ");
        //Serial.println(NUM_NODES);
        //Serial.print("Current iterator value: ");
        //Serial.println(i);
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

}

//NOTE: The Different tests do not currently function perfectly when executed sequentially, due to desync issues.  However, each test is individually valid.  Functions will still work when executed sequentially.
int state = -1;  // Define starting state.  For starters, it will be a state that does not exist, but, will be set a starting state depending on whether the node is a sender or receiver.
void loop() {
  Serial.println("Looping...");
  //CAN.readMsgBuf(&len,buf);
  //receiveMsg(msgReceived, MSG_SIZE);

  switch(state) {
      //States 0-99 are for standard operation
      //! States 0-49 are for Receivers (FOR NOW)
      //! States 50-99 are for Senders (FOR NOW)
      //States 100-200 are for testing purposes
      //States 900-999 are for error handling/exceptions
      case 0:
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
          sendMsg(response, MSG_SIZE, thisID);  //Changed here to fit the new SendMSG Function

          Serial.println("OK Sent!");
          while (msgReceived[0] != 'G') {
              receiveMsg(msgReceived, 1);
          }

          Serial.println("Ready to Go!");
          state = 1;
          break;

      case 1:
          //// RECEIVES MESSAGE |---------------------------------------------------------------------------------------------------------------------
          Serial.println("Entering state 1");
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
          Serial.println("Moving to state 2");
          state = 2;  //Change to response state
          break;

      case 2:
          //// RESPONDS |-----------------------------------------------------------------------------------------------------------------------------
          Serial.println("Entering state 2");
          // Respond to sender
          srand(EEPROM[0]); //generate random delay times for responses
          for ( int i = 0; i < MSGS_PER_KEY; i++) {
              // Bob makes the response
              for ( int x = 0; x < MSG_SIZE; x++ ){
                  response[x] = powMod(generator, privateKey[(i*4) + x], prime); // This is Bob's half-encrypted shared key
              }

              //Bob sends the response
              sendMsg(response, MSG_SIZE, thisID);  //Changed here to fit the new SendMSG Function
          }

          //Switch to state 101 is for testing purposes
          state = 101;
          break;

      case 101:
          //// PRINT OUT |----------------------------------------------------------------------------------------------------------------------------
          //Print out the Key
          Serial.print("SHARED KEY:");
          for (int c = 0; c < KEY_SIZE; c++) {
              Serial.print(" ");
              Serial.print(DIFFIE_KEY[c]);
          }
          state = 102;
          break;

      case 102: //TODO create a bloom filter check function
          //Bloom Filter testing
          //We should be able to fold this receiveBloom function into the normal receive function.  For now, it will be left separate.
          Serial.println("First Test: ");
          receiveMsg_BLOOM(msgReceived, MSG_SIZE);
          delay(1000); //Wait for 1 second - let the sender get ahead.
          state = 103;
          break;

      case 103:
          Serial.println("Second Test: ");
          receiveMsg_BLOOM(msgReceived, MSG_SIZE);
          delay(1000); //Wait for 1 second - let the sender get ahead.
          state = 0;
          break;


      case 104:
          Serial.println("\n\n---------- | HASHING |----------\n");
          //int i = 0;  //Define iterator for hashing tests
          while(true) {
          //while (i < 10){
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
                  Serial.println(((stopTime - startTime) / 10000.0) - 1200);
              } else {
                  Serial.print("\nSuccess!! The correct message is received");
              }

              Serial.print("\nCount: ");
              Serial.println(loopCount);
              if (loopCount == 0) {
                  stopTime = millis();
                  Serial.print("Time in mili seconds : ");
                  Serial.println(((stopTime - startTime) / 10000.0) - 1200);
                  Serial.print("Time in seconds : ");
                  Serial.println((((stopTime - startTime) / 10000.0) - 1200) / 1000.0);
                  loopCount = 9999;
              }
              loopCount--;
              //i++;
          }
          state = 0;
          break;

      case 50:
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

          state = 51;
          break;

      case 51:
          //// SEND MESSAGE |-------------------------------------------------------------------------------------------------------------------------
          //Send message to all receiver nodes ("Bobs")
          Serial.println("Entering case 1");
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
          state = 52;  //Switch to response state in preparation for a reply from each receiver
          break;

      case 52:
          //// RECEIVES RESPONSE |--------------------------------------------------------------------------------------------------------------------
          //Receive a message from all receiver nodes ("Bobs")
          Serial.println("Entering case 2");
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
          state = 151;
          break;

      case 151:
          //Prints keys out for testing purposes
          printKeys();
          state = 152;
          break;

      case 152:
          //Bloom Filter testing (to be folded into main sender testing)
          sendMsg(msgSent, MSG_SIZE, 'X');
          Serial.println("First Check sent.");
          verifyThisNode();
          Serial.println("Verification complete.  Proceeding to second test.");
          state = 153;
          break;

      case 153:
          Serial.println("Second test.");
          //sendMsg(msgSent, MSG_SIZE, nodeID[0]);
          sendMsg(msgSent, MSG_SIZE, thisID);
          Serial.println("Second Check sent.");
          verifyThisNode();
          Serial.println("Second test complete.");

          state = 50;
          break;

      case 154:
          //Hashing tests
          Serial.println();
          Serial.println();
          Serial.println("---------- | HASHING |----------");
          //int i = 0;
          //while (i < 20){
          while(true) {

              unsigned long time = millis();
              Serial.print("Time: ");
              Serial.println(time / 1000);
              Serial.println("\n");

              unsigned char arr[] = "56789";
              sendMsg(arr, 5, thisID);

              for (int i = 0; i < NUM_NODES; i++) {
                  char stmp[16] = "1234567890123456";
                  spritz_mac(hash[i], HASH_SIZE, stmp, sizeof(stmp), DIFFIE_KEY[i], KEY_SIZE);
                  aes128_enc_single(DIFFIE_KEY[i], stmp);
                  sendMsg(stmp, 8, nodeID[i]);
                  sendMsg(&stmp[8], 8, nodeID[i]);
                  delay(200);
              }
              //i++;
          }
          state = 50;
          break;

      default:
          Serial.println("Error: No Case with number.");
          //state = 1;
          break;
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
  Serial.println("Starting isValid:\n\n\n");
  // After the unknown node sends its SRAM PUF, make a hash from the PUF.
  uint16_t index[7];

  //logic to find the indexes from the associated PUF, given a nodeID.
  //TODO: for now, we can leave it like this.  In the future, I would like to have the message send the PUF, which we will check directly with getIndexes instead of these if statements
  if (puf == nodeID[0]){
      getIndexes(index, sramPUF[0]);
  }
  else if (puf == nodeID[1]){
      getIndexes(index, sramPUF[1]);
  }
  else if (puf == nodeID[2]){
      getIndexes(index, sramPUF[2]);
  }
  else if (puf == nodeID[3]){
      getIndexes(index, sramPUF[3]);
  }
  else{
      return false;
  }

  Serial.println("\nSRAM PUF hashed.");

  //Serial.println("Running through index, check for 1");
  //For each index, check if the index is a 1.
  for (int i = 0; i < 7; i++) {
    uint8_t byteNum = index[i] / 8;      // IndexS of the byte to be read
    Serial.print("Index of Byte: ");
    Serial.println(byteNum);

    uint8_t bitNum = index[i] % 8;       // Index of the bit to be read from within the byte
    Serial.print("Index of Bit: ");
    Serial.println(bitNum);

    Serial.print("Value at the index: ");
    Serial.println(bitRead(EEPROM[byteNum+16], bitNum));

      //If the index is not a 1, then this node isn't valid.
    if (!bitRead(EEPROM[byteNum+16], bitNum)) {
      Serial.println("IsValid Returning False.") ;
      return false;
    }
  }

    Serial.println("IsValid Returning True.") ;
    return true;
}

void getIndexes(uint16_t* indexes, uint8_t* puf) {
  //The puf is 16 bytes long, the index is 7 bytes long.
  const uint8_t k = 7; //Number of indexes to be made from the hash

  Serial.println("PRINTING HASH OF NODE ID\n\n\n");
  //Hash the SRAM PUF (First 16 Bytes)
  uint8_t hash[9];
  spritz_hash(hash, 9, puf, 16);

  for (int i=0; i<9; i++) {
      Serial.println(hash[i]);
  }
  Serial.println("\n\n\n");
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
//----------------------SENDER/RECEIVER COMMS FUNCTIONS----------------------------
void sendMsg(uint8_t* msg, int msgLength, uint8_t receiverID) {  //This function combines the sender and receiver variants.
    //S
    Serial.print("RECEIVER ID: ");
    Serial.println(receiverID);

    if (is_Receiver){  //Enclosing this delay in an if statement because this is how the codebase had it set up.  We may just always include a random delay.
        delay(10 * (rand() % 500 + 1)); //Delay for 0.1 to 5 seconds
    }

    CAN.sendMsgBuf(receiverID, 0, msgLength, msg);
    //The sender function has more functionality than the receiver function.  We can fit adjust the receiver calls to sendMsg to fit the additional options

    if (is_Sender){
        delay(200);
    }
}

uint8_t temp[CAN_MAX];
void receiveMsg(uint8_t* msg, uint8_t msgLength) {  //The two receive msg functions are identical.
    while(CAN_MSGAVAIL != CAN.checkReceive());

    byte len = MSG_SIZE;
    CAN.readMsgBuf(&len, temp);
    responderID = CAN.getCanId();

    for (int i = 0; i < msgLength; i++) {
        msg[i] = temp[i];
    }

}

//----OTHER COMMS Functions-------------
//This is an experimental function, to test the bloom filter.
void receiveMsg_BLOOM(uint8_t* msg, uint8_t msgLength) {
  while(CAN_MSGAVAIL != CAN.checkReceive());

  byte len = MSG_SIZE;
  CAN.readMsgBuf(&len, temp);
  senderID = CAN.getCanId();
  Serial.println("\n\nSender ID:");
  Serial.println(senderID);
  bool senderIsValid = true;

  if (isFishy()) {
    uint8_t yes[4] = {'Y', 'Y', 'Y', 'Y'};
    sendMsg(yes, MSG_SIZE, thisID);  //Changed here to fit the new SendMSG Function


      uint8_t fishyPuf[16];

    //senderID = 'X';
    TestSenderID = 'X';
    senderIsValid = isValid(senderID);

  }
  else {
    uint8_t no[4] = {'N', 'N', 'N', 'N'};
    sendMsg(no, MSG_SIZE, thisID);  //Changed here to fit the new SendMSG Function
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


// SENDER MESSAGE COMMUNICATION FUNCTIONS |------------------------------------------------------------------------------------------------------
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


