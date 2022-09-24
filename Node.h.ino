#ifndef NODE_H
#define NODE_H

#include "Arduino.h"
#include <mcp_can.h>
#include <mcp_can_dfs.h>

/* A Node...
 *  has a PUF ID
 *  has shared symmetric keys
 *  has the bloom filter
 *  knows friends "nicknames"  (short ID)
 *  has a "nickname" (short ID)

 *  can speak
 *  can listen
 *  can identify a friend
 *  can interrogate a potential stranger
 *  can comply to an interrogation
*/

/* A Sender...
 *  Is a node
 *  Generates a hash from a message
 *  Encrypts the message with a shared key
 *  Sends the encrypted message
 *  Sends the hash
*/

/* A Receiver...
 *  Is a node
 *  Receives an encrypted message
 *  Receives a hash
 *  Decrypts the message
 *  Generates a hash from the decrypted message
 *  Compares the two hashes
*/

class Node {
  public:
    #define NUM_NODES 3
    #define KEY_LEN 16
    #define SPI_CS_PIN 10

    uint8_t sharedKey[NUM_NODES][KEY_LEN];
    uint8_t hash[NUM_NODES][KEY_LEN];

// CONSTRUCTORS |-------------------------------------------------------------------
    Node();

    
// GETTERS |-------------------------------------------------------------------
    uint8_t getID();            //Get the 1st byte of the 16-byte PUF ID
    uint8_t getPUF(uint8_t i);  //Get 1 byte of the 16-byte PUF ID
    uint8_t getFriendID(uint8_t i);      //Get a friend's "nickname"
    
    // Returns the index of the friendly node in friendID, if it's friendly
    uint8_t getNum(uint8_t const id);


    uint8_t getBloomBit(int i); //Get a specific bit from the bloom filter

// COMMUNICATORS |-------------------------------------------------------------------
    void speak(uint8_t* msg, uint8_t msgLength, uint8_t id);
    void speak(uint8_t* msg, uint8_t msgLength);
    void speak(uint8_t* msg);

    void hear(uint8_t* msg, uint8_t msgLength);

// Bloom Filter |-------------------------------------------------------------------
    bool identify(uint8_t const id);     //Check if the node is friendly
    bool interrogate();           //Get the entire PUF of another node. Pass through the bloom filter to authenticate.
    void comply();                //Complies to being interrogated

  private:
    uint8_t friendID[NUM_NODES];  //Stores first byte of every other node's PUF
    uint8_t tempMsg[64];          //Temporary Storage for message received.

    void errorMsg(char* funcName, int nameLength, uint8_t const entry, uint8_t const firstIndex, uint8_t const lastIndex);

    MCP_CAN CAN;

};


#endif
