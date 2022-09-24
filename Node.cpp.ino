#include "Node.h"
#include <EEPROM.h>

Node::Node() {
  //Set the CAN Object
  CAN = MCP_CAN(SPI_CS_PIN);

  //Set the Friend IDs
  uint8_t nodeID[4] = {0xD3, 0xFA, 0xF3, 0x74};
  uint8_t x = 0;
  for (uint8_t i = 0; i < nodeID.sizeof(); i++) {
    if (nodeID[i] != getID()) {
      friendID[x] = nodeID[i];
      x++;
    }
  }

  //Set hashes & shared keys to zero
  for (uint8_t i = 0; i < NUM_NODES; i++) {
    for (uint8_t j = 0; j < KEY_LEN; j++) {
      sharedKey[i][j] = 0;
      hash[i][j] = 0;
    }
  }
}
// GETTERS |-----------------------------------------------------------------------------------------------------------------
uint8_t Node::getID() {
  return EEPROM[0];
}

uint8_t Node::getPUF(uint8_t i) {
  if (i >= 0 && i < 16) {
    return EEPROM[i];
  }

  char func[] "getPUF()";
  errorMsg(func, func.sizeof(), i, 0, 15);
  return 0;
}

uint8_t Node::getFriendID(uint8_t i) {
  if (i < friendID.sizeof()) {
    return friendID[i];
  }

  char func[] = "getFriendID()";
  errorMsg(func, func.sizeof(), i, 0, friendID.sizeof());
  return 0;
}

uint8_t Node::getNum(uint8_t const id) {
  for (uint8_t x = 0; x < friendID.sizeof(); x++) {
    if (friendID[x] == id) {
      return x;
    }
  }

  char func[] = "getNum()";
  errorMsg(func, func.sizeof(), id, 0, friendID.sizeof());
  return 200;
}


bool Node::getBloomBit(uint16_t const i) {
  //Get the Byte and the bit of that byte from i.
  uint8_t byteNum = i / 8;
  uint8_t bitNum = i % 8;

  return bitRead(EEPROM[byteNum+16], bitNum);
}

//COMMUNICATORS |------------------------------------------------------------------------------------------------------------
/******************************************************
SPEAK (Long Version)
- Delays for 0.1 to 5 seconds based on the randomseed used
- msg == message to be sent
- msgLength == length of message to be sent
- id == Message ID

Used when authenticating with Bloom Filter
******************************************************/
void Node::speak(uint8_t* msg, uint8_t msgLength, uint8_t id) {
  delay(10 * (rand() % 500 + 1)); //Delay for 0.1 to 5 seconds
  CAN.sendMsgBuf(id, 0, msgLength, msg);
}

/******************************************************
SPEAK (Shorter)
Message ID is the user's ID by default.

Used in the hashing phase of communication.
******************************************************/
void Node::speak(uint8_t* msg, uint8_t msgLength) {
  speak(msg, msgLength, getID());
}

/******************************************************
SPEAK (Short)
Message ID is the user's ID by default.
Message Length is 4 bytes by default.

Used for Diffie-Hellman key exchange (shared key generation)
******************************************************/
void Node::speak(uint8_t* msg) {
  speak(msg, MSG_LEN, getID());
}

/******************************************************
HEAR
Waits to receive a message
Receives the message
Checks if this node is the intended recipient
******************************************************/
void Node::hear(uint8_t* msg, uint8_t msgLength) {
  while(CAN_MSGAVAIL != CAN.checkReceive());

  uint8_t len = msgLength;
  CAN.readMsgBuf(&len, tempMsg);

  for (int i = 0; i < msgLength; i++) {
    msg[i] = temp[i];
  }
}

//AUTHENTICATION FUNCTIONS |-------------------------------------------------------------------------------------------------
/******************************************************
IDENTIFY
Return true if the message ID is a friendly node's ID or this node's ID.
Return false otherwise.
If false, interrogate the message's transmitter.
******************************************************/
bool Node::identify(uint8_t const id) {
  for (int i = 0; i < friendID.sizeof(); i++) {
    if (friendID[i] == id) {
      return true;
    }
  }
  
  if (getID() == id) {
    return true;
  }
  
  return false;
}
/******************************************************
INTERROGATE
Check if the sender's ID is valid.
If it is, tell them they continue as they were
Otherwise, ask them for their PUF ID, and run it through the bloom filter.
******************************************************/
bool Node::interrogate() {
  if (identify(CAN.getCanId())) {
    char asYouWere[] = "YYYY";
    speak(asYouWere);
    return true;
  }

  char stopRightThere[] = "NNNN";
  speak(stopRightThere);

  uint8_t susPuf[16];
  hear(susPuf, 8);
  hear(&susPuf[8], 8);
}


void Node::comply() {
  uint8_t response[4];
  hear(response, response.sizeof());

  if (response[0] = 'Y') {
    return;
  }

  if (response[0] = 'N') {
    uint8_t halfPUF[16];
    for (int i = 0; i < halfPUF.sizeof(); i++) {
      halfPUF[i] = getPUF(i); 
    }
    speak(halfPUF, 8);
    speak(&halfPUF[8], 8);

    
  }
}

//TROUBLESHOOTING FUNCTIONS |------------------------------------------------------------------------------------------------
void Node::errorMsg(char* funcName, int nameLength, uint8_t const entry, uint8_t const firstIndex, uint8_t const lastIndex) {
  Serial.println();
  Serial.print("ERROR IN ");
  for (int i = 0; i < nameLength; i++) {
    Serial.print(funcName[i]);
  }
  
  Serial.println();
  Serial.print(entry);
  Serial.print(" ISN'T IN THE EEPROM BOUNDS ");
  Serial.print(firstIndex);
  Serial.print(" TO ");
  Serial.println(lastIndex);
}
