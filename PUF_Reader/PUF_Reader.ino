#include <EEPROM.h>

// List of SRAM values at startup
// Address is dynamic. When globals are added/removed, the base address changes.
unsigned char bytes[ 1024 ] __attribute__ ((section (".noinit")));

/*
'A' == Uno-14402
'B' == Uno-14162
'C' == Uno-14168
'D' == Uno-14154
*/

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

void setup() {
  Serial.begin(115200);

  Serial.println("\n\n");

  printBaseAddress();
  Serial.println(" ");
  printSRAM();

  Serial.println("\n");
  //! Programmer must input the letter associated with their Uno device
  fillStableBytes('B');
  printStableBytes();
}

void loop() {  /* EMPTY LOOP */  }
