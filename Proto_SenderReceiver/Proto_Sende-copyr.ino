/// SETUP & LOOP |+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//NOTE: The Different tests do not currently function perfectly when executed sequentially, due to desync issues.  However, each test is individually valid.  Functions will still work when executed sequentially.
int state = 1;
void loop() {
    Serial.println("Looping...");
    switch(state){
        case 0:
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

            state = 1;
            break;

        case 1:
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
            state = 2;  //Switch to response state in preparation for a reply from each receiver
            break;

        case 2:
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
            state = 101;
            break;

        case 101:
            //Prints keys out for testing purposes
            printKeys();
            state = 102;
            break;

        case 102:
            //Bloom Filter testing (to be folded into main sender testing)
            sendMsg(msgSent, MSG_SIZE, 'X');
            Serial.println("First Check sent.");
            verifyThisNode();
            Serial.println("Verification complete.  Proceeding to second test.");
            state = 103;
            break;

        case 103:
            Serial.println("Second test.");
            //sendMsg(msgSent, MSG_SIZE, nodeID[0]);
            sendMsg(msgSent, MSG_SIZE, thisID);
            Serial.println("Second Check sent.");
            verifyThisNode();
            Serial.println("Second test complete.");

            state = 0;
            break;

        case 104:
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
            state = 0;
            break;

        default:
            Serial.print("Error: No Case with number");
            Serial.println(state);
            state = 1;
            break;
    }


}



