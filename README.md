# CanBusCommunication
UConn Security REU Repository

Before using this code, download the following files into your Arduino >> libraries folder:
  https://github.com/tthomas2000/CANBusCommunication_Libraries

For a more detailed view on how to connect a pair of Arduino Unos, go to:
  https://www.electronicshub.org/arduino-mcp2515-can-bus-tutorial/

To connect 4 nodes, look at the 4-Way Arduino Communication image and draw.io file.

#NODE WIRING:
To connect a node to an MCP2515, use this tutorial
https://www.electronicshub.org/arduino-mcp2515-can-bus-tutorial/
When connecting 2 MCP2515, use either the J2 or J3 pins.
To connect 4 MCP2515:
 *    Suppose MCP2515 A, B, C, and D.
 *    Connect A to B and C to D using the HIGH and LOW pins on J2.
 *    Connect A to D and B to C using the HIGH and LOW pins on J3.
 *    (Forms a circle with the wires)


# DIFFIE-HELLMAN
Diffie-Hellman Method: 
  https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
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
