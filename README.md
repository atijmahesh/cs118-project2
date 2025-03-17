# CS 118 Winter 25 Project 2
## Read Me
### Design Choices
For the most part, we followed the spec closely, ensuring that our implementation adhered to the protocol. However, we made a few design choices, including using distinct global variables to store important handshake and encryption-related data, such as client and server states, public keys, and handshake messages. We also stored and initialized the global type (if we were using client or server) with g_type, which was very helpful in maintaining proper state machine functionality. We used a state machine modelling @612 in Piazza pretty closely, and that was very helpful for us. For the state machine, we did the following:

The client state machine transitions through three stages: CLIENT_STATE_HELLO, CLIENT_STATE_FINISHED, and CLIENT_STATE_DATA, 
The server state machine follows a slightly more complex path with SERVER_STATE_HELLO, SERVER_STATE_FINISHED, SERVER_STATE_VERIFY_HMAC, and SERVER_STATE_DATA.

### Problems
We encountered numerous issues throughout the project. The one that was the hardest, by far, was debugging Server Hello. We constantly ran into issues in server hello, leading us to overhaul our logic and state machine multiple times, and was a massive setback. The hardest issue was especially in getting the correct handshake signiture, because we had numerous issues tied to it, including key/certificate issues as well as data processing. We also ran into problems regarding TLV headers, and just their overall format. The last major issue was in parsing and understanding the certificate in Client Finished, which was very difficult to debug.

### Solutions
To resolve our handshake issues, we refined our state machine to ensure clear transitions and prevent inconsistencies. We carefully structured the server hello , making sure each step correctly handled key exchange, certificate verification, and signature generation. For handshake signatures, we verified our key usage, structured the transcript properly, and aligned certificate handling and headers with spec. We also improved certificate parsing in Client Finished by ensuring we correctly extracted and verified fields. Shoutout Omar for spec clarifications and help overall.