# CS1652_Project2
All files we submitted are `tcp.c`, `tcp_connection.h` and `README.md`. We do not change the makefile.

## Team Composition
Our team name is Marcosoft, which consists of two members: Guangrui Wang & Wentao Wu.

## Task Division
Guangrui is responsible for `Passive Open` & `Data Flow` and Wentao is responsible for `Active Open` & `Connection Teardown`. Cooperation includes online such as zoom &livecode, and offline such as library & Wentao's apartment:)

## Realization Degree
`Passive Open`: 

We have successfully implemented the Passive Open function. 
We have tested this function through the listen_server.c.
We used Wireshark to make sure that our code response to syn,syn-ack,ack, then set up the connection.

test process:
1. listen_server listen on port 3000
2. nc 192.168.201.12 3000
3. listen_server set up the connection after handshake

`Active Open`:

We have successfully implemented the Active Open function. 
We have not tested this function.
I think the logic is correct, but I not sure how to test it. 
I tried to use the http server and client from project 1 to test it, but I found some errors that I don't know how to fix.

`Data Flow`:

We have successfully implemented the Data Flow function.
We have tested this function through the listen_server.c.
We used Wireshark to make sure that our code response to push ack and ack.

send one message test process:
1. After the handshake, enter test_message in the nc terminal and ctrl+d to send message.
2. listen_server receive the message and send ack.

send multiple messages test process:
3. after the previous step, press enter to start a new line.
4. enter the test_message in the nc terminal and ctrl+d to send message.
5. repeat step 3 and 4.

`Connection Teardown`:

We tried to implement the Connection Teardown function.
We have tested this function through the listen_server.c.
When we close the connection from the nc, it seems work from the wireshark packet.
Since we didn't test the active close, we are not sure about whether the active close works.

`Timeouts`:

We tried to implement the Timeout function, but actually it does not work as we  expected.

`Extra Part`:

We did not implement this part :(