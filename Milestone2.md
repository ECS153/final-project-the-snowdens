# Milestone 2
## Meeting Notes - 5/19/20
#### What We Did Last Week
Last week as a group we found a simple keylogger that we will be using to test our packet sniffer with. We ended up tossing this one and finding a Linux one instead. We also began working on the back end of the packet sniffer so it can detect TCP, UDP, and IMCP connections that are established in the network. 
#### What We Plan To Do This Week
* Create and implement guidelines on what connections we want to flag as malicious
* Look into creating an interface for the packet sniffer to display the connections on
#### Things We Are Stuck On
* Started trying to write the packet sniffer to work with MAC
  * Ran into issues of not being able to easily access different ports in the socket API for MAC
  * On linux, the socket API has certain variables for ports that make it easier to trace connections
#### Pull Requests
* 


#### Design Doc
* https://docs.google.com/document/d/1BZzWY7O2cwzse18eGwPLyvzinudyrf9mBvrLo_y8eEA/edit
