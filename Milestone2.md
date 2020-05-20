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
#### Member Contributions
* Jack Retterer - This week I worked on getting a keylogger for both MAC, and Linux systems that we will be using to test the packet sniffer with, as well as use Ubuntu to get the packet sniffer running on the Linux system. I also worked on Design Doc 1.
* Zack McDowell - This week I worked on attempting to implement the packet sniffer on the MAC system, and then after running into socket API difficulties ended up implementing a packet sniffer on the Linux system, debugging it, and making sure the sniffer showed established connections.
* Jack Abukhovski - This week I worked on both, Milestone 1 and Milestone 2 power points and video editing, I also created Design Doc 2, and in addition have been using Ubuntu to debug the packet sniffer information.
#### Design Doc 1
* https://docs.google.com/document/d/1BZzWY7O2cwzse18eGwPLyvzinudyrf9mBvrLo_y8eEA/edit
#### Design Doc 2
* https://docs.google.com/document/d/1TVQ59d-EK6Tnd2sOcIQZy7yKwgGNyR952KOUZaCgpJo/edit#
#### Milestone 2 Video Link
* https://www.youtube.com/watch?v=uj8qcmGagY4
