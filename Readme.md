Overview:

This project is a network sniffer that detects and notifies the user when
malicious content could be being sent from their device to the internet.
We elected to use Linux out of ease and file access ability. Also because we
have Linux installed within our systems. Our initial thought behind being able
to detect malicious software would be to analyze certain packets over the
network and create a filter in order to warn the user of possible attacks.

The network analyzer identifies the different connections that are established
and it analyzes the packets to determine whether or not they are malicious,
potentially malicious, or non-malicious. This will allow us to flag the
malicious connections and warn the user that their data may be getting tracked
or a malicious type of software could have been installed to the user's system
which would result in their data becoming compromised. To accomplish this, we
analyzed different connection types such as TCP, UDP, ICMP, and any other
connections such as SMTP, and sifting through each connection to see how often
we receive and send data, and at what time intervals.

In order to prevent new and future keyloggers or malicious software from being
installed onto one’s computer, our network analyzer scans for potentially
malicious systems. We use a real-time set of blacklisted malicious IPs and
scan for any packets that are sent or received from these malicious systems.
This set is large so it would be able to detect a majority of attacks if any
of these IPs are contacted. This is the precautionary side of our software
which helps to prevent further malicious software from being installed onto
the user's system.

Information about Code:

The main portion of the network analyzers code is a set of functions that
utilizes the Socket API in order to analyze and unpack all different types of
packets. This API establishes connections to ports and this allows the analyzer
to read data from each packet. In addition, this network analyzer reads from a
database to keep an updated list of blacklistedIPs. It uses this list of
blacklistedIPs to scan each packet for any destinations or sources that could
be potentially malicious.

Final Slides:
https://docs.google.com/presentation/d/16o5aILX_ciAn4ASWe1AdJDyBQzwbRrf_azHrc_HQ9PQ/edit?usp=sharing
