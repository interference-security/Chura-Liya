# Chura-Liya
Project "Chura Liya" is inspired from TrustWave SpiderLabs' project Smuggler (http://blog.spiderlabs.com/2014/11/smuggler-an-interactive-80211-wireless-shell-without-the-need-for-authentication-or-association.html).

It is a wireless interactive shell which utilizes 802.11 Management Frames to establish communication between two devices. It is different from usual wireless communication because it does not require any association or authentication to be performed before starting any communication.

Concept behind Smuggler tool was released by its author but the tool itself was not released. Project Chura-Liya comes out of this and shows the raw code and concept of the original project.

Due credits to TrustWave SpiderLabs' Smuggler project.

#Concept
802.11 wireless protocol has management frames which are used by wireless enabled stations to establish and maintain communication with other wireless devices. Two management frame types used in this project are:
  1. Beacon Frames
  2. Probe Requests

Beacon Frames are used by wireless access points to notify nearby wireless clients about its presence along with other details of the access point like its name (SSID field), etc.

Probe Requests are used by wireless stations seeking wireless access point using its name, which is mentioned in the SSID field.
Beacon Frames has Information Element fields, one of which is “RATES” field. This field can be used to store data and transmit in air.
