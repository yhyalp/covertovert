# Covert Timing Channel that exploits Idle Period Between Packet Bursts using NTP

## Overview
This project implements a covert timing channel, a method of communication that bypasses normal security controls to transmit information covertly. Covert channels exploit unintended features of a system, such as timing delays or idle periods, to encode and transfer data secretly. They are often challenging to detect and prevent, making them a significant focus in cybersecurity research.

This implementation specifically utilizes idle periods between packet bursts in NTP traffic. The covert channel encodes data using time-based variations, leveraging 2-bit encoding (00, 01, 10, 11) to modulate idle periods. The implementation consists of two main functionalities:
### Sender: 
Encodes and transmits a binary message as timing patterns between packet bursts.
### Receiver: 
Decodes timing patterns from the captured packets to reconstruct the transmitted message. The channel uses 2-bit encoding (00, 01, 10, 11) to modulate idle periods between bursts of NTP packets.

## Sender Workflow:
### 1. Generate Random Binary Message:
- A random binary message is generated.
- The binary string is then logged for reference and debugging.

### 2. Divide Binary Message into 2-Bit Groups:
- The binary message is split into groups of two bits (00, 01, 10, 11).
- Each group represents a timing interval that will be used for encoding.

### 3. Encode Message with Timing Intervals:
- 00: Corresponds to short_delay.
- 01: Corresponds to secondshort_delay.
- 10: Corresponds to long_delay.
- 11: Corresponds to secondlong_delay.
- Idle periods between bursts of NTP packets are set according to these timing intervals.

### 4. Send NTP Packets in Bursts:
- Packets are sent in bursts with a randomly determined size between burst_min and burst_max.
- The idle period between bursts encodes the 2-bit data.

### 5. Send Final Burst:
- A final burst of packets is transmitted to signify the end of the transmission.


## Receiver Workflow:
### 1. Capture Packets:
- The receiver listens on UDP port 123 (NTP traffic) to capture incoming packets.
- The Scapy library is used to sniff packets in real time.

### 2. Extract Timing Patterns:
- The receiver calculates the time intervals (idle periods) between consecutive packet bursts.

### 3. Decode Timing Intervals:
- short_delay: Decoded as 00.
- secondshort_delay: Decoded as 01.
- long_delay: Decoded as 10.
- secondlong_delay: Decoded as 11.

### 4. Reconstruct Binary Message:
- The 2-bit values are combined to reconstruct the binary message.

### 5. Convert Binary to Characters:
- The binary message is divided into 8-bit groups and converted to ASCII characters.
- Decoding stops when the delimiter (.) is detected, signifying the end of the message.

### 6. Log Decoded Message:
- The decoded message is saved in a log file for verification.

## Sender Parameters:
### 1. log_file_name: 
File name to log the transmitted binary message.
### 2. short_delay, secondshort_delay, long_delay, secondlong_delay: 
Ranges of delays (in milliseconds) corresponding to 00, 01, 10, and 11 bit pairs.
### 3. burst_min, burst_max: 
Minimum and maximum burst sizes for packet transmission. A random burst size is chosen between these values for each burst.

## Receiver Parameters:
### 1. short_delay, secondshort_delay, long_delay, secondlong_delay: 
Delay ranges for decoding 00, 01, 10, and 11.
### 2. log_file_name: 
File name to log the reconstructed message.

## Covert Channel Capacity:
Wİth the below parameters the sending of the 128 bit took approximately 13 seconds, resulting in a channel capacity of 9.84 bits/second is obtained.

### Maximized Channel Capacity Parameters For the Sender:
1) "short_delay": [50, 51]
2) "secondshort_delay": [110, 111]
3) "long_delay": [180, 181]
4) "secondlong_delay": [240, 241]

### Maximized Channel Capacity Parameters For the Receiver:
1) "short_delay": [50, 110]
2) "secondshort_delay": [110, 170]
3) "long_delay": [180, 240]
4) "secondlong_delay": [240, 350]

## Parameter Limitations and Recommended Parameters:
To ensure accuracy:
1) Idle Time Intervals for Sending: Should not exceed 1 millisecond (e.g. it should not be [200, 202] because the interval is 2 miliseconds there).
2) Idle Time Intervals for Receiving: Should not be less than 60 milliseconds (e.g. it should not be [200, 259] because the interval is 59 miliseconds there).

We could not ensure the correct transmission if the idle time intervals for sending are greater than 1, and the receiving intervals are less than 60. We recommend the below parameters for the safe and correct transmission independent of the system features.

### Safe Parameters For the Sender:
1) "short_delay": [200, 201]
2) "secondshort_delay": [400, 401]
3) "long_delay": [600, 601]
4) "secondlong_delay": [800, 801]

### Safe Parameters For the Receiver:
1) "short_delay": [200, 400]
2) "secondshort_delay": [400, 600]
3) "long_delay": [600, 800]
4) "secondlong_delay": [800, 1000]