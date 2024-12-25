from CovertChannelBase import CovertChannelBase
from scapy.all import sniff, IP, UDP, Raw
import time
import random

class MyCovertChannel(CovertChannelBase):
    """
    Covert timing channel implementation exploiting Idle Period Between Packet Bursts using NTP.
    """
    def __init__(self):
        super().__init__()

    def send(self, log_file_name, short_delay, secondshort_delay, long_delay, secondlong_delay, burst_min, burst_max):
        beginning = time.time()

        if not isinstance(log_file_name, str):
            raise ValueError("log_file_name must be a valid string path.")

        # Generating the random binary message
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Generated Binary Message: {binary_message}")

        i = 0
        for j in range(0, len(binary_message), 2):
            # The 2-bit value
            bit_pair = binary_message[j:j+2]
            
            burst_size = random.randint(burst_min, burst_max)
            
            for _ in range(burst_size):
                ntp_packet = IP(dst="172.18.0.3") / UDP(dport=123)  # Simulated NTP packet
                super().send(ntp_packet)  
                
            # Delay based on the 2-bit value
            if bit_pair == '00':
                
                self.sleep_random_time_ms(short_delay[0], short_delay[1])
            elif bit_pair == '01':
                
                self.sleep_random_time_ms(secondshort_delay[0], secondshort_delay[1])
            elif bit_pair == '10':
                
                self.sleep_random_time_ms(long_delay[0], long_delay[1])
            elif bit_pair == '11':
               
                self.sleep_random_time_ms(secondlong_delay[0], secondlong_delay[1])

            i += 1
        
        burst_size = random.randint(burst_min, burst_max)
        
        # Sending a burst of NTP packets
        for _ in range(burst_size):
            ntp_packet = IP(dst="172.18.0.3") / UDP(dport=123)  # Simulated NTP packet
            super().send(ntp_packet) 

        ending = time.time()

        print("time:", ending-beginning)
        print("Message transmission completed.")



    def receive(self, short_delay, secondshort_delay, long_delay, secondlong_delay, log_file_name):

        captured_binary = ""
        previous_time = None

        maxIdleShort = 0.0
        maxIdleSecondShort = 0.0
        maxIdleLong = 0.0
        maxIdleLongest = 0.0
        state = True
        should_stop_sniffing = False

        def stop_sniff(packet):
            return should_stop_sniffing  

        def packet_callback(packet):
            nonlocal previous_time, captured_binary
            nonlocal maxIdleLong, maxIdleShort, maxIdleSecondShort, maxIdleLongest, state, should_stop_sniffing

            # Capturing packet timestamp
            current_time = time.time()

            # Measuring idle time
            if previous_time is not None:
                idle_time = (current_time - previous_time) * 1000  # Converting to milliseconds

                # Handling the idle time for 2-bit values:
                if short_delay[0] <= idle_time <= short_delay[1]:
                    captured_binary += '00' 
                  
                elif secondshort_delay[0] <= idle_time < secondshort_delay[1]:
                    captured_binary += '01'  

                elif long_delay[0] <= idle_time <= long_delay[1]:
                    captured_binary += '10' 
                  
                elif secondlong_delay[0] <= idle_time <= secondlong_delay[1]:
                    
                    captured_binary += '11'  


            if len(captured_binary) % 8 == 0 and len(captured_binary) != 0:
                out = [(captured_binary[i:i+8]) for i in range(0, len(captured_binary), 8)]
                
                if out.pop() == self.convert_string_message_to_binary("."):
                    should_stop_sniffing = True
            
            previous_time = current_time

        print("Listening for incoming NTP packets...")
        sniff(filter="udp port 123", prn=packet_callback, stop_filter=stop_sniff, iface="eth0", timeout=1500) # Sniffing NTP packets

        # Stops when '.' is detected in the binary stream
        decoded_message = ""
        for i in range(0, len(captured_binary), 8):  # Processing in chunks of 8 bits
            char = self.convert_eight_bits_to_character(captured_binary[i:i+8])
            if char == ".":
                decoded_message += char
                break
            decoded_message += char

        # Log the decoded message
        self.log_message(decoded_message, log_file_name)
        print(f"Received Message: {decoded_message}")
        print(captured_binary)
