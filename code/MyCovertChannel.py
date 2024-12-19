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
        # Ensure log_file_name is a valid string path
        if not isinstance(log_file_name, str):
            raise ValueError("log_file_name must be a valid string path.")

        # Generate and log the random binary message
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        print(f"Generated Binary Message: {binary_message}")

        i = 0
        for j in range(0, len(binary_message), 2):
            # Get the 2-bit value
            bit_pair = binary_message[j:j+2]
            
            # Random burst size
            burst_size = random.randint(burst_min, burst_max)

            # Send the start marker packet
            start_marker_packet = IP(dst="127.0.0.1") / UDP(dport=123) / Raw(b"START")
            super().send(start_marker_packet)

            # Send a burst of NTP packets
            for _ in range(burst_size):
                ntp_packet = IP(dst="127.0.0.1") / UDP(dport=123)  # Simulated NTP packet
                super().send(ntp_packet)  # Send the packet using the method from CovertChannelBase
            
            # Send the end marker packet
            end_marker_packet = IP(dst="127.0.0.1") / UDP(dport=123) / Raw(b"END")  # Payload size = 128 bytes
            super().send(end_marker_packet)

            # Delay based on the 2-bit value
            if bit_pair == '00':
                # Short idle time for '00'
                self.sleep_random_time_ms(short_delay[0], short_delay[1])
            elif bit_pair == '01':
                # Medium idle time for '01' (if you want to distinguish it from '00')
                self.sleep_random_time_ms(secondshort_delay[0], secondshort_delay[1])
            elif bit_pair == '10':
                # Longer idle time for '10'
                self.sleep_random_time_ms(long_delay[0], long_delay[1])
            elif bit_pair == '11':
                # Longest idle time for '11' (if you want to distinguish it)
                self.sleep_random_time_ms(secondlong_delay[0], secondlong_delay[1])

            #print(i, bit_pair)  # Print the index and the 2-bit pair
            i += 1
        
        burst_size = random.randint(burst_min, burst_max)
        
        start_marker_packet = IP(dst="127.0.0.1") / UDP(dport=123) / Raw(b"START")
        super().send(start_marker_packet)
        # Send a burst of NTP packets
        for _ in range(burst_size):
            ntp_packet = IP(dst="127.0.0.1") / UDP(dport=123)  # Simulated NTP packet
            super().send(ntp_packet)  # Send the packet using the method from CovertChannelBase

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
        total = 0.0
        state = True

        def packet_callback(packet):
            if Raw in packet:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
            else:
                payload = None
            
            nonlocal previous_time, captured_binary
            nonlocal maxIdleLong, maxIdleShort, maxIdleSecondShort, maxIdleLongest, state

            if payload == "START" and state == True:
                # Capture packet timestamp
                current_time = time.time()

                # Measure idle time
                if previous_time is not None:
                    idle_time = (current_time - previous_time) * 1000  # Convert to milliseconds
                    #print(f"Idle time: {idle_time}ms")  # Print idle time to debug

                    # Now handle the idle time for 2-bit values:
                    if short_delay[0] <= idle_time <= short_delay[1]:
                        captured_binary += '00'  # Capture '00' for short idle time
                        #print(f"Idle time: {idle_time}ms", '00')
                        if maxIdleShort < idle_time:
                            maxIdleShort = idle_time
                        #print("maxIdleShort", maxIdleShort)
                    elif secondshort_delay[0] <= idle_time < secondshort_delay[1]:
                        captured_binary += '01'  # Capture '01' for medium idle time
                        #print(f"Idle time: {idle_time}ms", '01')
                        if maxIdleSecondShort < idle_time:
                            maxIdleSecondShort = idle_time
                        #print("maxIdlesecondshort", maxIdleSecondShort)
                    elif long_delay[0] <= idle_time <= long_delay[1]:
                        captured_binary += '10'  # Capture '10' for longer idle time
                        #print(f"Idle time: {idle_time}ms", '10')
                        if maxIdleLong < idle_time:
                            maxIdleLong = idle_time
                        #print("maxIdleLong", maxIdleLong)
                    elif secondlong_delay[0] <= idle_time <= secondlong_delay[1]:
                        # This case can be adjusted based on your specific delay ranges
                        captured_binary += '11'  # Capture '11' for very long idle time
                        #print(f"Idle time: {idle_time}ms", '11')
                        if maxIdleLongest < idle_time:
                            maxIdleLongest = idle_time
                        #print("maxIdleLongest", maxIdleLongest)

                state = False
            
            elif payload == "END" and state == False:
                # Capture packet timestamp
                current_time = time.time()

                # Update previous_time
                previous_time = current_time

                state = True

        print("Listening for incoming NTP packets...")
        sniff(filter="udp port 123", prn=packet_callback, iface="lo", timeout=60) # Sniff NTP packets for 30 seconds

        # Stop when '.' is detected in the binary stream
        decoded_message = ""
        for i in range(0, len(captured_binary), 8):  # Process in chunks of 8 bits
            char = self.convert_eight_bits_to_character(captured_binary[i:i+8])
            if char == ".":
                decoded_message += char
                break
            decoded_message += char

        # Log the decoded message
        self.log_message(decoded_message, log_file_name)
        print(f"Received Message: {decoded_message}")
        print(captured_binary)