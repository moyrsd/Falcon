import pyshark
import pandas as pd
from keras.models import load_model
import numpy as np
from threading import Thread
import time

# Load trained model
model = load_model('model.keras')

# Configuration
TIME_WINDOW = 10  # Analysis window in seconds
THRESHOLD = 0.8   # Detection threshold
INTERFACE = 'wlo1'  # Update with your interface

# Buffer for packet features
packet_buffer = []

def process_packet(packet):
    """Extract features from PyShark packets"""
    try:
        if 'TCP' in packet:
            features = {
                'timestamp': time.time(),
                'packet_len': int(packet.length),
                'ip_proto': int(packet.ip.proto),
                'tcp_src_port': int(packet.tcp.srcport),
                'tcp_dst_port': int(packet.tcp.dstport),
                'syn_flag': int('SYN' in packet.tcp.flags),
                'ack_flag': int('ACK' in packet.tcp.flags),
                'fin_flag': int('FIN' in packet.tcp.flags),
                'psh_flag': int('PSH' in packet.tcp.flags),
                'rst_flag': int('RST' in packet.tcp.flags),
                'tcp_hdr_len': int(packet.tcp.hdr_len),
                'tcp_seq': int(packet.tcp.seq),
                'tcp_ack': int(packet.tcp.ack),
                'tcp_window': int(packet.tcp.window_size),
                'tcp_payload_len': int(packet.tcp.payload_length) if hasattr(packet.tcp, 'payload_length') else 0
            }
            packet_buffer.append(features)
    except AttributeError:
        pass

def analyze_traffic():
    """Process buffered packets periodically"""
    while True:
        time.sleep(TIME_WINDOW)
        if packet_buffer:
            import pandas as pd

    # Create the DataFrame
    df = pd.DataFrame(packet_buffer, columns=['timestamp', 'packet_len', 'ip_proto', 'tcp_src_port', 'tcp_dst_port',
                                            'syn_flag', 'ack_flag', 'fin_flag', 'psh_flag', 'rst_flag', 
                                            'tcp_hdr_len', 'tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_payload_len', 
                                            'label'])

    # Define data types
    dataTypes = {'timestamp': 'float32', 'packet_len': 'int16', 'ip_proto': 'int8', 
                'tcp_src_port': 'int32', 'tcp_dst_port': 'int32', 'syn_flag': 'int8', 
                'ack_flag': 'int8', 'fin_flag': 'int8', 'psh_flag': 'int8', 
                'rst_flag': 'int8', 'tcp_hdr_len': 'int8', 'tcp_seq': 'int32', 
                'tcp_ack': 'int32', 'tcp_window': 'int32', 'tcp_payload_len': 'int16', 
                'label': 'bool'}

    # Fill NaN values
    df.fillna(0, inplace=True)

    # Cast columns to specified data types
    df = df.astype(dataTypes)

                
    # Make predictions
    predictions = model.predict(df)
    
    # Check for attacks
    if np.mean(predictions) > THRESHOLD:
        print("\n[!] Slowloris DDoS attack detected!")
        
    # Clear buffer
    packet_buffer.clear()

def start_capture():
    """Start live packet capture with PyShark"""
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        use_json=True,
        include_raw=True,
        output_file=None
    )
    
    print(f"Starting capture on {INTERFACE}...")
    for packet in capture.sniff_continuously():
        process_packet(packet)

if __name__ == "__main__":
    # Start analysis thread
    Thread(target=analyze_traffic, daemon=True).start()
    
    # Start PyShark capture
    start_capture()
