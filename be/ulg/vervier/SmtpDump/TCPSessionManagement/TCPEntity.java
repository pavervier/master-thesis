/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * A TCP entity is a generic way of representing the source or destination
 * TCP.
 * 
 */

package be.ulg.vervier.SmtpDump.TCPSessionManagement;

import java.net.InetAddress;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import jpcap.packet.TCPPacket;

class TCPEntity {
    
    /** INSTANCE VARIABLES */
    
    /** The entity IP */
    InetAddress ip;
    /** The entity port number */
    int port;
    /** True if the entity has sent a SYN segment, false otherwise */
    boolean has_syn;
    /** True if the entity has acknowledged the other entity SYN segment,
     * false otherwise */
    boolean has_ack_syn;
    /** True if the entity has sent a FIN segment, false otherwise */
    boolean has_fin;
    /** True if the entity has acknowledged the other entity FIN segment,
     * false otherwise */
    boolean has_ack_fin;
    /** True if the entity has sent a RST segment, false otherwise */
    boolean has_rst;
    /** The entity TCP SYN sequence number */
    long syn_seq;
    /** The entity TCP FIN sequence number */
    long fin_seq;
    /** The entity last TCP sequence number sent */
    long last_byte_sent;
    /** The entity last TCP sequence number acked */
    long last_byte_acked;
    /** The length of the data of the last TCP packet sent */
    int last_sent_packet_data_len;
    /** The entity TCP receive window size */
    int window;
    /** The start sequence number */
    long start_seq;
    /** The number of packets sent by this entity. */
    int packet_count;
    /** The list of TCP options */
    HashSet<String> options;
    /** A data structure mapping TCP options kind field and their name */
    private static HashMap<Byte, String> opt_def;
    /** The packet reassembling buffer */
    List<TCPPacket> p_buffer;
    
    static {
        opt_def = new HashMap<Byte, String>();
        opt_def.put((byte)0x02, "Maximum Segment Size");
        opt_def.put((byte)0x03, "Window Scale");
        opt_def.put((byte)0x04, "SACK Permitted");
        opt_def.put((byte)0x05, "SACK");
        opt_def.put((byte)0x06, "Echo");
        opt_def.put((byte)0x07, "Echo reply");
        opt_def.put((byte)0x08, "Time Stamp Option");
        opt_def.put((byte)0x09, "Partial Order Connection Permitted");
        opt_def.put((byte)0x0A, "Partial Order Service Profile");
        opt_def.put((byte)0x0B, "CC");
        opt_def.put((byte)0x0C, "CC.NEW");
        opt_def.put((byte)0x0D, "CC.ECHO");
        opt_def.put((byte)0x0E, "TCP Alternate Checksum Request");
        opt_def.put((byte)0x0F, "TCP Alternate Checksum Data");
        opt_def.put((byte)0x10, "Skeeter");
        opt_def.put((byte)0x11, "Bubba");
        opt_def.put((byte)0x12, "Trailer Checksum Option");
        opt_def.put((byte)0x13, "MD5 Signature Option");
        opt_def.put((byte)0x14, "SCPS Capabilities");
        opt_def.put((byte)0x15, "Selective Negative Acknowledgements");
        opt_def.put((byte)0x16, "Record Boundaries");
        opt_def.put((byte)0x17, "Corruption Experienced");
        opt_def.put((byte)0x18, "SNAP");
        opt_def.put((byte)0x1A, "TCP Compression Filter");
        opt_def.put((byte)0x1B, "Quick-Start Response");
        opt_def.put((byte)0x1C, "User Timeout Option");
        opt_def.put((byte)0x1D, "TCP Authentication Option");
        opt_def.put((byte)0xFD, "RFC3692-style Experiment 1");
        opt_def.put((byte)0xFE, "RFC3692-style Experiment 2");
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    TCPEntity(InetAddress ip, int port) {
        this.ip = ip;
        this.port = port;
        has_syn = false;
        has_ack_syn = false;
        has_fin = false;
        has_ack_fin = false;
        has_rst = false;
        syn_seq = 0;
        fin_seq = 0;
        last_byte_sent = 0;
        last_byte_acked = 0;
        last_sent_packet_data_len = 0;
        window = 0;
        start_seq = 0;
        packet_count = 0;
        options = new HashSet<String>();
        p_buffer = new ArrayList<TCPPacket>();
    }
    
    /** METHODS */
    
    /** Return true if the entity has sent a SYN segment, false otherwise */
    boolean hasSyn() { return has_syn; }
    
    /** Set true if the entity has sent a SYN segment, false otherwise */
    void hasSyn(boolean has_syn) { this.has_syn = has_syn; }
    
    /** Return true if the entity has acknowledged the other entity SYN segment,
     * false otherwise */
    boolean hasAckSyn() { return has_ack_syn; }
    
    /** Set true if the entity has acknowledged the other entity SYN segment,
     * false otherwise */
    void hasAckSyn(boolean has_ack_syn) { this.has_ack_syn = has_ack_syn; }
    
    /** Return true if the entity has sent a FIN segment, false otherwise */
    boolean hasFin() { return has_fin; }
    
    /** Set true if the entity has sent a FIN segment, false otherwise */
    void hasFin(boolean has_fin) { this.has_fin = has_fin; }
    
    /** Return true if the entity has acknowledged the other entity FIN segment,
     * false otherwise */
    boolean hasAckFin() { return has_ack_fin; }
    
    /** Set true if the entity has acknowledged the other entity FIN segment,
     * false otherwise */
    void hasAckFin(boolean has_ack_fin) { this.has_ack_fin = has_ack_fin; }
    
    /** Return true if the entity has sent a RST segment, false otherwise */
    boolean hasRst() { return has_rst; }
    
    /** Set true if the entity has sent a RST segment, false otherwise */
    void hasRst(boolean has_rst) { this.has_rst = has_rst; }
    
    /** Retrieve the entity TCP SYN sequence number */
    long synSeq() { return syn_seq; }
    
    /** Set the entity TCP SYN sequence number */
    void synSeq(long syn_seq) { this.syn_seq = syn_seq; }
    
    /** Retrieve the entity TCP FIN sequence number */
    long finSeq() { return fin_seq; }
    
    /** Set the entity TCP FIN sequence number */
    void finSeq(long fin_seq) { this.fin_seq = fin_seq; }
    
    /** Retrieve the entity last TCP sequence number sent */
    long lastByteSent() { return last_byte_sent; }
    
    /** Set the entity last TCP sequence number sent */
    void lastByteSent(long last_byte_sent) {
        this.last_byte_sent = last_byte_sent;
    }
    
    /** Retrieve the entity last TCP sequence number acked */
    long lastByteAcked() { return last_byte_acked; }
    
    /** Set the entity last TCP sequence number acked */
    void lastByteAcked(long last_byte_acked) {
        this.last_byte_acked = last_byte_acked;
    }
    
    /** Retrieve the length of the data of the last packet send by the entity */
    int lastSentPacketDataLen() { return last_sent_packet_data_len; }
    
    /** Set the length of the data of the last packet send by the entity */
    void lastSentPacketDataLen(int last_sent_packet_data_len) {
        this.last_sent_packet_data_len = last_sent_packet_data_len;
    }
    
    /** Retrieve the entity TCP receive window size */
    int window() { return window; }
    
    /** Set the entity TCP receive window size */
    void window(int window) { this.window = window; }
    
    /** Retrieve the start sequence number */
    long startSeq() { return start_seq; }
    
    /** Set the start sequence number */
    void startSeq(long start_seq) { this.start_seq = start_seq; }
    
    /** Retrieve the number of packets sent by this entity. */
    int packetCount() { return packet_count; }
    
    /** Set the number of packets sent by this entity. */
    void packetCount(int packet_count) { this.packet_count = packet_count; }
    
    /** Retrieve the packet buffer of this entity. */
    List<TCPPacket> getPacketBuffer() { return p_buffer; }
    
    /** Retrieve the list of TCP options */
    Collection<String> options() { return options; }
    
    /** Extract the TCP options from the given TCP option field. */
    void extractTCPOptions(byte[] opt) {
        if (opt == null) return;
        for (int i = 0; i < opt.length; i++) {
            if (opt_def.containsKey(opt[i]) && i < opt.length - 1) {
                options.add(opt_def.get(opt[i]));
                // the 1 octet length-field follows the 1 octet kind-field
                i = (i + opt[i + 1] - 1 >= i) ? i + opt[i + 1] - 1 : i;
            }
        }
    }
    
    /** Return a String representation of the TCPEntity. */
    public String toString() {
        return ip.toString() + ":" + port;
    }
    
}
