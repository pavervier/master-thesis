/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class represents a TCP session. A TCP session is uniquely identified by
 * the quadruple <src_ip, src_port, dst_ip, dst_port>.
 * 
 */

package be.ulg.vervier.SmtpDump.TCPSessionManagement;

import java.util.Collection;
import java.util.LinkedList;
import java.util.GregorianCalendar;
import java.util.Date;
import java.net.InetAddress;
import jpcap.packet.TCPPacket;
import jpcap.JpcapCaptor;
import jpcap.packet.Packet;

public class TCPSession {
    
    /** INSTANCE VARIABLES */
    
    /** The list of TCP packets */
    private LinkedList<TCPPacket> packets;
    /** The source TCP entity */
    private TCPEntity src;
    /** The destination TCP entity */
    private TCPEntity dst;
    /** The last TCP packet capture time (in sec) */
    private long last_cap_sec;
    /** The last TCP packet capture time (in msec)*/
    private long last_cap_msec;
    /** The TCP session duration (in msec) */
    private long duration;
    /** True if the TCP session has been opened correctly */
    private boolean has_syn;
    /** True if the TCP session has been closed correctly */
    private boolean has_fin;
    /** True if the TCP session has been reset by one of the entities */
    private boolean has_rst;
    /** The start time of the TCP session (timestamp format) */
    private long start_time;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public TCPSession() {
        packets = new LinkedList<TCPPacket>();
        last_cap_sec = 0;
        last_cap_msec = 0;
        has_syn = false;
        has_fin = false;
        has_rst = false;
        start_time = 0;
    }
    
    /** METHODS */
    
    /** Add the given packet to the TCP session. */
    public boolean addPacket(TCPPacket packet) {
        if (packets.isEmpty()) { // for the first packet
            src = new TCPEntity(packet.src_ip, packet.src_port);
            dst = new TCPEntity(packet.dst_ip, packet.dst_port);
            last_cap_sec = packet.sec;
            last_cap_msec = packet.usec / 1000;
            start_time = (packet.sec * 1000) + (packet.usec / 1000);
        }
        TCPEntity a = null;
        TCPEntity b = null;
        if (packet.src_ip.equals(src.ip) && packet.src_port == src.port) {
            a = src;
            b = dst;
        } else {
            a = dst;
            b = src;
        }
        // process packet from <a> if and only if inside <b>'s receive window
        if (a.last_byte_acked == 0 ||
            packet.sequence - a.last_byte_acked <= b.window) {
            // TCP lost segment
            if (packet.sequence < a.last_byte_acked) return false;
            // TCP duplicate segment
            if (packet.sequence == a.last_byte_sent &&
                a.last_sent_packet_data_len > 0) return false;
            // TCP out of order segment
            if (a.last_byte_sent != 0 &&
                packet.sequence != 
                a.last_byte_sent + a.last_sent_packet_data_len) {
                int i = 0;
                while (i < b.p_buffer.size() &&
                       packet.sequence <= b.p_buffer.get(i).sequence) {
                    i++;
                }
                b.p_buffer.add(i, packet);
                return true;
            }
            if (packet.syn) { // <a> has sent a syn
                a.has_syn = true;
                a.syn_seq = packet.sequence;
                if (a.last_byte_acked == 0) {
                    a.start_seq = a.syn_seq; // save first seq num exhibited
                    a.extractTCPOptions(packet.option); // save TCP options
                }
            } else if (packet.fin) { // <a> has sent a fin
                a.has_fin = true;
                a.fin_seq = (packet.sequence > a.fin_seq) ?
                    packet.sequence : a.fin_seq;
            } else if (packet.rst) { // <a> has sent a rst
                a.has_rst = true;
            }
            if (packet.ack) { // <a> has sent an ack
                // update "last_byte_acked"
                b.last_byte_acked = (packet.ack_num > b.last_byte_acked) ?
                    packet.ack_num : b.last_byte_acked;
                // check if "ack" number matches <b>'s syn sequence number
                if (b.has_syn && !a.has_ack_syn)
                    a.has_ack_syn = packet.ack_num == b.syn_seq + 1;
                // check if "ack' number matches <b>'s fin sequence number
                else if (b.has_fin && !a.has_ack_fin)
                    a.has_ack_fin = packet.ack_num == b.fin_seq + 1;
            }
            // update TCP session state
            has_syn = src.has_ack_syn && dst.has_ack_syn;
            has_fin = src.has_ack_fin && dst.has_ack_fin;
            has_rst = src.has_rst || dst.has_rst;
            // update TCP session information
            a.last_byte_sent = (packet.syn || packet.fin || packet.rst) ?
                packet.sequence + 1 : packet.sequence;
            a.last_sent_packet_data_len = packet.data.length;
            a.window = packet.window;
            duration = getDuration(packet.sec, packet.usec);
            // add packet to session
            packets.add(packet);
            a.packet_count++;
            // if a packet is added to the session, check if it fills a hole
            // in the out of order packets buffer
            if (b.p_buffer.size() > 0 &&
                packet.sequence + packet.data.length == 
                b.p_buffer.get(0).sequence) {
                TCPPacket p = b.p_buffer.remove(0);
                addPacket(p);
            }
            return true;
        }
        return false;
    }
    
    /** Retrieve the collection of TCP packets. */
    public Collection<TCPPacket> getPackets() { return packets; }
    
    /** Retrieve the source IP of the session. */
    public InetAddress getSourceIP() { return src.ip; }
    
    /** Retrieve the destination IP of the session. */
    public InetAddress getDestinationIP() { return dst.ip; }
    
    /** Retrieve the source port number of the session. */
    public int getSourcePort() { return src.port; }
    
    /** Retrieve the destination port number of the session; */
    public int getDestinationPort() { return dst.port; }
    
    /** Return true if the connection has been established, false otherwise. */
    public boolean hasSyn() { return has_syn; }
    
    /** Return true if the connection has been terminated correctly, false
     * otherwise. */
    public boolean hasFin() { return has_fin; }
    
    /** Return true if the connection has been reset, false otherwise. */
    public boolean hasRst() { return has_rst; }
    
    /** Return true if the connection has been opened but not yet closed or
     * reset, false otherwise. */
    public boolean isOpen() { return !(has_fin || has_rst); }
    
    /** Retrieve the updated TCP session duration (in msec) */
    public long getDuration(long t_sec, long t_usec) {
        long t_duration = duration;
        long t_msec = t_usec / 1000;
        // compute TCP session duration
        if (t_sec > last_cap_sec) {
            t_duration += (t_sec - last_cap_sec) * 1000;
            last_cap_sec = t_sec;
            if (t_msec < last_cap_msec) {
                t_duration -= last_cap_msec - t_msec;
                last_cap_msec = t_msec;
            }
        }
        if (t_msec > last_cap_msec) {
            t_duration += t_msec - last_cap_msec;
            last_cap_msec = t_msec;
        }
        return t_duration;
    }
    
    /** Retrieve the TCP session duration (in msec) */
    public long getDuration() { return duration; }
    
    /** Retrieve the TCP session start time (timestamp format). */
    public long getStartTime() { return start_time; }
    
    /** Retrieve the source TCP first sequence number. */
    public long getSourceStartSeq() { return src.start_seq; }
    
    /** Retrieve the destination TCP first sequence number. */
    public long getDestinationStartSeq() { return dst.start_seq; }
    
    /** Retrieve the source TCP options. */
    public Collection<String> getSourceOptions() { return src.options; }
    
    /** Retrieve the destination TCP options. */
    public Collection<String> getDestinationOptions() { return dst.options; }
    
    /** Retrieve the number of TCP packets in the TCP session. */
    public int size() { return packets.size(); }
    
    /** Retrieve the number of TCP packets sent by the source. */
    public int getSourcePacketCount() { return src.packet_count; }
    
    /** Retrieve the number of TCP packets sent by the destination. */
    public int getDestinationPacketCount() { return dst.packet_count; }
    
    /** Return true if the session is empty, i.e. contains no TCP packets, false
     * otherwise. */
    public boolean isEmpty() { return packets.isEmpty(); }
    
    /** Return true if the packet is a valid first packet for a TCP session. */
    public static boolean isValidFirstPacket(TCPPacket p) {
        return p.syn;
    }
    
    /** Return a String representation of the TCP session. */
    public String toString() {
        StringBuilder sb = new StringBuilder(300);
        sb.append(src.ip);
        sb.append(":");
        sb.append(src.port);
        sb.append(" --> ");
        sb.append(dst.ip);
        sb.append(":");
        sb.append(dst.port);
        sb.append(" [");
        sb.append(packets.size());
        sb.append(" packets, ");
        sb.append(duration);
        sb.append(" msec");
        sb.append((has_syn ? ", syn" : ""));
        sb.append((has_fin ? ", fin" : ""));
        sb.append((has_rst ? ", rst" : ""));
        sb.append("], src opt = ");
        sb.append(src.options);
        sb.append(", dst opt = ");
        sb.append(dst.options);
        return sb.toString();
    }
    
}
