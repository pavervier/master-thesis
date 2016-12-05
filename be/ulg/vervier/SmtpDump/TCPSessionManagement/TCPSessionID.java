/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class represents an identifier for a TCP session. A TCP session is
 * identified by the source and destination IP addresses and by the source and
 * destination port numbers.
 * 
 */

package be.ulg.vervier.SmtpDump.TCPSessionManagement;

import java.net.InetAddress;
import jpcap.JpcapCaptor;
import jpcap.packet.*;

public class TCPSessionID {
    
    /** INSTANCE VARIABLES */
    
    /** Source IP */
    private InetAddress src_ip;
    /** Destination IP */
    private InetAddress dst_ip;
    /** Source port */
    private int src_port;
    /** Destination port */
    private int dst_port;
    
    /** CONSTRUCTORS */
    
    /** Default constructor */
    TCPSessionID() { this(null, null, 0, 0); }
    /** Create a new TCP session identifier with the given IPs and ports. */
    TCPSessionID(InetAddress src_ip,
                 InetAddress dst_ip,
                 int src_port,
                 int dst_port) {
        this.src_ip = src_ip;
        this.dst_ip = dst_ip;
        this.src_port = src_port;
        this.dst_port = dst_port;
    }
    
    /** METHODS */
    
    /** Retrieve the source IP. */
    InetAddress getSourceIP() { return src_ip; }
    
    /** Retrieve the destination IP. */
    InetAddress getDestinationIP() { return dst_ip; }
    
    /** Retrieve the source port number. */
    int getSourcePort() { return src_port; }
    
    /** Retrieve the destination port number. */
    int getDestinationPort() { return dst_port; }
    
    /** Set the source IP. */
    void setSourceIP(InetAddress ip) { src_ip = ip; }
    
    /** Set the destination IP. */
    void setDestinationIP(InetAddress ip) { dst_ip = ip; }
    
    /** Set the source port number. */
    void setSourcePort(int port) { src_port = port; }
    
    /** Set the destination port number. */
    void setDestinationPort(int port) { dst_port = port; }
    
    /** Compute hashcode for a TCP session identifier. */
    public int hashCode() {
        return src_ip.hashCode() + dst_ip.hashCode() + src_port + dst_port;
    }
    
    /** Return true if the given object is equal to the currrent TCP session
     * identifier. Two identifiers are equal if the source and destination
     * IP and the source and destination port numbers are equal. */
    public boolean equals(Object o) {
        TCPSessionID tcp_id;
        try {
            tcp_id = (TCPSessionID)o;
        } catch (ClassCastException cce) {
            return false;
        }
        return ((src_ip.equals(tcp_id.src_ip) && dst_ip.equals(tcp_id.dst_ip))||
               (src_ip.equals(tcp_id.dst_ip) && dst_ip.equals(tcp_id.src_ip)))&&
               ((src_port == tcp_id.src_port && dst_port == tcp_id.dst_port) ||
               (src_port == tcp_id.dst_port && dst_port == tcp_id.src_port));
    }
    
}
