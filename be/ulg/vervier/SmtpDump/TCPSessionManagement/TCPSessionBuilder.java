/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class aims at rebuilding TCP sessions from provided TCP packets.
 * A TCP session is uniquely defined as a quadruple <src_ip, src_port, dst_ip,
 * dst_port>.
 * 
 */

package be.ulg.vervier.SmtpDump.TCPSessionManagement;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.FileHandler;
import java.net.InetAddress;
import jpcap.packet.*;
import be.ulg.vervier.SmtpDump.NetworkDataCapture.*;

public class TCPSessionBuilder implements Runnable {
    
    /** INSTANCE VARIALES */
    
    /** The packet captor */
    private PacketCaptor captor;
    /** Map storing currently open TCP sessions */
    private HashMap<TCPSessionID, TCPSession> w_sessions;
    /** Map storing opening TCP sessions, i.e. 3-way handshake not complete */
    private HashMap<TCPSessionID, TCPSession> in_buff_sessions;
    /** Queue storing opening TCP sessions, i.e. 3-way handshake not complete */
    private LinkedList<TCPSessionID> in_queue_sessions;
    /** The collection of rebuilt TCP sessions */
    private ArrayBlockingQueue<TCPSession> q_sessions;
    /** Data structure mapping TCP sessions source IP and the number of sessions
     * issued by each IP */
    private HashMap<InetAddress, Integer> src_ips;
    /** The maximum number of opening TCP sessions,
     * i.e. 3-way handshake not complete */
    private static final int MAX_SYN_SESSIONS = 300;
    /** The number of TCP packets added to a TCP session */
    private int tcp_packet_count;
    /** The number of rebuilt TCP sessions */
    private int tcp_session_count;
    /** Temporary TCP session */
    private TCPSession t_session;
    /** Temporary TCP session identifier */
    private TCPSessionID t_session_id;
    /** The mean duration of a TCP session (in msec) */
    private double mean_duration;
    /** The mean deviation of the duration of a TCP session (in msec) */
    private double dev_duration;
    /** The EWMA factor */
    private static final double ALPHA = 0.5;
    /** The EWMA factor */
    private static final double BETA = 0.25;
    /** The deviation multiplier */
    private static final float DEV_MUL = 20;
    /** The maximum duration of a TCP session (in msec) */
    private double max_duration;
    /** The minimum value of the duration of a TCP session (in msec), i.e. no
     * TCP session can be aborted unless it has a duration greater than
     * this value */
    private static final double MIN_DURATION = 600000;  // 10 sec
    /** The number of discarded TCP packets */
    private int discarded_pkt_count;
    /** The number of discarded TCP SYN packets */
    private int discarded_syn_count;
    /** The number of discarded TCP FIN packets */
    private int discarded_fin_count;
    /** The number of discarded TCP RST packets */
    private int discarded_rst_count;
    /** The number of discarded TCP retransmitted packets */
    private int discarded_retrans_count;
    /** The number of discarded TCP packets other than SYN, FIN and RST */
    private int discarded_other_count;
    /** Logger: log SMTPDUMP program error */
    private static final Logger LOGGER =
        Logger.getLogger(be.ulg.vervier.SmtpDump.SmtpDumpMain.class.getName());
    /** Logger: log rebuilt TCP sessions information */
    private static final Logger LOGGER_SESSION =
        Logger.getLogger(TCPSessionBuilder.class.getName() + "_session");
    /** Logger: log junk (discarded) TCP packets information */
    private static final Logger LOGGER_JUNK =
        Logger.getLogger(TCPSessionBuilder.class.getName() + "_junk");
    /** The logging level: determine what information should be logged */
    private static final Level LOGGING_LEVEL = Level.FINE;
    
    /** Static block: loggers initialization */
    static {
        try {
            // log TCP sessions
            FileHandler fh = new FileHandler("log_tcp_session.txt");
            fh.setLevel(LOGGING_LEVEL);
            fh.setFormatter
                (new be.ulg.vervier.SmtpDump.Utils.SimpleLogFormatter());
            LOGGER_SESSION.addHandler(fh);
            // log discarded TCP packets
            // i.e. packets not associated with any TCP session
            fh = new FileHandler("log_tcp_junk.txt");
            fh.setLevel(LOGGING_LEVEL);
            fh.setFormatter
                (new be.ulg.vervier.SmtpDump.Utils.SimpleLogFormatter());
            LOGGER_JUNK.addHandler(fh);
        } catch (java.io.IOException ioe) {}
        // FINE level is appropriate for diagnostic
        LOGGER_SESSION.setLevel(LOGGING_LEVEL);
        LOGGER_JUNK.setLevel(LOGGING_LEVEL);
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor */
    public TCPSessionBuilder() { this(null, null); }
    
    /** Create a new TCP session builder with the given TCP sessions
     * container. */
    public TCPSessionBuilder(ArrayBlockingQueue<TCPSession> q_sessions) {
        this(q_sessions, null);
    }
    
    /** Create a new TCP session builder with the given TCP sessions container
     * and network data identifier. */
    public TCPSessionBuilder(ArrayBlockingQueue<TCPSession> q_sessions,
                             String network_resource_id) {
        this.q_sessions = q_sessions;
        setResourceIdentifier(network_resource_id);
        w_sessions = new HashMap<TCPSessionID, TCPSession>(1000);
        in_buff_sessions = new HashMap<TCPSessionID, TCPSession>(MAX_SYN_SESSIONS);
        in_queue_sessions = new LinkedList<TCPSessionID>();
        src_ips = new HashMap<InetAddress, Integer>(500);
        tcp_packet_count = 0;
        tcp_session_count = 0;
        mean_duration = 0;
        dev_duration = 0;
        max_duration = 18000000; // initial max duration set to 18000 sec = 5 h
        discarded_pkt_count = 0;
        discarded_syn_count = 0;
        discarded_fin_count = 0;
        discarded_rst_count = 0;
        discarded_retrans_count = 0;
        discarded_other_count = 0;
        if (LOGGER_SESSION == null || LOGGER_JUNK == null)
            LOGGER.warning("Error initializing TCP session builder loggers");        
    }
    
    /** METHODS */
    
    /** The TCP session builder tasks. */
    public void run() {
        try {
            buildSessions();
        } catch (TCPSessionBuilderException tsbe) {
            LOGGER.severe(tsbe.getMessage() + "\n");
            System.exit(1);
        }
        
        try {
            for (TCPSession s: w_sessions.values()) {
                LOGGER_SESSION.fine(new StringBuilder(100).
                                        append(s.toString()).
                                        append("\n").toString());
                q_sessions.put(s);
                tcp_session_count++;
            }
            q_sessions.put(new TCPSession());
        } catch (InterruptedException ie) {
            LOGGER.severe("tcp-session-builder interrupted\n");
            System.exit(1);
        }
        //logReport();
    }
    
    /** Build TCP sessions from the given network packets source. */
    public void buildSessions() throws TCPSessionBuilderException {
        if (captor == null)
            throw new TCPSessionBuilderException
            ("tcp-session-builder:no valid resource locator provided");
        try {
            captor.open();
        } catch (PacketCaptorException pce) {
            throw new TCPSessionBuilderException(pce.getMessage());
        }
        jpcap.packet.Packet packet;
        while (true) {
            try {
                if ((packet = captor.read()) == null)
                    break;
                addPacket(packet);
            } catch (PacketCaptorException pce) {
                throw new TCPSessionBuilderException(pce.getMessage());
            }
        }
        captor.close();
    }
    
    /** Retrieve the build TCP sessions. */
    public Collection<TCPSession> getSessions() {
        return w_sessions.values();
    }
    
    /** Set the resource identifier for network packets capturing (e.g. file
     * name, interface). */
    public void setResourceIdentifier(String resource_id) {
        newCaptor(resource_id);
        if (captor != null)
            captor.setResourceIdentifier(resource_id.substring(2));
    }
    
    /** Retrieve the resource identifier for network packets capturing. */
    public String getResourceIdentifier() {
        return (captor != null) ? captor.getResourceIdentifier() : null;
    }
    
    /** Retrieve the number of TCP packets added to a TCP session. */
    public int getTCPPacketCount() {
        return tcp_packet_count;
    }
    
    /** Retrieve the number of TCP session rebuilt. */
    public int getTCPSessionCount() {
        return tcp_session_count;
    }
    
    /** Retrieve the number of discarded TCP packets. */
    public int discardedPacketCount() {
        return discarded_pkt_count;
    }
    
    /** Retrieve the number of discarded TCP SYN packets. */
    public int discardedSynCount() {
        return discarded_syn_count;
    }
    
    /** Retrieve the number of discarded TCP FIN packets. */
    public int discardedFinCount() {
        return discarded_fin_count;
    }
    
    /** Retrieve the number of discarded TCP RST packets */
    public int discardedRstCount() {
        return discarded_rst_count;
    }
    
    /** Retrieve the number of discarded TCP retransmitted packets. */
    public int discardedRetransCount() {
        return discarded_retrans_count;
    }
    
    /** Retrieve the number of discarded TCP packets other than SYN, FIN and
     * RST. */
    public int discardedOtherCount() {
        return discarded_other_count;
    }
    
    /** Add a packet to a TCP session.*/
    private void addPacket(Packet p) throws TCPSessionBuilderException {
        TCPPacket tcp_packet = null;
        try {
            tcp_packet = (TCPPacket)p;
        } catch (ClassCastException cce) {}
        if (tcp_packet == null) return;
        t_session_id = new TCPSessionID(tcp_packet.src_ip,
                                        tcp_packet.dst_ip,
                                        tcp_packet.src_port,
                                        tcp_packet.dst_port);
        // search for the session identifier in the not yet opened sessions
        // buffer
        if ((t_session = w_sessions.get(t_session_id)) != null) {
            // add packet to session
            if (!t_session.addPacket(tcp_packet)) { // lost or duplicate packet
                LOGGER_JUNK.fine(new StringBuilder(100).
                                 append("(R)").
                                 append(tcp_packet.toString()).
                                 append("\n").toString());
                discarded_retrans_count++;
                discarded_pkt_count++;
            }
        // search for the session identifier in the already opened sessions
        // buffer
        } else if ((t_session = in_buff_sessions.get(t_session_id)) != null) {
            // add packet to session
            if (!t_session.addPacket(tcp_packet)) { // lost or duplicate packet
                LOGGER_JUNK.fine(new StringBuilder(100).
                                 append("(R)").
                                 append(tcp_packet.toString()).
                                 append("\n").toString());
                discarded_retrans_count++;
                discarded_pkt_count++;
            }
            // if the session has completed the TCP three-way handshake,
            // transfer it to the opened sessions buffer
            if (t_session.hasSyn()) {
                in_buff_sessions.remove(t_session_id);
                in_queue_sessions.remove(t_session_id);
                w_sessions.put(t_session_id, t_session);
            }
        } else {
            // create new session
            if (TCPSession.isValidFirstPacket(tcp_packet)) {
                if (in_queue_sessions.size() == MAX_SYN_SESSIONS)
                    in_buff_sessions.remove(in_queue_sessions.pollFirst());
                (t_session = new TCPSession()).addPacket(tcp_packet);
                in_buff_sessions.put(t_session_id, t_session);
                in_queue_sessions.addLast(t_session_id);
                // record source IPs and the number of sessions issued
                if (src_ips.containsKey(t_session.getSourceIP()))
                    src_ips.put(t_session.getSourceIP(), 
                                src_ips.get(t_session.getSourceIP()) + 1);
                else src_ips.put(t_session.getSourceIP(), 1);
            // invalid packet for current sessions and for a new session, drop
            } else {
                discarded_pkt_count++;
                if (tcp_packet.syn) discarded_syn_count++;
                else if (tcp_packet.fin) discarded_fin_count++;
                else if (tcp_packet.rst) discarded_rst_count++;
                else discarded_other_count++;
                LOGGER_JUNK.fine(new StringBuilder(100).
                                 append("(J)").
                                 append(tcp_packet.toString()).
                                 append("\n").toString());
            }
        }
        Iterator<TCPSession> it = w_sessions.values().iterator();
        long t_duration = -1;
        while (it.hasNext()) {
            t_session = it.next();
            t_duration =
                t_session.getDuration(tcp_packet.sec, tcp_packet.usec);
            if (!t_session.isOpen() || t_duration > max_duration) {
                try {
                    //System.out.println(t_session);
                    LOGGER_SESSION.fine(new StringBuilder(100).
                                        append(t_session.toString()).
                                        append("\n").toString());
                    q_sessions.put(t_session);
                    it.remove();
                    tcp_session_count++;
                    if (!t_session.isOpen()) {
                        // compute the mean duration using a EWMA
                        mean_duration = (1 - ALPHA) * mean_duration +
                                        ALPHA * t_session.getDuration();
                        // compute the mean deviation using a EWMA
                        dev_duration = (1 - BETA) * dev_duration +
                                       BETA * Math.abs(t_session.getDuration() -
                                                       mean_duration);
                        // compute the maximum duration of a TCP session
                        max_duration = mean_duration + DEV_MUL * dev_duration;
                        max_duration = (max_duration > MIN_DURATION) ?
                            max_duration : MIN_DURATION;
                    }
                } catch (Exception e) {
                    throw new TCPSessionBuilderException
                    ("tcp-session-builder:unable to deliver more TCP sessions ("
                    + e.getMessage() + ")");
                }
            }
        }
        tcp_packet_count++;
    }
    
    /** Create a new network data captor for capturing from the given network
     * resource identifier. The type of captor is determined with a special
     * marker added appended to the beginning of the identifier, e.g. "p:"
     * stands for pcap file and "i:" stands for network interface. */ 
    private void newCaptor(String resource_id) {
        if (resource_id == null ||
            (resource_id != null && resource_id.length() < 2)) return;
        char id_type = resource_id.charAt(0);
        switch (id_type) {
            case 'p':
                if (!(captor instanceof PCAPFileReader))
                    captor = new PCAPFileReader();
                break;
            default:
                captor = null;
                break;
        }
    }
    
    /** Print TCP session builder execution information in the log. */
    private void logReport() {
        LOGGER.info("---------------TCP SUMMARY BEGIN-----------------\n");
        LOGGER.info("TCP PACKET COUNT  = " + tcp_packet_count + "\n");
        LOGGER.info("TCP SESSION COUNT = " + tcp_session_count + "\n");
        LOGGER.info("DISCARDED PACKETS = " + discarded_pkt_count + "\n");
        LOGGER.info("              SYN = " + discarded_syn_count + "\n");
        LOGGER.info("              FIN = " + discarded_fin_count + "\n");
        LOGGER.info("              RST = " + discarded_rst_count + "\n");
        LOGGER.info("          RETRANS = " + discarded_retrans_count + "\n");
        LOGGER.info("            OTHER = " + discarded_other_count + "\n");
        LOGGER.info("       IP SOURCES = " + src_ips + "\n");
        LOGGER.info("------------------SUMMARY END--------------------\n");
    }
    
}
