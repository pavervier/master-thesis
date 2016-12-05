/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * TCP states enumeration.
 * 
 */

package be.ulg.vervier.SmtpDump.TCPSessionManagement;

public enum TCPState {
    NONE (0),
    CLOSED (1),
    LISTEN (2),
    SYN_RCVD (3),
    SYN_SENT (4),
    ESTABLISHED (5),
    FIN_WAIT_1 (6),
    FIN_WAIT_2 (7),
    CLOSING (8),
    TIME_WAIT (9),
    CLOSE_WAIT (10),
    LAST_ACK (11);
    
    /** A unique state index */
    private final int index;
    
    /** Default private constructor. */
    private TCPState(int index) {
        this.index = index;
    }
    
    /** Return the state index. */
    private int index() {
        return index;
    }
    
}
