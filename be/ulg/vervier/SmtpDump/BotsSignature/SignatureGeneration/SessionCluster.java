/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a session cluster. A SMTP session cluster simply
 * hold multiple SMTP session samples sharing specific features. In order to
 * decide which cluster hold a session, a SessionFingerPrint is extracted for
 * each session sample. This fingerprint takes into consideration different
 * features of the TCP/SMTP/IMF protocol to differentiate sessions comming from
 * different client implementations.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.util.List;
import java.util.LinkedList;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;

public class SessionCluster {
    
    /** INSTANCE VARIABLES */
    
    /** The list of SMTP sessions */
    private List<SMTPSession> sessions;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    SessionCluster() {
        sessions = new LinkedList<SMTPSession>();
    }
    
    /** METHODS */
    
    /** Add a new SMTP session to the session cluster. */
    void addSession(SMTPSession session) {
        if (session != null)
            sessions.add(session);
    }
    
    /** Retrieve the SMTP sessions stored in the cluster. */
    List<SMTPSession> getSessions() { return sessions; }
    
    /** Retrieve the number of SMTP session samples stored in the cluster. */
    int getSessionCount() { return sessions.size(); }
    
    /** Return the String representation of the session cluster, i.e.
     * the collection of SMTP session. */
    public String toString() { return sessions.toString(); }
    
}
