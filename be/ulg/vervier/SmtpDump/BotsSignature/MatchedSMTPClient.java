/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a SMTP client matched by defined signatures. From now
 * on, signatures are refered to as clients, so when a SMTP session matches
 * a signature, it matches a (SMTP) client.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

import java.util.Collection;
import java.util.LinkedList;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;

public class MatchedSMTPClient {

    /** INSTANCE VARIABLES */
    
    /** The matched SMTP client/signature */
    private Signature client;
    /** The matching SMTP sessions */
    private Collection<SMTPSession> m_sessions;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public MatchedSMTPClient() {
        this(null);
    }
    
    /** Create a new matching SMTP session with the given matching session and
     * the given matched client/signature. */
    public MatchedSMTPClient(Signature client) {
        this.client = client;
        this.m_sessions = new LinkedList<SMTPSession>();
    }
    
    /** METHODS */
    
    /** Retrieve the matched SMTP client/signature. */
    public Signature matchedClient() { return client; }

    /** Add a matching SMTP session to the collection of sessions matching this
     * SMTP client. */
    public void addMatchingSession(SMTPSession session) {
        m_sessions.add(session);
    }

    /** Retrieve the matching SMTP sessions. */
    public Collection<SMTPSession> matchingSessions() { return m_sessions; }
    
    /** Return true if the client/signature is not matched by any SMTP session,
     * false otherwise. */
    public boolean isEmpty() { return m_sessions.isEmpty(); }

}
