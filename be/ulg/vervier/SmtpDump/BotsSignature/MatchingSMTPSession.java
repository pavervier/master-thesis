/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a SMTP session matching defined signatures. From now
 * on, signatures are refered to as clients, so when a SMTP session matches
 * a signature, it matches a (SMTP) client.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

import java.util.Collection;
import java.util.LinkedList;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;

public class MatchingSMTPSession {

    /** INSTANCE VARIABLES */
    
    /** The matching SMTP session */
    private SMTPSession session;
    /** The matched signature */
    private Collection<Signature> m_clients;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public MatchingSMTPSession() {
        this(null);
    }
    
    /** Create a new matching SMTP session with the given matching session and
     * the given matched SMTP client. */
    public MatchingSMTPSession(SMTPSession session) {
        this.session = session;
        this.m_clients = new LinkedList<Signature>();
    }
    
    /** METHODS */
    
    /** Retrieve the matching SMTP session. */
    public SMTPSession matchingSession() { return session; }

    /** Add a matched client to the collection of clients this SMTP session
     * matched. */
    public void addMatchedClient(Signature client) {
        m_clients.add(client);
    }

    /** Retrieve the matched SMTP clients. */
    public Collection<Signature> matchedClients() { return m_clients; }
    
    /** Retrieve the matched SMTP client identifiers. */
    public Collection<String> matchedClientsID() {
        Collection<String> to_return = new LinkedList<String>();
        for (Signature client: m_clients)
            to_return.add(client.getIdentifier());
        return to_return;
    }
    
    /** Return true if the SMTP session matches no client/signature, false
     * otherwise. */
    public boolean isEmpty() { return m_clients.isEmpty(); }

}
