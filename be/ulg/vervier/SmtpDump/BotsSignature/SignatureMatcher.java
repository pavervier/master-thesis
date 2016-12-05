/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a matcher for spamming botnet signatures. Using
 * regex based signatures, it attempts to match these signatures against SMTP
 * session. Signatures are extracted from a file by the SignatureParser or
 * automatically generated using the SignatureGenerator.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.logging.Logger;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;

public class SignatureMatcher {
    
    /** INSTANCE VARIABLES */
    
    /** The signature file parser */
    private SignatureParser sig_parser;
    /** The collection of bot signatures */
    private Collection<Signature> signatures;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public SignatureMatcher() { this(null); }
        
    /** Create a new SignatureParser with the given matched session queue and
     * the input signature file. */
    public SignatureMatcher(String sig_file_name) {
        sig_parser = new SignatureParser(sig_file_name);
    }
    
    /** METHODS */
    
    /** Parse the signature file and extract signatures from it. */
    public void buildSignatures() throws SignatureParserException {
        sig_parser.parse();
        signatures = sig_parser.getSignatures();
    }
    
    /** Add the given signature to the collection. Unlike the "buildSignatures"
     * method which reads defintions from a file given at startup, this method
     * allows for dynamic addition of new signatures. */
    public void addSignature(Signature signature) {
        if (signature != null && !signature.isEmpty())
            signatures.add(signature);
    }
    
    /** Retrieve the collection of signatures (aka clients) matched by the given
     * SMTP session. */
    public Collection<MatchedSMTPClient> getMatchedClients
            (SMTPSession session) {
        Collection<MatchedSMTPClient> to_return =
            new LinkedList<MatchedSMTPClient>();
        MatchedSMTPClient t_m = null;
        for (Signature sig: signatures) {
            if (sig.isMatching(session)) {
                (t_m = new MatchedSMTPClient(sig)).addMatchingSession(session);
                to_return.add(t_m);
            }
        }
        return to_return;
    }
    
    /** Retrieve the collection of signatures (aka clients) matched by at least
     * one of the given SMTP sessions. */
    public Collection<MatchedSMTPClient> getMatchedClients
            (Collection<SMTPSession> sessions) {
        Collection<MatchedSMTPClient> to_return =
            new LinkedList<MatchedSMTPClient>();
        for (SMTPSession session: sessions)
            to_return.addAll(getMatchedClients(session));
        return to_return;
    }
    
    /** Retrieve the collection of signatures (aka clients) matched by the given
     * SMTP session. */
    public MatchingSMTPSession getMatchingSession(SMTPSession session) {
        MatchingSMTPSession to_return = null;
        for (Signature sig: signatures) {
            if (sig.isMatching(session)) {
                if (to_return == null)
                    to_return = new MatchingSMTPSession(session);
                to_return.addMatchedClient(sig);
            }
        }
        return to_return;
    }
    
    /** Retrieve the collection of SMTP sessions matching at least one signature
     * (aka client). */
    public Collection<MatchingSMTPSession> getMatchingSessions
            (Collection<SMTPSession> sessions) {
        Collection<MatchingSMTPSession> to_return =
            new LinkedList<MatchingSMTPSession>();
        MatchingSMTPSession t_m = null;
        for (SMTPSession session: sessions) {
            if ((t_m = getMatchingSession(session)) != null)
                to_return.add(t_m);
        }
        return to_return;
    }
    
}
