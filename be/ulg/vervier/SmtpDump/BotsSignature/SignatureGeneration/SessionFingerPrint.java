/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a client SMTP session fingerprint. A finger print
 * includes different kind of features usefull in identifying further instances
 * of SMTP sessions comming intiated by the same SMTP client. Below are some
 * examples of features:
 * - the client open and close/reset the underlying TCP connection;
 * - the client uses SMTP/ESMTP;
 * - SMTP commands format (e.g. HELO, helo, Helo, etc);
 * - the IMF message fragmentation pattern;
 * - etc.
 * The fingerprint is meant to be used to perform SMTP session clustering in
 * the client signature generation process.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.util.Collection;
import java.util.List;
import java.util.HashSet;
import java.util.ArrayList;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SessionStatement;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SessionStatementType;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPCommand;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPCommandType;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.IMFMessage;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.IMFStatement;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.IMFStatementType;

class SessionFingerPrint {
    
    /** INSTANCE VARIABLES */
    
    /** The TCP connection has been opened */
    private boolean tcp_open;
    /** The TCP connection has been closed */
    private boolean tcp_close;
    /** The TCP connection has been reset */
    private boolean tcp_reset;
    /** True if Extended SMTP is used, false otherwise */
    private boolean esmtp;
    /** True if at least one IMF message has been sent */
    private boolean has_send_message;
    /** The SMTP session has been closed (QUIT command issued) */
    private boolean smtp_quit;
    /** The number of SMTP transactions */
    private int smtp_trans_count;
    /** The list of SMTP commands issued by the client */
    private Collection<SMTPCommandType> smtp_commands;
    /** The list of IMF fields used in the message(s) */
    private Collection<IMFStatementType> imf_stmts;
    /** The IMF message fragmentation pattern */
    private Collection<Integer> imf_fragments;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    SessionFingerPrint() {}
    
    /** METHODS */
    
    /** Perform fingerprinting of the given SMTP session. */
    void fingerPrint(SMTPSession smtp_session) {
        if (smtp_session == null) return;
        // extract TCP flags
        tcp_open = smtp_session.hasTcpSyn();
        tcp_close = smtp_session.hasTcpFin();
        tcp_reset = smtp_session.hasTcpRst();
        smtp_trans_count = smtp_session.getTransactionCount();
        SMTPCommand c = null;
        SMTPCommandType c_type = null;
        smtp_commands =
			new HashSet<SMTPCommandType>(smtp_session.getCommands().size());
        imf_stmts = new HashSet<IMFStatementType>();
        imf_fragments = new HashSet<Integer>(smtp_trans_count);
        // extract the SMTP commands and IMF messages
        for (SessionStatement s: smtp_session.getCommands()) {
            if (s.stmtType() == SessionStatementType.COMMAND) {
                smtp_commands.add(c_type = (c = (SMTPCommand)s).cmdType());
                // test if client uses SMTP or ESMTP
                if (c_type == SMTPCommandType.HELO) {
                    String t_c = c.command();
                    for (int i = 0; i < t_c.length(); i++) {
                        if (Character.isLetter(t_c.charAt(i)) &&
                            (t_c.charAt(i) == 'e' || t_c.charAt(i) == 'E'))
                            esmtp = true;
                        else break;
                    }
                // test if the client correctly closes the SMTP session
                } else if (c_type == SMTPCommandType.QUIT) {
                    smtp_quit = true;
                }
                // record the type of SMTP commands issued
                if (!smtp_commands.contains(c_type))
                    smtp_commands.add(c_type);
            } else if (s.stmtType() == SessionStatementType.MESSAGE) {
                has_send_message = true;
                List<IMFStatement> l_s = ((IMFMessage)s).getStatements();
                // record the type of the IMF message fields encountered
                for (IMFStatement i: l_s)
                    if (!imf_stmts.contains(i.type()))
                        imf_stmts.add(i.type());
                // extract the IMF message fragmentation patterns
                for (Integer i: ((IMFMessage)s).getFragments())
                    imf_fragments.add(i);
            }
        }
    }
    
    /** Return true if the TCP connection has been opened, false otherwise. */
    boolean tcpOpen() { return tcp_open; }
    
    /** Return true if the TCP connection has been closed, false otherwise. */
    boolean tcpClose() { return tcp_close; }
    
    /** Return true if the TCP connection has been reset, false otherwise. */
    boolean tcpReset() { return tcp_reset; }
    
    /** Return true if Extended SMTP is used, false otherwise. */
    boolean esmtp() { return esmtp; }
    
    /** Return true if at least one IMF message has been sent. */
    boolean hasSendMessage() { return has_send_message; }
    
    /** Return true if the SMTP session has been closed (QUIT command issued),
     * false otherwise. */
    boolean smtpQuit() { return smtp_quit; }
    
    /** Retrieve the number of SMTP transactions. */
    int smtpTransactionCount() { return smtp_trans_count; }
    
    /** Retrieve the list of SMTP commands issued by the client. */
    Collection<SMTPCommandType> getCmdsType() { return smtp_commands; }
    
    /** Retrieve the list of IMF fields used in the message(s). */
    Collection<IMFStatementType> getIMFStmtsType() { return null; }
    
    /** Return true if the given object is equal to the current session
     * fingerprint. Two fingerprints are equal if all their fields match.
     * Session fingerprint fields include:
     * - the TCP connection has been open;
     * - the TCP connection has been closed;
     * - the TCP connection has been reset;
     * - the client uses ESMTP;
     * - the client has sent at least one email message;
     * - the SMTP session has been closed (QUIT);
     * - the number of SMTP transactions;
     * - the list of SMTP commands issued by the client;
     * - the list of IMF statements found in the message(s);
     * - the list of IMF message fragment booundaries.
     * Fields may be updated.
     * 
     */
    public boolean equals(Object o) {
        SessionFingerPrint sfp;
        try {
            sfp = (SessionFingerPrint)o;
        } catch (ClassCastException cce) {
            return false;
        }
        boolean equal = false;
        equal = tcp_open == sfp.tcp_open &&
                tcp_close == sfp.tcp_close &&
                tcp_reset == sfp.tcp_reset &&
                esmtp == sfp.esmtp &&
                has_send_message == sfp.has_send_message &&
                smtp_quit == sfp.smtp_quit &&
                smtp_trans_count == sfp.smtp_trans_count;
        if (!equal) return false;
        if (smtp_commands.size() != sfp.smtp_commands.size()) return false;
        if (imf_stmts.size() != sfp.imf_stmts.size()) return false;
        if (imf_fragments.size() != sfp.imf_fragments.size()) return false;
        for (SMTPCommandType c: smtp_commands)
            if (!sfp.smtp_commands.contains(c)) return false;
        for (IMFStatementType s: imf_stmts)
            if (!sfp.imf_stmts.contains(s)) return false;
        for (Integer i: imf_fragments)
            if (!sfp.imf_fragments.contains(i)) return false;
        return true;
    }
    
    /** Compute and return the hashcode of the session fingerprint instance. */
    public int hashCode() {
        long hash_code = 0;
        hash_code = 15 * new Boolean(tcp_open).hashCode() +
                    16 * new Boolean(tcp_close).hashCode() +
                    17 * new Boolean(tcp_reset).hashCode() +
                    18 * new Boolean(esmtp).hashCode() +
                    19 * new Boolean(has_send_message).hashCode() +
                    20 * new Boolean(smtp_quit).hashCode() +
                    21 * smtp_trans_count;
        for (SMTPCommandType c_t: smtp_commands)
            hash_code += c_t.hashcode();
        for (IMFStatementType s_t: imf_stmts)
            hash_code += s_t.hashcode();
        for (Integer i: imf_fragments)
            hash_code += i.hashCode();
        return new Long(hash_code).hashCode();
    }
    
}
