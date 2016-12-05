/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a spam bot signature. It is simply a set of regular
 * expressions that must match SMTP communications between the bot and a server.
 * In addition to regex pattern matching, the TCP flags can also be checked.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

import java.util.Collection;
import java.util.List;
import java.util.LinkedList;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SessionStatement;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SessionStatementType;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPCommand;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.IMFMessage;

public class Signature {
    
    /** INSTANCE VARIABLES */
    
    /** The pattern matcher */
    private Matcher matcher;
    /** A litteral identifier of the signature, i.e. the name of the spambot */
    private String lit_identifier;
    /** The list of signature regular expressions */
    private ArrayList<Statement> statements;
    /** The list of variable values that linked groups must match. */
    private ArrayList<String> variables_value;
    /** True if the signature must check for TCP flags (SYN, FIN, RST), false
     * otherwise */
    private boolean check_tcp_flags;
    /** True if the TCP connection must have been opened correctly, false
     * otherwise */
    private boolean has_syn;
    /** True if the TCP connection must have been closed correclty, false
     * otherwise */
    private boolean has_fin;
    /** True if the TCP connection must have been reset, false otherwise */
    private boolean has_rst;
    /** True if the signature statement contains at least one variable */
    private boolean has_variable;
    /** True if the signature statements have to be matched in the order there
     * were added, i.e. a strict ordering must be respected, false otherwise */
    private boolean strict_order;
    
    /** This class represents a signature statement, i.e. a component of the
     * signature. */
    class Statement {
        
        /** INSTANCE VARIABLES */
        
        /** The signature pattern to be matched */
        private Pattern pattern;
        /** The list of links, i.e. pattern groups whose value is linked with
         * other statements' pattern groups. */
        private LinkedList<Link> links;
        /** True if the statement is grouped with the preceding one. A group
         * of statements must match consecutive SMTP messages, false
         * otherwise. */
        private boolean grouped;
        /** True if the statement must be in the same SMTP transaction as the
         * preceding statement, false otherwise. */
        private boolean same_transaction;
        
        /** CONSTRUCTORS */
        
        /** Default constructor. */
        Statement(Pattern pattern,
                  LinkedList<Link> links,
                  boolean grouped,
                  boolean same_transaction) {
            this.pattern = pattern;
            this.links = links;
            this.grouped = grouped;
            this.same_transaction = same_transaction;
        }
        
        /** METHODS */
        
        /** Return true if the statement is grouped with the preceding
         * statement. */
        boolean isGrouped() { return grouped; }
        
        /** Return true if the statement must belong to the same SMTP
         * transaction as the preceding statement, false otherwise. */
        boolean sameTransaction() { return same_transaction; }
        
        /** Return true if the statement contains at least one variable. */
        boolean hasVariable() { return links != null; }
        
        /** Retrieve the collection of links for that statement. */
        Collection<Link> getLinks() { return links; }
        
        /** Retrieve the statement pattern. */
        Pattern getPattern() { return pattern; }
        
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public Signature() { this(null); }
    
    /** Create a new Signature instance with the given litteral identifier. */
    public Signature(String identifier) {
        lit_identifier = identifier;
        statements = new ArrayList<Statement>();
        variables_value = new ArrayList<String>();
        has_syn = false;
        has_fin = false;
        has_rst = false;
        has_variable = false;
        strict_order = false;
    }
    
    /** METHODS */
    
    /** Add a regular expression signature to the list. */
    public void addSignatureRegex(String sig,
                           LinkedList<Link> links,
                           boolean grouped,
                           boolean same_transaction)
            throws InvalidBotSignatureException {
        try {
            statements.add(new Statement(Pattern.compile(sig, Pattern.DOTALL),
                                         links,
                                         grouped,
                                         same_transaction));
        } catch (java.util.regex.PatternSyntaxException pse) {
            throw new InvalidBotSignatureException();
        }
    }
    
    /** Set the identifier of the signature. */
    public void setIdentifier(String identifier) {
        lit_identifier = identifier;
    }
    
    /** Retrieve the identifier of the signature. */
    public String getIdentifier() {
        return lit_identifier;
    }
    
    /** Set/reset the strict ordering constraint on the signature statements,
     * i.e. statements have/have not to be matched in the order they were added
     * to the signature. */
    public void strictOrder(boolean order) {
        strict_order = order;
    }
    
    /** Set the signature check for a successfull TCP SYN phase. */
    public void checkTcpSyn() {
        check_tcp_flags = has_syn = true;
    }
    
    /** Set the signature check for a successfull TCP FIN phase. */
    public void checkTcpFin() {
        check_tcp_flags = has_syn = has_fin = true;
    }
    
    /** Set the signature check for a TCP RESET. */
    public void checkTcpRst() {
        check_tcp_flags = has_rst = true;
    }
    
    /** Return true if the signature contains no statement. */
    public boolean isEmpty() {
        return statements.isEmpty();
    }
    
    /** Return the number of statements in the signature. */
    public int size() {
        return statements.size();
    }
    
    /** Attemp to match the given SMTP session data with the signature, i.e.
     * test the whole SMTP session against the list of regular expressions. */
    public boolean isMatching(SMTPSession session) {
        // if commands collection is empty, no match
        if (session == null || (session != null && session.isEmpty()))
            return false;
        // TCP flags must be checked ?
        if (check_tcp_flags) {
            if (!(session.hasTcpSyn() == has_syn &&
                session.hasTcpFin() == has_fin &&
                session.hasTcpRst() == has_rst))
                return false;
        }
        Matcher pm = null;
        Statement cur_stmt = null;
        boolean match = false;
        int bs = 1, be = -1;
        boolean eof = false;
        List<SessionStatement> msgs = session.getCommands();
        String smtp_stmt = null;
        // if the SMTP contains no SMTP command, no match
        if (msgs.size() == 0) return false;
        int var_index = -1, gp_number = -1;
        int i = 0, j = msgs.size(), k = 0, l = k, m = -1, n = m;
        variables_value.clear();
        while (k < statements.size() && !eof) { // for each signature statement
            bs = be = k;
            while (be < statements.size() -1 &&
                   (statements.get(be + 1).isGrouped() ||
                   statements.get(be + 1).sameTransaction())) {
                be++;
            }
            while (l <= be && !eof) {
                cur_stmt = statements.get(l);
                i = n + 1;
                if (cur_stmt.isGrouped()) {
					// search forward to match the block/grp
                    j = i + 1;
                } else {
					// search forward to match the statement
                    j = msgs.size();
                }
                // attempt to match STMP content
                for (;j <= msgs.size() && i < j && !match; i++) {
                    if (cur_stmt.sameTransaction() &&
                        !session.isMatchingTransaction
                        (session.getCmdTransaction(i-1),
                         session.getCmdTransaction(i)))
                        break;
                    if (msgs.get(i).stmtType() == SessionStatementType.COMMAND)
                        smtp_stmt = ((SMTPCommand)msgs.get(i)).command();
                    else if (msgs.get(i).stmtType() ==
							 SessionStatementType.MESSAGE)
                        smtp_stmt = ((IMFMessage)msgs.get(i)).message();
                    if ((pm = cur_stmt.getPattern().matcher(smtp_stmt)).find()){
                        // statement has matched
                        if (cur_stmt.hasVariable()) {
                            // statement contains variables, check value
                            for (Link li: cur_stmt.getLinks()) {
                                var_index = li.getVariableValueIndex();
                                gp_number = li.getLinkGroupNumber();
                                if (var_index >= 0 &&
									pm.group(gp_number) != null) {
                                    if (var_index < variables_value.size() &&
                                        variables_value.get(var_index) != null) {
                                        // the variable has already been
                                        // assigned a value, check if values
                                        // match
                                        if (!pm.group(gp_number).equals
                                            (variables_value.get(var_index)))
                                            return false;
                                    } else {
                                        // the variable has not already been
                                        // assigned a value, record first value
                                        variables_value.add
                                            (var_index, pm.group(gp_number));
                                    }
                                    match = true;
                                }
                            }
                        } else match = true;
                    }
                }
                if (match) { // match, go to next statement
                    n = i - 1;
                    l++;
                } else if (!match && bs < be) {
					// no match for the block, go backward
                    l = k;
                    n = ++m;
                } else if (!match && bs == be) {
					// no match for the current sig, quit
                    return false;
                }
                // reset match variable
                match = false;
                eof = n >= msgs.size() - 1;
            }
            m = n;
            k = l;
        }
        return k == statements.size();
    }
    
}
