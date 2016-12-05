/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a session statement. A session statement can be either
 * a SMTP command or a IMF message. The session statement allows easy processing
 * of SMTP commands and IMF messages whithout any knowledge of what is actually
 * inside.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public abstract class SessionStatement {

    /** INSTANCE VARIABLE */
    
    /** The stmt_type of statement (e.g. SMTP command, IMF message) */
    private SessionStatementType stmt_type;
    
    /** CONSTRUCTOR */
    
    /** Default constructor. */
    public SessionStatement(SessionStatementType stmt_type) {
        this.stmt_type = stmt_type;
    }
    
    /** METHOD */
    
    /** Retrieve the stmt_type of the session statement. */
    public SessionStatementType stmtType() { return stmt_type; }
    
    /** Return the String representation of the given session statement. */
    public abstract String toString();
    
}
