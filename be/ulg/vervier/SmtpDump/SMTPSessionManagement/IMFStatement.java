/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a IMF (RFC 5322) statement. Each statement belongs to
 * the set of enumerated IMF statement types (see IMFStatementType for details).
 * An IMF statement is simply an e-mail header field, body message or
 * termination sequence.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public class IMFStatement {

    /** INSTANCE VARIABLES */
    
    /** The IMF statement start index */
    private int start;
    /** The IMF statement end index */
    private int end;
    /** The SMTP command type, i.e. the command literal */
    private IMFStatementType type;
    
    /** CONSTRUCTOR */
    
    /** Default constructor. */
    public IMFStatement(IMFStatementType type) {
        this(type, 0, 0);
    }
    
    /** Create a new IMF statement with the given type, start and end index. */
    public IMFStatement(IMFStatementType type, int start, int end) {
        this.type = type;
        this.start = start;
        this.end = end;
    }
    
    /** METHODS */
    
    /** Retrieve the IMF statement type, e.g. IMF header field */
    public IMFStatementType type() { return type; }
    
    /** Retrieve the IMF statement start index. */
    public int start() { return start; }
    
    /** Retrieve the IMF statement end index. */
    public int end() { return end; }
    
    /** Set the IMF statement start index. */
    public void start(int start) { this.start = start; }
    
    /** Set the IMF statement end index. */
    public void end(int end) { this.end = end; }
    
    /** Return the length of the SMTP command. */
    public int length() { return end - start; }
    
    /** Return true if the command is empty, i.e. of length zero, false
     * otherwise. */
    public boolean isEmpty() { return start >= end; }

}
