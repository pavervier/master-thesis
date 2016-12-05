/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a SMTP response. SMTP responses contain a digital code
 * and an optional text message.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public class SMTPResponse extends SessionStatement {

    /** INSTANCE VARIABLES */
    
    /** The SMTP response code */
    private int code;
    /** The SMTP response text message */
    private String message;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    SMTPResponse(int code) {
        this(code, null);
    }
    
    /** Create a new SMTP response with the given digital code and text
     * message. */
    SMTPResponse(int code, String message) {
        super(SessionStatementType.RESPONSE);
        this.code = code;
        this.message = message;
    }
    
    /** METHODS */
    
    /** Retrieve the SMTP response code. */
    public int code() { return code; }
    
    /** Retrieve the SMTP response text message. */
    public String message() { return message; }
    
    /** Return the String representation of the SMTP response, i.e. the 3-digit
     * code and the associated message if any. */
    public String toString() {
        return code + " \"" + message + "\"";
    }
    
}
