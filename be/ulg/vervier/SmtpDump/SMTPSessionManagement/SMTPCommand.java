/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a SMTP command. Each command belongs to the set of
 * enumerated SMTP command types. SMTP commands provided by an Extended SMTP
 * compliant server are labeled as EXTN (Extended) (e.g. starttls, auth).
 * The Internet Message Format data sent by a SMTP client is also stored in a
 * SMTP command even if it is not really a SMTP command. The command label IMF
 * refers to that kind of message.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public class SMTPCommand extends SessionStatement {

    /** INSTANCE VARIABLES */
    
    /** The SMTP command */
    private String command;
    /** The SMTP command type, i.e. the command literal */
    private SMTPCommandType cmd_type;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public SMTPCommand(SMTPCommandType cmd_type) {
        super(SessionStatementType.COMMAND);
        this.cmd_type =  cmd_type;
    }
    
    /** METHODS */
    
    /** Retrieve the SMTP command type, i.e. the command literal */
    public SMTPCommandType cmdType() { return cmd_type; }
    
    /** Retrieve the SMTP command. */
    public String command() { return command; }
    
    /** Set the SMTP command. */
    public void command(String command) { this.command = command; }
    
    /** Return the length of the SMTP command. */
    public int length() { return command.length(); }
    
    /** Return true if the command is empty, i.e. of length zero, false
     * otherwise. */
    public boolean isEmpty() { return command.isEmpty(); }
    
    /** Return the String representation of the SMTP command, i.e. the command
     * literal and its arguments if any. */
    public String toString() {
        return command;
    }

}
