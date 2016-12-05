/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a Internet Message Format (RFC 5322) message. A message
 * is usually made of:
 * - IMF header fields;
 * - a message body;
 * - and the SMTP termination sequence.
 * Warning: concatenating IMF statements may not return the original IMF payload
 * as character sequences may be associated with multiple statements.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

import java.util.List;
import java.util.ArrayList;

public class IMFMessage extends SessionStatement {

    /** INSTANCE VARIABLES */
    
    /** The IMF message */
    private String message;
    /** The index in the reassembled message where this part of message
     * starts */
    private int start_msg_index;
    /** The list of IMF statements */
    private List<IMFStatement> statements;
    /** The list of IMF fragments start index */
    private List<Integer> fragments;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public IMFMessage(int start_msg_index) {
        super(SessionStatementType.MESSAGE);
        this.start_msg_index = start_msg_index;
        statements = new ArrayList<IMFStatement>(10);
        fragments = new ArrayList<Integer>(10);
    }
    
    /** METHODS */
    
    /** Retrieve the IMF message. */
    public String message() { return message; }
    
    /** Set the IMF message. */
    public void message(String message) {
        if (message == null) fragments.clear();
        else {
			// remove any fragment that would be out of the message boundaries
            for (int i = 0; i < fragments.size(); i++)
                if (fragments.get(i).intValue() >= message.length())
                    fragments.remove(i);
        }
        this.message = message;
    }
    
    /** Return the length of the SMTP message. */
    public int length() { return message != null ? message.length() : -1; }
    
    /** Return true if the message is empty, i.e. of length zero, false
     * otherwise. */
    public boolean isEmpty() {
        return message != null ? message.isEmpty() : true;
    }
    
    /** Retrieve the index in the reassembled message where this part of message
     * starts. */
    public int getStartMsgIndex() { return start_msg_index; }
    
    /** Add the given IMF statement to the IMF message. The statement position
     * is given by its start and end index. The whole message can still be
     * processed while individual statements can be extracted from the message
     * if needed. */
    public void addStatement(IMFStatementType type, int start, int end) {
        start -= start_msg_index;
        end -= start_msg_index;
        if (start >= 0 && end > start)
            statements.add(new IMFStatement(type, start, end));
    }
    
    /** Set an IMF fragment boundary at the given index in the message. */
    public void setFragment(int frag_index, int stmt_index) {
        if (frag_index >= 0 && stmt_index >= 0)
            if (frag_index < fragments.size())
                fragments.set(frag_index, stmt_index);
            else if (frag_index == fragments.size())
                fragments.add(stmt_index);
        return;
    }
    
    /** Retrieve the list of IMF fragment boundaries. */
    public List<Integer> getFragments() { return fragments; }
    
    /** Retrieve the part of the message corresponding to the given fragment. */
    public String getFragment(int index) {
        if (message == null) return null;
        int frag_index = fragments.indexOf(index);
        int frag_start = fragments.get(frag_index);
        int frag_end = fragments.size() > frag_index + 1 ? 
            fragments.get(frag_index + 1) : message.length();
        return message.substring(frag_start, frag_end);
    }
    
    /** Retrieve the list of IMF statements. */
    public List<IMFStatement> getStatements() { return statements; }
    
    /** Retrieve the number of IMF statments in the IMF message. */
    public int getStatementCount() { return statements.size(); }
    
    /** Retrieve the String representation of the given IMF statement. */
    public String getStatementString(IMFStatement statement) {
        return message.substring(statement.start(), statement.end());
    }
    
    /** Return the String representation of the IMF message. */
    public String toString() { return message; }

}
