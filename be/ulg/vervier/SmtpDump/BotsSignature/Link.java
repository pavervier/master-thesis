/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class represents a link between a variable instance in a signature
 * statement and the index in a data structure of the value it should have.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

class Link {
    
    /** INSTANCE VARIABLES */
    
    /** The number of the linked group in the statement */
    private int group_number;
    /** The index of the variable unique value */
    private int link_index;
    
    /** CONSTRUCTORS */
    
    /** Create a new Link instance between a group in a statement and a
     * variable. */
    Link(int group_number, int link_index) {
        this.group_number = group_number;
        this.link_index = link_index;
    }
    
    /** METHODS */
    
    /** Retrieve the group number of the link in the statement */
    int getLinkGroupNumber() { return group_number; }
    
    /** Retrieve the index of the variable unique value. */
    int getVariableValueIndex() { return link_index; }
    
    public String toString() {
        return "(" + group_number + "," + link_index + ")";
    }
    
}
