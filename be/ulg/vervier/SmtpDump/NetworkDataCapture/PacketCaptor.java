/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a network PDUs reader. It is independant of the
 * PDUs container (file, network, ...).
 * 
 */

package be.ulg.vervier.SmtpDump.NetworkDataCapture;

public abstract class PacketCaptor {
    
    /** INSTANCE VARIABLES */
    
    /** The resource identifier (e.g. capture interface, file) */
    protected String resource_identifier;
    /** The reader component */
    protected jpcap.JpcapCaptor captor;
    /** Is the resource opened ? */
    protected boolean is_resource_open;
    /** The current packet being read */
    protected jpcap.packet.Packet packet;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public PacketCaptor() { this(null); }
    /** Creates a packet captor with the given resource identifier. */
    public PacketCaptor(String resource_identifier) {
        this.resource_identifier = resource_identifier;
        is_resource_open = false;
    }
    
    /** METHODS */
    
    /** Read the next PDU from the input stream. */
    public jpcap.packet.Packet read() throws PacketCaptorException {
        if (!is_resource_open)
            throw new PacketCaptorException("packet-captor:no open captor");
        packet = captor.getPacket();
        return (packet == null || packet == jpcap.packet.Packet.EOF) ?
            null : packet;
    }
    
    /** Set the identifier of the resource to capture from. */
    public void setResourceIdentifier(String resource_id) {
        this.resource_identifier = resource_id;
    }
    
    /** Get the identifier of the resource to capture from. */
    public String getResourceIdentifier() {
        return resource_identifier;
    }
    
    /** Open a new input resource. */
    public abstract void open() throws PacketCaptorException;
    
    /** Close the current input stream. */
    public void close() {
        if (!is_resource_open) return;
        captor.close();
        is_resource_open = false;
    }
    
}
