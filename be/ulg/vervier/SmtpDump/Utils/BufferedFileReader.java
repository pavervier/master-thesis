/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a file reader using buffering to speed up the reading
 * process. After the file has been opened, the sequence of characters stored in
 * the file can be retrieved. The file must be closed after the reading process.
 * 
 */

package be.ulg.vervier.SmtpDump.Utils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class BufferedFileReader {
    
    /** INSTANCE VARIABLES */
    
    /** The name of the file to read */
    private String file_name;
    /** The buffered reader used to read the file */
    private BufferedReader br;
    /** The default buffer size (1KB) */
    private static final int DEFAULT_BUFFER_SIZE = 1024;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public BufferedFileReader() { this(null); }
    
    /** Create a new SignatureParser to parse bots signature from the given
     * input file. */
    public BufferedFileReader(String file_name) {
        this.file_name = file_name;
    }
    
    /** METHODS */
    
    /** Read the file and return the sequence of characters using a default
     * buffer of size 1024 bytes (1KB). */
    public String readFile() throws IOException {
        return readFile(DEFAULT_BUFFER_SIZE);
    }
    
    /** Read the file and return the sequence of characters using a buffer
     * of the given size. */
    public String readFile(int buffer_size) throws IOException {
        if (!isOpen() || buffer_size < 1) return null;
        // limit buffer size to 8KB
        if (buffer_size > 8192) buffer_size = 8192;
        // create an initial character buffer for reading the input file
        StringBuilder in_str = new StringBuilder(2048);
        char[] in_buffer = new char[buffer_size];
        int read_count;
        try {
            while (br.ready()) {
                read_count = br.read(in_buffer, 0, in_buffer.length);
                in_str.append(in_buffer, 0, read_count);
            }
        } catch (IOException ioe) {
            throw new IOException("file reader:" + ioe.getMessage());
        }
        return in_str.toString();
    }
    
    /** Return true if the file is open, false otherwise. */
    public boolean isOpen() {
        return br != null;
    }
    
    /** Open the signature file. */
    public void openFile() throws IOException {
        if (file_name == null || (file_name != null && file_name.isEmpty()))
            throw new IOException("file-reader:no file provided");
        try {
            br = new BufferedReader(new FileReader(file_name));
        } catch (IOException ioe) {
            throw new IOException
                ("file reader:error while opening file \"" + file_name + "\"");
        }
    }
    
    /** Close the signature file. */
    public void closeFile() throws IOException {
        if (br == null) return;
        try {
            br.close();
        } catch (IOException ioe) {
            throw new IOException
                ("file reader:error while closing file " + file_name);
        }
        br = null;
    }
    
}
