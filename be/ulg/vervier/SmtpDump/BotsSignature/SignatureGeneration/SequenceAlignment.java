/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a sequence alignment algorithm. It implements both the
 * Needleman-Wunsch global alignement and the Smith-Waterman local alignment
 * algorithms.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.util.List;
import java.util.LinkedList;

public class SequenceAlignment {
    
    /** INSTANCE VARIABLES */
    
    /** The alignment matrix */
    private Cell[][] matrix;
    /** The first aligned sequence */
    private String aligned1;
    /** The second aligned sequence */
    private String aligned2;
    /** The list of gaps added to the first sequence to align it */
    private List<Integer> aligned1_gaps;
    /** The list of gaps added the second sequence to align it */
    private List<Integer> aligned2_gaps;
    /** The score obtained by the alignment of two sequences */
    private int score;
    /** The scoring function: identical character score */
    private static final int I = 1;
    /** The scoring function: gap inserted score */
    private static final int G = 0;
    /** The scoring function: different character score */
    private static final int D = 0;
    
    /** Class Cell. */
    class Cell {
        
        /** INSTANCE VARIABLES */
        
        /** The score of the cell */
        int score;
        /** The pointer to the cell representing the next aligned character in
         * the sequence */
        Cell pointer;
        /** The direction of the pointer to the next aligned character. Possible
         * directions include DIAG, UP, LEFT. */
        Direction direction;
        
        /** CONSTRUCTOR */
        
        /** Default constructor. */
        Cell(int score) {
            this(score, null, null);
        }
        
        /** Create a new cell with the given score and pointer to the given
         * cell. */
        Cell(int score, Cell pointer, Direction direction) {
            this.score = score;
            this.pointer = pointer;
            this.direction = direction;
        }
        
        /** METHODS */
        
        /** Retrieve the score of the cell. */
        int score() { return score; }
        
        /** Set the score of the cell. */
        void score(int score) { this.score = score; }
        
        /** Retrieve the cell representing the next aligned character in the
         * sequence */
        Cell pointer() { return pointer; }
        
        /** Retrieve the direction of the pointer to the next aligned character
         * in the sequence. */
        Direction direction() { return direction; }
        
    }
    
    /** Enum Direction. */
    enum Direction {
        DIAG,
        UP,
        LEFT
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    SequenceAlignment() {
		score = 0;
	}
    
    /** METHODS */
    
    /** Align the two given sequences using the Needleman-Wunsch global
     * alignment algorithm. */
    void alignNW(String s1, String s2) {
        align(s1, s2, true);
    }
    
    /** Align the two given sequences using the Smith-Waterman local
     * alignment algorithm. */
    void alignSW(String s1, String s2) {
        align(s1, s2, false);
    }
    
    /** Align the two given sequences. */
    void align(String s1, String s2, boolean nw) {
        if (s1 == null || s2 == null) return;
        matrix = new Cell[s1.length() + 1][s2.length() + 1];
        // build the score matrix
        matrix[0][0] = new Cell(0);
        Cell highest_score_cell = matrix[0][0];	// backtrace start cell for SW
        for (int i = 1; i < s1.length() + 1; i++)
            matrix[i][0] = new Cell(i * G, matrix[i - 1][0], Direction.UP);
        for (int j = 1; j < s2.length() + 1; j++)
            matrix[0][j] = new Cell(j * G, matrix[0][j - 1], Direction.LEFT);
        int diag_score = 0, left_score = 0, up_score = 0;
        for (int i = 1; i < s1.length() + 1; i++) {
            for (int j = 1; j < s2.length() + 1; j++) {
                diag_score = matrix[i - 1][j - 1].score() +
					score(s1.charAt(i - 1), s2.charAt(j - 1));
                up_score = matrix[i - 1][j].score() + G;
                left_score = matrix[i][j - 1].score() + G;
                if (diag_score >= left_score) {
                    if (diag_score >= up_score)
                        matrix[i][j] = new Cell(diag_score,
												matrix[i - 1][j - 1],
												Direction.DIAG);
                    else matrix[i][j] = new Cell(up_score,
												 matrix[i - 1][j],
												 Direction.UP);
                } else {
                    if (left_score >= up_score)
                        matrix[i][j] = new Cell(left_score,
												matrix[i][j - 1],
												Direction.LEFT);
                    else matrix[i][j] = new Cell(up_score,
												 matrix[i - 1][j],
												 Direction.UP);
                }
                if (!nw) {
					if (matrix[i][j].score() < 0)
						matrix[i][j].score(0);
					if (matrix[i][j].score() > highest_score_cell.score())
						highest_score_cell = matrix[i][j];
				}
            }
        }
        StringBuilder alignment1 = new StringBuilder();
        StringBuilder alignment2 = new StringBuilder();
        aligned1_gaps = new LinkedList<Integer>();
        aligned2_gaps = new LinkedList<Integer>();
        score = 0;
        int i = s1.length();
        int j = s2.length();
        // build the aligned sequences
        Cell cell = nw ? matrix[i][j] : highest_score_cell;
        while (cell != null && cell.pointer() != null) {
			if (!nw && cell.score() == 0) break;
            switch (cell.direction()) {
                case DIAG:
                    alignment1.append(s1.charAt(--i));
                    alignment2.append(s2.charAt(--j));
                    break;
                case UP:
                    alignment1.append(s1.charAt(--i));
                    alignment2.append('_');
                    aligned2_gaps.add(j);
                    break;
                case LEFT:
                    alignment1.append('_');
                    aligned1_gaps.add(i);
                    alignment2.append(s2.charAt(--j));
                    break;
                default: break;
            }
            score += cell.score();
            cell = cell.pointer();
        }
        aligned1 = alignment1.reverse().toString();
        aligned2 = alignment2.reverse().toString();
    }
    
    /** Return the score of the alignment of two sequences. */
    int getAlignmentScore() {
		return score;
	}
    
    /** Return the string version of the first aligned sequence. Gaps are
     * represented by '_' (underscore). */
    String getFirstAlignedSequence() { return aligned1; }
    
    /** Return the list of gaps that must be applied to the first sequence to
     * align it with the second one. */
    List<Integer> getFirstSequenceGaps() { return aligned1_gaps; }
    
    /** Return the string version of the second aligned sequence. Gaps are
     * represented by '_' (underscore). */
    String getSecondAlignedSequence() { return aligned2; }
    
    /** Return the list of gaps that must be applied to the second sequence to
     * align it with the first one. */
    List<Integer> getSecondSequenceGaps() { return aligned2_gaps; }
    
    /** The sequence alignement score function. */
    private int score(char c1, char c2) {
        return c1 == c2 ? I : D;
    }
    
}
