/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements the building of a phylogenetic tree given a set of
 * input sequences. The Smith-Waterman local alignment algorithm and the UPGMA
 * method are used to build the tree.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

class TreeBuilder {
    
    /** INSTANCE VARIABLES */
    
    /** The built tree */
    private PhylogeneticTree tree;
    /** The collection of sequences to be stored in the tree */
    private List<PhylogeneticTree> sequences;
    /** The matrix storing the distance between each tree leaf, i.e. between
     * each sequence. */
    private int[][] dist_matrix;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    TreeBuilder() {
        sequences = new ArrayList<PhylogeneticTree>();
    }
    
    /** METHODS */
    
    /** Retrieve the built tree. */
    PhylogeneticTree getTree() { return tree; }
    
    /** Add the given sequence to the collection of sequences stored in the
     * tree. */
    void addSequence(String sequence) {
        if (sequence != null) {
            PhylogeneticTree t = new PhylogeneticTree();
            t.setRoot(new TreeNode(sequence));
            t.addLeafIndex(sequences.size());
            sequences.add(t);
        }
    }
    
    /** Build the phylogenetic tree with the sequences previously added using
     * the UPGMA method. */
    PhylogeneticTree buildTree() {
        computeDistanceMatrix();
        PhylogeneticTree nearest_t1 = null;
        PhylogeneticTree nearest_t2 = null;
        int shortest_dist = 0;
        int distance = 0;
        while (sequences.size() > 1) {
            for (PhylogeneticTree t: sequences) {
                for (PhylogeneticTree tt: sequences) {
                    if (t != tt) {
                        if (nearest_t1 == null && nearest_t2 == null) {
                            nearest_t1 = t;
                            nearest_t2 = tt;
                            shortest_dist = getDistance(t, tt);
                        } else {
                            if ((distance = getDistance(t, tt)) <
								shortest_dist) {
                                nearest_t1 = t;
                                nearest_t2 = tt;
                                shortest_dist = distance;
                            }
                        }
                    }
                }
            }
            nearest_t1.mergeTrees(nearest_t2);
            sequences.remove(nearest_t2);
            nearest_t1 = null;
            nearest_t2 = null;
        }
        return sequences.get(0);
    }
    
    /** Perform a preorder tree traversal and print the value of each visited
     * node. */
    private void treeTraversal(TreeNode n) {
        if (n == null) return;
        if (n.isLeaf())
            System.out.println(n.getValue());
        else {
            treeTraversal(n.getRightChild());
            treeTraversal(n.getLeftChild());
        }
    }
    
    /** Compute the distance between two phylogenetic trees. If at least of tree
     * contains more than one leaf, the UPGMA method is employed to compute the
     * distance. If the two trees only have one leaf, the distance between the
     * value of the node of these trees is computed using a local alignment
     * algorithm. */
    private int getDistance(PhylogeneticTree t1, PhylogeneticTree t2) {
        if (t1 == null || t2 == null) return -1;
        return t1.getRoot().isLeaf() && t2.getRoot().isLeaf() ?
            getExternalDistance(t1, t2) : getInternalDistance(t1, t2);
    }
    
    /** Compute the distance between two given trees containing only one
     * leaf. The distance is computed using the Smith-Waterman local alignment
     * algorithm. */
    private int getExternalDistance(PhylogeneticTree t1, PhylogeneticTree t2) {
        if (t1 == null || t2 == null) return -1;
        int i = t1.getLeafIndices().get(0);
        int j = t2.getLeafIndices().get(0);
        return dist_matrix[(i > j ? i : j) - 1][i > j ? j : i];
    }
    
    /** Compute the distance between two trees with at least of tree containing
     * more than one leaf. The distance is computed using the UPGMA method. */
    private int getInternalDistance(PhylogeneticTree t1, PhylogeneticTree t2) {
        if (t1 == null || t2 == null) return -1;
        int distance = 0;
        for (Integer i: t1.getLeafIndices())
            for (Integer j: t2.getLeafIndices())
                distance += dist_matrix[(i > j ? i : j) - 1][i > j ? j : i];
        distance /= (t1.getLeafIndices().size() * t2.getLeafIndices().size());
        return distance;
    }
    
    /** Compute the distance between sequences using the Smith-Waterman local
     * alignment algorithm and store the result in a matrix. */
    private void computeDistanceMatrix() {
        String seq1 = null;
        String seq2 = null;
        int limit = 0;
        SequenceAlignment sa = new SequenceAlignment();
        dist_matrix = new int[sequences.size() - 1][];
        // fill in distance matrix
        for (int i = 0; i < sequences.size() -1; i++) {
            dist_matrix[i] = new int[i + 1];
            for (int j = 0; j < i + 1; j++) {
                seq1 = sequences.get(i + 1).getRoot().getValue();
                seq2 = sequences.get(j).getRoot().getValue();
                // perform local alignment
                if (seq1 != seq2) {
					sa.alignSW(seq1, seq2);
					dist_matrix[i][j] = sa.getAlignmentScore();
                }
            }
        }
    }
    
}
