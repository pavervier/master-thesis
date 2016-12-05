/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a binary phylogenetic tree.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.util.List;
import java.util.LinkedList;

public class PhylogeneticTree {
    
    /** INSTANCE VARIABLES */
    
    /** The tree root */
    private TreeNode root;
    /** The number of nodes in the tree */
    private int node_count;
    /** The list of leaf indices */
    private List<Integer> leaf_indices;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public PhylogeneticTree() {
        leaf_indices = new LinkedList<Integer>();
    }
    
    /** METHODS */
    
    /** Get the root node of the tree. */
    public TreeNode getRoot() { return root; }
    
    /** Set the given node as the root node. If a root node already exists,
     * the previous root node is replaced with the new given node. Return the
     * previous root node if any. */
    public TreeNode setRoot(TreeNode root) {
        TreeNode previous_root = null;
        if (this.root != null) {
            previous_root = this.root;
            this.root.getLeftChild().setParent(root);
            root.setLeftChild(this.root.getLeftChild());
            this.root.getRightChild().setParent(root);
            root.setRightChild(this.root.getRightChild());
            root.setValue(this.root.getValue());
        } else {
            node_count++;
        }
        this.root = root;
        this.root.setParent(null);
        return previous_root;
    }
    
    /** Add the given left child node to the given node. */
    public void addLeft(TreeNode parent, TreeNode child) {
        if (parent != null)
            parent.setLeftChild(child);
        node_count++;
    }
    
    /** Add the given right child node to the given node. */
    public void addRight(TreeNode parent, TreeNode child) {
        if (parent != null)
            parent.setRightChild(child);
        node_count++;
    }
    
    /** Retrieve the number of nodes in the tree. */
    public int getNodeCount() { return node_count; }
    
    /** Merge the current tree with the given tree by setting each subtree root
     * node as the left and right child of the new tree root node. */
    public void mergeTrees(PhylogeneticTree tree) {
        if (tree != null) {
            TreeNode n = new TreeNode();
            n.setLeftChild(this.root);
            this.root.setParent(n);
            n.setRightChild(tree.getRoot());
            tree.getRoot().setParent(n);
            this.root = n;
            leaf_indices.addAll(tree.getLeafIndices());
            node_count += tree.getNodeCount() + 1;
        }
    }
    
    /** Add the given leaf index to this tree. */
    public void addLeafIndex(int index) { leaf_indices.add(index); }
    
    /** Retrieve the leaf indices list. */
    public List<Integer> getLeafIndices() { return leaf_indices; }
    
}

/** Class TreeNode. */

class TreeNode {

    /** INSTANCE VARIABLES */
    
    /** The value of the node */
    private String value;
    /** The list of gaps added to align the value */
    private List<Integer> gaps;
    /** The parent node */
    private TreeNode parent;
    /** The left child node */
    private TreeNode left_child;
    /** The right child node */
    private TreeNode right_child;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    TreeNode() { this(null, null, null); }
    
    /** Create a new tree node with the given value. */
    TreeNode(String value) { this(value, null, null); }
    
    /** Create a new tree node with the given value and the given left and right
     * children. */
    TreeNode(String value, TreeNode left_child, TreeNode right_child) {
        this.value = value;
        this.left_child = left_child;
        this.right_child = right_child;
    }
    
    /** METHODS */
    
    /** Set the given node as left child. */
    void setLeftChild(TreeNode child) {
        left_child = child;
    }
    
    /** Set the given node as right child. */
    void setRightChild(TreeNode child) {
        right_child = child;
    }
    
    /** Set the given node as the parent node. */
    void setParent(TreeNode parent) {
        this.parent = parent;
    }
    
    /** Add the given list of gaps to the gaps required to align this value. */
    void addGaps(List<Integer> gaps) {
		if (gaps == null) return;
        if (this.gaps == null) {
            this.gaps = gaps;
        } else {
            for (Integer i: gaps)
                this.gaps.add(i);
        }
    }
    
    /** Set the value associated with the node. */
    void setValue(String value) { this.value = value; }
    
    /** Retrieve the list of gaps added to align this value. */
    List<Integer> getGaps() { return gaps; }
    
    
    /** Return the value associated with the node. */
    String getValue() { return value; }
    
    /** Return true if the node has a left child, false otherwise. */
    boolean hasLeftChild() { return left_child != null; }
    
    /** Return true if the node has a right child, false otherwise. */
    boolean hasRightChild() { return right_child != null; }
    
    /** Return the left child of the node. */
    TreeNode getLeftChild() { return left_child; }
    
    /** Return the right child of the node. */
    TreeNode getRightChild() { return right_child; }
    
    /** Return the parent of the node. */
    TreeNode getParent() { return parent; }
    
    /** Return true if the node is a leaf (i.e. has no children),
     * false otherwise. */
    boolean isLeaf() { return left_child == null && right_child == null; }
    
    /** Return true if the node is the root (i.e. has no parent),
     * false otherwise. */
    boolean isRoot() { return parent == null; }
    
    /** Returnt the String value of the node, i.e. the value and the gaps and
     * differences associated with the node. */
    public String toString() {
		return new StringBuilder().
			   append("(").
			   append(isRoot() ? "R" : "").
			   append(isLeaf() ? "L" : "").
			   append(!isLeaf() ? "I" : "").
			   append(")").
			   append(value).
			   append(" ").
			   append(gaps).toString();
	}

}
