/* wmem_tree.c
 * Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <glib.h>

#include "wmem-int.h"
#include "wmem_core.h"
#include "wmem_strutl.h"
#include "wmem_tree.h"
#include "wmem_tree-int.h"
#include "wmem_user_cb.h"

static wmem_tree_node_t *
node_uncle(wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent;

    parent = node->parent;
    if (parent == NULL) {
        return NULL;
    }

    grandparent = parent->parent;
    if (grandparent == NULL) {
        return NULL;
    }

    if (parent == grandparent->left) {
        return grandparent->right;
    }
    else {
        return grandparent->left;
    }
}

static void rb_insert_case1(wmem_tree_t *tree, wmem_tree_node_t *node);
static void rb_insert_case2(wmem_tree_t *tree, wmem_tree_node_t *node);

static void
rotate_left(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    if (node->parent) {
        if (node->parent->left == node) {
            node->parent->left = node->right;
        }
        else {
            node->parent->right = node->right;
        }
    }
    else {
        tree->root = node->right;
    }

    node->right->parent = node->parent;
    node->parent        = node->right;
    node->right         = node->right->left;
    if (node->right) {
        node->right->parent = node;
    }
    node->parent->left = node;

    if (tree->post_rotation_cb) {
        tree->post_rotation_cb (node);
    }
}

static void
rotate_right(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    if (node->parent) {
        if (node->parent->left == node) {
            node->parent->left = node->left;
        }
        else {
            node->parent->right = node->left;
        }
    }
    else {
        tree->root = node->left;
    }

    node->left->parent = node->parent;
    node->parent       = node->left;
    node->left         = node->left->right;
    if (node->left) {
        node->left->parent = node;
    }
    node->parent->right = node;


    if (tree->post_rotation_cb) {
        tree->post_rotation_cb (node);
    }
}

static void
rb_insert_case5(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent;

    parent      = node->parent;
    grandparent = parent->parent;

    parent->color      = WMEM_NODE_COLOR_BLACK;
    grandparent->color = WMEM_NODE_COLOR_RED;

    if (node == parent->left && parent == grandparent->left) {
        rotate_right(tree, grandparent);
    }
    else {
        rotate_left(tree, grandparent);
    }
}

static void
rb_insert_case4(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent;

    parent      = node->parent;
    grandparent = parent->parent;
    if (!grandparent) {
        return;
    }

    if (node == parent->right && parent == grandparent->left) {
        rotate_left(tree, parent);
        node = node->left;
    }
    else if (node == parent->left && parent == grandparent->right) {
        rotate_right(tree, parent);
        node = node->right;
    }

    rb_insert_case5(tree, node);
}

static void
rb_insert_case3(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent, *uncle;

    uncle = node_uncle(node);

    if (uncle && uncle->color == WMEM_NODE_COLOR_RED) {
        parent      = node->parent;
        grandparent = parent->parent;

        parent->color      = WMEM_NODE_COLOR_BLACK;
        uncle->color       = WMEM_NODE_COLOR_BLACK;
        grandparent->color = WMEM_NODE_COLOR_RED;

        rb_insert_case1(tree, grandparent);
    }
    else {
        rb_insert_case4(tree, node);
    }
}

static void
rb_insert_case2(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    /* parent is always non-NULL here */
    if (node->parent->color == WMEM_NODE_COLOR_RED) {
        rb_insert_case3(tree, node);
    }
}

static void
rb_insert_case1(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent = node->parent;

    if (parent == NULL) {
        node->color = WMEM_NODE_COLOR_BLACK;
    }
    else {
        rb_insert_case2(tree, node);
    }
}

static void
rb_remove_doubleblack(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent = node->parent;
    wmem_tree_node_t *sib, *c_nephew, *d_nephew;
    bool left;

    ws_assert(parent);
    if (node == parent->left) {
        left = true;
        parent->left = NULL;
    } else {
        left = false;
        parent->right = NULL;
    }

    for (node = NULL; parent; parent = node->parent) {
        if (node) {
            left = (node == parent->left);
        }
        if (left) {
            sib = parent->right;
            c_nephew = sib->left;
            d_nephew = sib->right;
        } else {
            sib = parent->left;
            c_nephew = sib->right;
            d_nephew = sib->left;
        }
        if (sib && sib->color == WMEM_NODE_COLOR_RED) {
            // Sib red
            goto case_d3;
        } else if (d_nephew && d_nephew->color == WMEM_NODE_COLOR_RED) {
            // D red, Sib black
            goto case_d6;
        } else if (c_nephew && c_nephew->color == WMEM_NODE_COLOR_RED) {
            // C red, Sib, D black
            goto case_d5;
        } else if (parent->color == WMEM_NODE_COLOR_RED) {
            // Parent red, Sib, D, C black
            goto case_d4;
        } else {
            // All black
            sib->color = WMEM_NODE_COLOR_RED;
            node = parent;
        }
    }

    return;

case_d3:
    if (left) {
        rotate_left(tree, parent);
    } else {
        rotate_right(tree, parent);
    }
    parent->color = WMEM_NODE_COLOR_RED;
    sib->color = WMEM_NODE_COLOR_BLACK;
    sib = c_nephew;
    d_nephew = left ? sib->right : sib->left;
    if (d_nephew && d_nephew->color == WMEM_NODE_COLOR_RED)
        goto case_d6;
    c_nephew = left ? sib->left : sib->right;
    if (c_nephew && c_nephew->color == WMEM_NODE_COLOR_RED)
        goto case_d5;

case_d4:
    sib->color = WMEM_NODE_COLOR_RED;
    parent->color = WMEM_NODE_COLOR_BLACK;
    return;

case_d5:
    if (left) {
        rotate_right(tree, sib);
    } else {
        rotate_left(tree, sib);
    }
    sib->color = WMEM_NODE_COLOR_RED;
    c_nephew->color = WMEM_NODE_COLOR_BLACK;
    d_nephew = sib;
    sib = c_nephew;
    // D red and sib black;

case_d6:
    if (left) {
        rotate_left(tree, parent);
    } else {
        rotate_right(tree, parent);
    }
    sib->color = parent->color;
    parent->color = WMEM_NODE_COLOR_BLACK;
    d_nephew->color = WMEM_NODE_COLOR_BLACK;
    return;
}

static void
rb_remove_node(wmem_tree_t *tree, wmem_tree_node_t *node, bool free_key)
{
    wmem_tree_node_t *temp_node;
    /* First, if the node has both children, swap the key and data
     * with the in-order successor and delete that node instead.
     */
    if (node->left && node->right) {
        temp_node = node->right;
        while (temp_node->left) {
            temp_node = temp_node->left;
        }
        node->key = temp_node->key;
        node->data = temp_node->data;
        node = temp_node;
    }

    wmem_node_color_t child_color = WMEM_NODE_COLOR_BLACK;
    /* node now has one child at most. */
    if (node->left) {
        temp_node = node->left;
        ws_assert(node->right == NULL);
    } else {
        temp_node = node->right;
    }
    /* If there is a child, then the child must be red and original
     * node black, or else the R-B tree assumptions are wrong and
     * there's a problem elsewhere in the code. */
    if (temp_node) {
        child_color = temp_node->color;
        ws_assert(child_color == WMEM_NODE_COLOR_RED);
        ws_assert(node->color == WMEM_NODE_COLOR_BLACK);
        temp_node->parent = node->parent;
        temp_node->color = WMEM_NODE_COLOR_BLACK;
    }

    if (temp_node == NULL &&
        node->color == WMEM_NODE_COLOR_BLACK && node->parent) {

        /* Removing will create a "double black" imbalance in the tree and
         * we will need to rectify it to keep this a R-B tree.
         * This function removes and does any necessary rotations.
         */
        rb_remove_doubleblack(tree, node);
    } else {
        // Now remove the node from the tree.
        if (node->parent) {
            if (node == node->parent->left) {
                node->parent->left = temp_node;
            } else {
                node->parent->right = temp_node;
            }
        } else {
            tree->root = temp_node;
        }
    }

    /* Freeing memory is only strictly necessary for a NULL allocator.
     * The key is copied in a string tree, a GUINT_TO_POINTER in a
     * 32 bit integer tree, and used uncopied in a generic tree, so
     * it should be freed in the first case but not the others.
     * The value is returned, so not freed under any circumstance.
     */
    if (free_key) {
        wmem_free(tree->data_allocator, (void *)node->key);
    }
    wmem_free(tree->data_allocator, node);
}

wmem_tree_t *
wmem_tree_new(wmem_allocator_t *allocator)
{
    wmem_tree_t *tree;

    tree = wmem_new0(allocator, wmem_tree_t);
    tree->metadata_allocator    = allocator;
    tree->data_allocator = allocator;

    return tree;
}

static bool
wmem_tree_reset_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event,
        void *user_data)
{
    wmem_tree_t *tree = (wmem_tree_t *)user_data;

    tree->root = NULL;

    if (event == WMEM_CB_DESTROY_EVENT) {
        wmem_unregister_callback(tree->metadata_allocator, tree->metadata_scope_cb_id);
        wmem_free(tree->metadata_allocator, tree);
    }

    return true;
}

static bool
wmem_tree_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data)
{
    wmem_tree_t *tree = (wmem_tree_t *)user_data;

    wmem_unregister_callback(tree->data_allocator, tree->data_scope_cb_id);

    return false;
}

wmem_tree_t *
wmem_tree_new_autoreset(wmem_allocator_t *metadata_scope, wmem_allocator_t *data_scope)
{
    wmem_tree_t *tree;

    tree = wmem_new0(metadata_scope, wmem_tree_t);
    tree->metadata_allocator = metadata_scope;
    tree->data_allocator = data_scope;

    tree->metadata_scope_cb_id = wmem_register_callback(metadata_scope, wmem_tree_destroy_cb,
            tree);
    tree->data_scope_cb_id  = wmem_register_callback(data_scope, wmem_tree_reset_cb,
            tree);

    return tree;
}

static void
free_tree_node(wmem_allocator_t *allocator, wmem_tree_node_t* node, bool free_keys, bool free_values)
{
    if (node == NULL) {
        return;
    }

    if (node->left) {
        free_tree_node(allocator, node->left, free_keys, free_values);
    }

    if (node->is_subtree) {
        wmem_tree_destroy((wmem_tree_t *)node->data, free_keys, free_values);
        node->data = NULL;
    }

    if (node->right) {
        free_tree_node(allocator, node->right, free_keys, free_values);
    }

    if (free_keys) {
        wmem_free(allocator, (void*)node->key);
    }

    if (free_values) {
        wmem_free(allocator, node->data);
    }
    wmem_free(allocator, node);
}

void
wmem_tree_destroy(wmem_tree_t *tree, bool free_keys, bool free_values)
{
    free_tree_node(tree->data_allocator, tree->root, free_keys, free_values);
    if (tree->metadata_allocator) {
        wmem_unregister_callback(tree->metadata_allocator, tree->metadata_scope_cb_id);
    }
    if (tree->data_allocator) {
        wmem_unregister_callback(tree->data_allocator, tree->data_scope_cb_id);
    }
    wmem_free(tree->metadata_allocator, tree);
}

bool
wmem_tree_is_empty(wmem_tree_t *tree)
{
    return tree->root == NULL;
}

static bool
count_nodes(const void *key _U_, void *value _U_, void *userdata)
{
    unsigned* count = (unsigned*)userdata;
    (*count)++;
    return false;
}

unsigned
wmem_tree_count(wmem_tree_t* tree)
{
    unsigned count = 0;

    /* Recursing through the tree counting each node is the simplest approach.
       We don't keep track of the count within the tree because it can get
       complicated with subtrees within the tree */
    wmem_tree_foreach(tree, count_nodes, &count);

    return count;
}

static wmem_tree_node_t *
create_node(wmem_allocator_t *allocator, wmem_tree_node_t *parent, const void *key,
        void *data, wmem_node_color_t color, bool is_subtree)
{
    wmem_tree_node_t *node;

    node = wmem_new(allocator, wmem_tree_node_t);

    node->left   = NULL;
    node->right  = NULL;
    node->parent = parent;

    node->key  = key;
    node->data = data;

    node->color      = color;
    node->is_subtree = is_subtree;
    node->is_removed = false;

    return node;
}

#define CREATE_DATA(TRANSFORM, DATA) ((TRANSFORM) ? (TRANSFORM)(DATA) : (DATA))


/**
 * return inserted node
 */
static wmem_tree_node_t *
lookup_or_insert32_node(wmem_tree_t *tree, uint32_t key,
        void*(*func)(void*), void* data, bool is_subtree, bool replace)
{
    wmem_tree_node_t *node     = tree->root;
    wmem_tree_node_t *new_node = NULL;

    /* is this the first node ?*/
    if (!node) {
        new_node = create_node(tree->data_allocator, NULL, GUINT_TO_POINTER(key),
                CREATE_DATA(func, data), WMEM_NODE_COLOR_BLACK, is_subtree);
        tree->root = new_node;
        return new_node;
    }

    /* it was not the new root so walk the tree until we find where to
     * insert this new leaf.
     */
    while (!new_node) {
        /* this node already exists, so just return the data pointer*/
        if (key == GPOINTER_TO_UINT(node->key)) {
            if (replace) {
                node->data = CREATE_DATA(func, data);
            }
            return node;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            if (node->left) {
                node = node->left;
            }
            else {
                /* new node to the left */
                new_node = create_node(tree->data_allocator, node, GUINT_TO_POINTER(key),
                        CREATE_DATA(func, data), WMEM_NODE_COLOR_RED,
                        is_subtree);
                node->left = new_node;
            }
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            if (node->right) {
                node = node->right;
            }
            else {
                /* new node to the right */
                new_node = create_node(tree->data_allocator, node, GUINT_TO_POINTER(key),
                        CREATE_DATA(func, data), WMEM_NODE_COLOR_RED,
                        is_subtree);
                node->right = new_node;
            }
        }
    }

    /* node will now point to the newly created node */
    rb_insert_case1(tree, new_node);

    return new_node;
}


static void *
lookup_or_insert32(wmem_tree_t *tree, uint32_t key,
        void*(*func)(void*), void* data, bool is_subtree, bool replace)
{
    wmem_tree_node_t *node = lookup_or_insert32_node(tree, key, func, data, is_subtree, replace);
    return node->data;
}

static void *
wmem_tree_lookup(wmem_tree_t *tree, const void *key, compare_func cmp)
{
    wmem_tree_node_t *node;

    if (tree == NULL || key == NULL) {
        return NULL;
    }

    node = tree->root;

    while (node) {
        int result = cmp(key, node->key);
        if (result == 0) {
            return node->data;
        }
        else if (result < 0) {
            node = node->left;
        }
        else if (result > 0) {
            node = node->right;
        }
    }

    return NULL;
}

wmem_tree_node_t *
wmem_tree_insert_node(wmem_tree_t *tree, const void *key, void *data, compare_func cmp)
{
    wmem_tree_node_t *node = tree->root;
    wmem_tree_node_t *new_node = NULL;

    /* is this the first node ?*/
    if (!node) {
        tree->root = create_node(tree->data_allocator, node, key,
                data, WMEM_NODE_COLOR_BLACK, false);
        return tree->root;
    }

    /* it was not the new root so walk the tree until we find where to
     * insert this new leaf.
     */
    while (!new_node) {
        int result = cmp(key, node->key);
        if (result == 0) {
            node->data = data;
            node->is_removed = data ? false : true;
            return node;
        }
        else if (result < 0) {
            if (node->left) {
                node = node->left;
            }
            else {
                new_node = create_node(tree->data_allocator, node, key,
                        data, WMEM_NODE_COLOR_RED, false);
                node->left = new_node;
            }
        }
        else if (result > 0) {
            if (node->right) {
                node = node->right;
            }
            else {
                /* new node to the right */
                new_node = create_node(tree->data_allocator, node, key,
                        data, WMEM_NODE_COLOR_RED, false);
                node->right = new_node;
            }
        }
    }

    /* node will now point to the newly created node */
    rb_insert_case1(tree, new_node);

    return new_node;
}

void
wmem_tree_insert32(wmem_tree_t *tree, uint32_t key, void *data)
{
    lookup_or_insert32(tree, key, NULL, data, false, true);
}

bool wmem_tree_contains32(wmem_tree_t *tree, uint32_t key)
{
    if (!tree) {
        return false;
    }

    wmem_tree_node_t *node = tree->root;

    while (node) {
        if (key == GPOINTER_TO_UINT(node->key)) {
            return true;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            node = node->left;
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            node = node->right;
        }
    }

    return false;
}

static wmem_tree_node_t*
wmem_tree_lookup32_node(wmem_tree_t *tree, uint32_t key)
{
    if (!tree) {
        return NULL;
    }

    wmem_tree_node_t *node = tree->root;

    while (node) {
        if (key == GPOINTER_TO_UINT(node->key)) {
            return node;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            node = node->left;
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            node = node->right;
        }
    }

    return NULL;
}

void *
wmem_tree_lookup32(wmem_tree_t *tree, uint32_t key)
{
    wmem_tree_node_t *node = wmem_tree_lookup32_node(tree, key);
    if (node == NULL) {
        return NULL;
    }
    return node->data;
}

static wmem_tree_node_t*
wmem_tree_lookup32_le_node(wmem_tree_t *tree, uint32_t key)
{
    if (!tree) {
        return NULL;
    }

    wmem_tree_node_t *node = tree->root;

    while (node) {
        if (key == GPOINTER_TO_UINT(node->key)) {
            return node;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            if (node->left == NULL) {
                break;
            }
            node = node->left;
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            if (node->right == NULL) {
                break;
            }
            node = node->right;
        }
    }

    if (!node) {
        return NULL;
    }

    /* If we are still at the root of the tree this means that this node
     * is either smaller than the search key and then we return this
     * node or else there is no smaller key available and then
     * we return NULL.
     */
    if (node->parent == NULL) {
        if (key > GPOINTER_TO_UINT(node->key)) {
            return node;
        } else {
            return NULL;
        }
    }

    if (GPOINTER_TO_UINT(node->key) <= key) {
        /* if our key is <= the search key, we have the right node */
        return node;
    }
    else if (node == node->parent->left) {
        /* our key is bigger than the search key and we're a left child,
         * we have to check if any of our ancestors are smaller. */
        while (node) {
            if (key > GPOINTER_TO_UINT(node->key)) {
                return node;
            }
            node=node->parent;
        }
        return NULL;
    }
    else {
        /* our key is bigger than the search key and we're a right child,
         * our parent is the one we want */
        return node->parent;
    }
}

void *
wmem_tree_lookup32_le(wmem_tree_t *tree, uint32_t key)
{
    wmem_tree_node_t *node = wmem_tree_lookup32_le_node(tree, key);
    if (node == NULL) {
        return NULL;
    }

    return node->data;
}

void *
wmem_tree_lookup32_le_full(wmem_tree_t *tree, uint32_t key, uint32_t *orig_key)
{
    wmem_tree_node_t *node = wmem_tree_lookup32_le_node(tree, key);
    if (node == NULL) {
        return NULL;
    }

    *orig_key = GPOINTER_TO_UINT(node->key);
    return node->data;
}

static wmem_tree_node_t*
wmem_tree_lookup32_ge_node(wmem_tree_t *tree, uint32_t key)
{
    if (!tree) {
        return NULL;
    }

    wmem_tree_node_t *node = tree->root;

    while (node) {
        if (key == GPOINTER_TO_UINT(node->key)) {
            return node;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            if (node->left == NULL) {
                break;
            }
            node = node->left;
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            if (node->right == NULL) {
                break;
            }
            node = node->right;
        }
    }

    if (!node) {
        return NULL;
    }

    /* If we are still at the root of the tree this means that this node
     * is either greater than the search key and then we return this
     * node or else there is no greater key available and then
     * we return NULL.
     */
    if (node->parent == NULL) {
        if (key < GPOINTER_TO_UINT(node->key)) {
            return node;
        } else {
            return NULL;
        }
    }

    if (GPOINTER_TO_UINT(node->key) >= key) {
        /* if our key is >= the search key, we have the right node */
        return node;
    }
    else if (node == node->parent->right) {
        /* our key is smaller than the search key and we're a right child,
         * we have to check if any of our ancestors are bigger. */
        while (node) {
            if (key < GPOINTER_TO_UINT(node->key)) {
                return node;
            }
            node=node->parent;
        }
        return NULL;
    }
    else {
        /* our key is smaller than the search key and we're a left child,
         * our parent is the one we want */
        return node->parent;
    }
}

void *
wmem_tree_lookup32_ge(wmem_tree_t *tree, uint32_t key)
{
    wmem_tree_node_t *node = wmem_tree_lookup32_ge_node(tree, key);
    if (node == NULL) {
        return NULL;
    }

    return node->data;
}

void *
wmem_tree_lookup32_ge_full(wmem_tree_t *tree, uint32_t key, uint32_t *orig_key)
{
    wmem_tree_node_t *node = wmem_tree_lookup32_ge_node(tree, key);
    if (node == NULL) {
        return NULL;
    }

    *orig_key = GPOINTER_TO_UINT(node->key);
    return node->data;
}

void *
wmem_tree_remove32(wmem_tree_t *tree, uint32_t key)
{
    wmem_tree_node_t *node = wmem_tree_lookup32_node(tree, key);
    if (node == NULL) {
        return NULL;
    }

    void *ret = node->data;

    /* Remove the node. Do not free the key, because it is a
     * GPOINTER_TO_UINT. The value we return.
     */
    rb_remove_node(tree, node, false);

    return ret;
}

void
wmem_tree_insert_string(wmem_tree_t* tree, const char* k, void* v, uint32_t flags)
{
    char *key;
    compare_func cmp;

    key = wmem_strdup(tree->data_allocator, k);

    if (flags & WMEM_TREE_STRING_NOCASE) {
        cmp = (compare_func)g_ascii_strcasecmp;
    } else {
        cmp = (compare_func)strcmp;
    }

    wmem_tree_insert_node(tree, key, v, cmp);
}

void *
wmem_tree_lookup_string(wmem_tree_t* tree, const char* k, uint32_t flags)
{
    compare_func cmp;

    if (flags & WMEM_TREE_STRING_NOCASE) {
        cmp = (compare_func)g_ascii_strcasecmp;
    } else {
        cmp = (compare_func)strcmp;
    }

    return wmem_tree_lookup(tree, k, cmp);
}

void *
wmem_tree_remove_string(wmem_tree_t* tree, const char* k, uint32_t flags)
{
    void *ret = wmem_tree_lookup_string(tree, k, flags);
    if (ret) {
        /* Not really a remove, but set data to NULL to mark node with is_removed */
        wmem_tree_insert_string(tree, k, NULL, flags);
    }
    return ret;
}

static void *
create_sub_tree(void* d)
{
    return wmem_tree_new(((wmem_tree_t *)d)->data_allocator);
}

void
wmem_tree_insert32_array(wmem_tree_t *tree, wmem_tree_key_t *key, void *data)
{
    wmem_tree_t *insert_tree = NULL;
    wmem_tree_key_t *cur_key;
    uint32_t i, insert_key32 = 0;

    for (cur_key = key; cur_key->length > 0; cur_key++) {
        for (i = 0; i < cur_key->length; i++) {
            /* Insert using the previous key32 */
            if (!insert_tree) {
                insert_tree = tree;
            } else {
                insert_tree = (wmem_tree_t *)lookup_or_insert32(insert_tree,
                        insert_key32, create_sub_tree, tree, true, false);
            }
            insert_key32 = cur_key->key[i];
        }
    }

    ws_assert(insert_tree);

    wmem_tree_insert32(insert_tree, insert_key32, data);
}

static void *
wmem_tree_lookup32_array_helper(wmem_tree_t *tree, wmem_tree_key_t *key,
        void*(*helper)(wmem_tree_t*, uint32_t))
{
    wmem_tree_t *lookup_tree = NULL;
    wmem_tree_key_t *cur_key;
    uint32_t i, lookup_key32 = 0;

    if (!tree || !key) {
        return NULL;
    }

    for (cur_key = key; cur_key->length > 0; cur_key++) {
        for (i = 0; i < cur_key->length; i++) {
            /* Lookup using the previous key32 */
            if (!lookup_tree) {
                lookup_tree = tree;
            }
            else {
                lookup_tree =
                    (wmem_tree_t *)(*helper)(lookup_tree, lookup_key32);
                if (!lookup_tree) {
                    return NULL;
                }
            }
            lookup_key32 = cur_key->key[i];
        }
    }

    /* Assert if we didn't get any valid keys */
    ws_assert(lookup_tree);

    return (*helper)(lookup_tree, lookup_key32);
}

void *
wmem_tree_lookup32_array(wmem_tree_t *tree, wmem_tree_key_t *key)
{
    return wmem_tree_lookup32_array_helper(tree, key, wmem_tree_lookup32);
}

void *
wmem_tree_lookup32_array_le(wmem_tree_t *tree, wmem_tree_key_t *key)
{
    return wmem_tree_lookup32_array_helper(tree, key, wmem_tree_lookup32_le);
}

static bool
wmem_tree_foreach_nodes(wmem_tree_node_t* node, wmem_foreach_func callback,
        void *user_data)
{
    bool stop_traverse = false;

    if (!node) {
        return false;
    }

    if (node->left) {
        if (wmem_tree_foreach_nodes(node->left, callback, user_data)) {
            return true;
        }
    }

    if (node->is_subtree) {
        stop_traverse = wmem_tree_foreach((wmem_tree_t *)node->data,
                callback, user_data);
    } else if (!node->is_removed) {
        /* No callback for "removed" nodes */
        stop_traverse = callback(node->key, node->data, user_data);
    }

    if (stop_traverse) {
        return true;
    }

    if(node->right) {
        if (wmem_tree_foreach_nodes(node->right, callback, user_data)) {
            return true;
        }
    }

    return false;
}

bool
wmem_tree_foreach(wmem_tree_t* tree, wmem_foreach_func callback,
        void *user_data)
{
    if(!tree->root)
        return false;

    return wmem_tree_foreach_nodes(tree->root, callback, user_data);
}

static void wmem_print_subtree(wmem_tree_t *tree, uint32_t level, wmem_printer_func key_printer, wmem_printer_func data_printer);

static void
wmem_print_indent(uint32_t level) {
    uint32_t i;
    for (i=0; i<level; i++) {
        printf("    ");
    }
}

static void
wmem_tree_print_nodes(const char *prefix, wmem_tree_node_t *node, uint32_t level,
    wmem_printer_func key_printer, wmem_printer_func data_printer)
{
    if (!node)
        return;

    wmem_print_indent(level);

    printf("%sNODE:%p parent:%p left:%p right:%p colour:%s key:%p %s:%p\n",
            prefix,
            (void *)node, (void *)node->parent,
            (void *)node->left, (void *)node->right,
            node->color?"Black":"Red", node->key,
            node->is_subtree?"tree":"data", node->data);
    if (key_printer) {
        wmem_print_indent(level);
        key_printer(node->key);
        printf("\n");
    }
    if (data_printer && !node->is_subtree) {
        wmem_print_indent(level);
        data_printer(node->data);
        printf("\n");
    }

    if (node->left)
        wmem_tree_print_nodes("L-", node->left, level+1, key_printer, data_printer);
    if (node->right)
        wmem_tree_print_nodes("R-", node->right, level+1, key_printer, data_printer);

    if (node->is_subtree)
        wmem_print_subtree((wmem_tree_t *)node->data, level+1, key_printer, data_printer);
}


static void
wmem_print_subtree(wmem_tree_t *tree, uint32_t level, wmem_printer_func key_printer, wmem_printer_func data_printer)
{
    if (!tree)
        return;

    wmem_print_indent(level);

    printf("WMEM tree:%p root:%p\n", (void *)tree, (void *)tree->root);
    if (tree->root) {
        wmem_tree_print_nodes("Root-", tree->root, level, key_printer, data_printer);
    }
}

void
wmem_print_tree(wmem_tree_t *tree, wmem_printer_func key_printer, wmem_printer_func data_printer)
{
    wmem_print_subtree(tree, 0, key_printer, data_printer);
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
