/* hpot_support.h       <<-- A template
 * Huzefa Dossaji        <<-- some changes needed
 * hdossaj
 * ECE 223 Fall 2015 
 * MP3
 *
 * Propose: A template for MP2. The data structures for the specific format of the packet records, and the prototype
 *   definitions.
 *
 * Assumptions: suggested structure definitions and public functions 
 *              as defined for assignmnet.  
 *
 *              You may change this file if needed for your design.
 *
 * Bugs: THERE ARE NO BUGS DETECTED EVEN WITH ALL MY EXTENSIVE TESTING
 *
 */

#define MAXLINE 170

/* prototype function definitions */

/* function to compare packet records */
int hpot_compare(const packet_t *rec_a, const packet_t *rec_b);

/* functions to create and cleanup a Honeypot list */
pList hpot_create(char *);
void hpot_cleanup(pList);

/* Functions to get and print packet information */
void hpot_print(pList list_ptr, char *); /* print list of records */
void hpot_stats(pList, pList, pList);            /* prints size of each list */

/* functions for sorted list */
void hpot_add(pList , int);
void hpot_list(pList , int);
void hpot_remove(pList , int);
void hpot_scan(pList , int);
void hpot_scan_MP3(pList list_ptr, int thresh); // Made for effeciency for MP3

/* functions for unsorted list 
 * inserts at the tail, removes at the head, 
 * Duplicate packets with the same destination IP address are not
 * permitted.  If a new packet is inserted the old one must be 
 * recycled
 */
void hpot_add_tail(pList, int);
void hpot_remove_head(pList );

// function just to call list.c function (list_sort)
void hpot_sort(pList, int);
// function to add to the end of the third list without removing multiples. used for appendl
void hpot_add_tail_append(pList , int );

/* commands for vim. ts: tabstop, sts: soft tabstop sw: shiftwidth */
/* vi:set ts=8 sts=4 sw=4 et: */
