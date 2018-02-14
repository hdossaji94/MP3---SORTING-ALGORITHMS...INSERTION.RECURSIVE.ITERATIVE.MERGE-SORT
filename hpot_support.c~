/* hpot_support.c         <<-- A template 
 * Huzefa Dossaji         <<-- many updates required
 * hdossaj
 * ECE 223 Fall 2015 
 * MP3
 *
 * Propose: A template for MP2, CONTAINS SUBROUTINES THAT SUPPORT HANDLING OF PACKET RECORDS 
 *
 * Assumptions: There are many inputs that the functions in this code will accept, it can be packet_t structures, it can be node_t structures
 * most of the functions have the list as one of the inputs so you can modify it. 
 *
 * Bugs: THERE ARE NO BUGS DETECTED EVEN WITH ALL MY EXTENSIVE TESTING
 *
 * You can modify the interface for any of the hpot_ functions if you like
 * But you must clearly document your changes.
 *
 * (You CANNOT modify any of the details of the list.h interface, or use any 
 *  of the private variables outside of list.c.)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "datatypes.h"
#include "list.h"
#include "hpot_support.h"

// private functions for use in hpot_support.c only
void hpot_record_fill(packet_t *rec);   /* collect input from user */
void hpot_record_print(packet_t *rec);  /* print one record */

/* hpot_compare is required by the list ADT for sorted lists. 
 *
 * This function returns 
 *     1 if rec_a should be closer to the head than rec_b,
 *    -1 if rec_b is to be considered closer to the head, and 
 *     0 if the records are equal.
 *
 * For the packet data we want to sort from lowest IP address up, so
 * closer to the front means a smaller IP address.
 *
 * The function expects pointers to two record structures, and it is an error
 * if either is NULL
 *
 * THIS FUNCTION SHOULD NOT BE CHANGED
 */
int hpot_compare(const packet_t *record_a, const packet_t *record_b)
{
    assert(record_a != NULL && record_b !=NULL);
    if (record_a->dest_ip_addr < record_b->dest_ip_addr)
        return 1;
    else if (record_a->dest_ip_addr > record_b->dest_ip_addr)
        return -1;
    else
        return 0;
}

/* This functions reads in the information from the user for the packet 
 * record.  It assumes that the memory block for the record has been malloced
 * and the dest ip address has been set. 
 *
 * Do not change the sequence of prompts as grading requires this exact
 * format
 */
void hpot_record_fill(packet_t *new)
{
    char line[MAXLINE];
    assert(new != NULL);

    printf("Source IP address:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->src_ip_addr);
    printf("Destination port number:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->dest_port_num);
    printf("Source port number:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->src_port_num);
    printf("Hop count:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->hop_count);
    printf("Protocol:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->protocol);
    printf("Threat Score:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%f", &new->threat_score);
    printf("Time:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->time_received);
    printf("\n");
}

/* print the information for a particular record 
 *
 * Input is a pointer to a record, and no entries are changed.
 *
 * Do not change any of these lines and grading depends on this
 * format.
 */
void hpot_record_print(packet_t *rec)
{
    assert(rec != NULL);
    printf("Dest IP: %d, Src: %d, Dest port: %d,", rec->dest_ip_addr, 
            rec->src_ip_addr, rec->dest_port_num);
    printf(" Src: %d, Hop Count: %d", rec->src_port_num, rec->hop_count); 
    printf(" Prot: %d", rec->protocol);
    printf(" Score: %g, Time: %d\n", rec->threat_score, rec->time_received);
}

/* print one of the packet record lists
 *
 * inputs: 
 *    list_ptr: a pList pointer to either sorted or unsorted list
 *
 *    type_of_list: a charter string that must be either "List" or "Queue"
 *
 * output: prints the list in the format required for grading.
 *         Do not change any of these lines 
 */
void hpot_print(pList list_ptr, char *list_type)
{
    assert(strcmp(list_type, "List")==0 || strcmp(list_type, "Queue")==0 || strcmp(list_type, "Priority") == 0);
    pIterator index;
    int counter = 0;

    index = list_iter_first(list_ptr);
    while (index != list_iter_tail(list_ptr))
    {
        printf("%d: ", ++counter);
        hpot_record_print(list_access(list_ptr, index));
        index = list_iter_next(index);
    }
    if (counter == 0) {
        printf("%s is empty\n", list_type);
    } else {
        printf("%s contains %d record%s\n", list_type, counter,
                counter==1 ? "." : "s.");
    }
    printf("\n");
}

/* This functions adds a packet record to the tail of a list.  The list is
 * unsorted, and it does not have any limits on the maximum size of the list.
 *
 * If the new packet has the same destination IP address as a packet that is
 * already in the list, the old matching packet is removed from the list and 
 * recycled.  The new packet is appended to the end of the list.
 */
void hpot_add_tail(pList list_ptr, int destination_ip_address)
{
    packet_t * new = NULL;
    new = (packet_t*)malloc(sizeof(packet_t));
    new->dest_ip_addr = destination_ip_address;
    hpot_record_fill(new);
   
    
    
    
    // INSERTS NEW PACKET AT THE TAIL IF NO OTHER PACKET WITHT THE SAME DEST IP IS FOUND
    if(list_elem_find(list_ptr, new)==NULL)
    {
        list_insert(list_ptr, new, list_iter_tail(list_ptr));
        printf("Appended %d onto queue\n", destination_ip_address);
    }
    // INSERTS NEW PACKET AT THE TAIL AFTER REMOVING MATCHING PACKET
    else{
        
        free(list_remove(list_ptr, list_elem_find(list_ptr, new)));
        list_insert(list_ptr, new, list_iter_tail(list_ptr));
        printf("Appended %d onto queue and removed old copy\n", destination_ip_address);
    }
    
    
}


// Function for just appendl to add the packets at the end without removing multiple packets. 

void hpot_add_tail_append(pList list_ptr, int destination_ip_address)
{
    packet_t * new = NULL;
    new = (packet_t*)calloc(1,sizeof(packet_t)); //changed to calloc to allow valgrind to not say unitalized values
    new->dest_ip_addr = destination_ip_address;
    //hpot_record_fill(new);     //commented out for large input file testing. 
    
         list_insert(list_ptr, new, list_iter_tail(list_ptr));
      // printf("Appended %d onto queue\n", destination_ip_address);   //commented out for effeciency for MP3
   
}

/* This function removes the packet record at the head of the list.  The
 * list is unsorted, and there is no limit on the maximum size of the list.
 *
 * The packet should be recycled so there are no memory leaks.
 */
void hpot_remove_head(pList list_ptr)
{
    
    packet_t *pkt_ptr = NULL;
    if(list_size(list_ptr)!= 0){
        pkt_ptr = list_remove(list_ptr, list_iter_first(list_ptr));
    }

    if (pkt_ptr != NULL)
        printf("Deleted head with IP addr: %d\n", pkt_ptr->dest_ip_addr);
    else
        printf("Queue empty, did not remove\n");
    free(pkt_ptr);
}

/* This creates a list and it can be either a sorted or unsorted list
 *
 * inputs: 
 *    list_type: a character string that must be either "List" or "Queue"
 *
 * This function is provided to you as an example of how to use a
 * function pointer.  
 *
 * Bug: list_type is not used.  It should be deleted.  The prototype
 *      in hpot_support.h should be updated.  The calls in lab1.c should 
 *      be fixed.
 */
 
 // Was told this char list_type could be left alone as long as it did not create an error in my code. 
pList hpot_create(char *list_type)
{
    return list_construct(hpot_compare);
}

/* This function adds a packet to the sorted list.  
 * If the new packet has the same dest ip address as one or
 * more packets in the list, then the new packet is placed after all the
 * existing packets with the same address. 
 *
 * There is no return value since the insertion must always be 
 * successful, except in the catastrophic condition that the program
 * has run out of memory.
 */

void hpot_add(pList list_ptr, int destination_ip_address)
{
    packet_t * new = NULL;
    new = (packet_t*)malloc(sizeof(packet_t));
    new->dest_ip_addr = destination_ip_address;
    hpot_record_fill(new);
    
    list_insert_sorted(list_ptr, new);
    
    // after the packet is added you must print
    printf("Inserted %d into list\n", destination_ip_address);
    
    new = NULL;
    free(new);
}

/* This function prints all packets with the matching ip_address in the
 * sorted list.  Print all fields of each matching packet record, and 
 * after the last packet print the number found.
 */
void hpot_list(pList list_ptr, int id)
{
    int count = 0;
    
       
    pIterator n1 = NULL;

        
    packet_t * new = NULL;
    new = (packet_t*)malloc(sizeof(packet_t));
    new->dest_ip_addr=id;
   
     
    
    n1 = list_elem_find(list_ptr, new);
 
    
    if(n1 != NULL){
    
    while(n1 != list_iter_tail(list_ptr) ){
    if(list_access(list_ptr, n1)->dest_ip_addr == new->dest_ip_addr){
        hpot_record_print(list_access(list_ptr, n1));
        count++;
    }
      
    n1 = list_iter_next(n1);
    }
    }
    // after printing each matching record, print one of these summaries
    if (count > 0)
        printf("Found %d packets matching %d\n", count, id);
    else
        printf("Did not find: %d\n", id);
        
      
       free(new);
      
}

/* This function removes all packets from the sorted list with the matching
 * dest ip address
 */
void hpot_remove(pList list_ptr, int id)
{
    int count = 0;
   

        
    packet_t * new = NULL;
    new = (packet_t*)malloc(sizeof(packet_t));
    new->dest_ip_addr=id;
    
    
    

    if(list_elem_find(list_ptr, new) !=NULL){
    if(list_size(list_ptr)!=0){
    while(list_elem_find(list_ptr, new) != list_iter_tail(list_ptr)){
    
    if(list_access(list_ptr, list_elem_find(list_ptr, new))->dest_ip_addr == new->dest_ip_addr){
        free(list_remove(list_ptr, list_elem_find(list_ptr, new)));
        count++;
        
    }
      
    
    if(list_elem_find(list_ptr, new) == NULL){
        break;
    }
    }
    }
   } 
    
    if (count > 0)
        printf("Removed %d packets matching %d\n", count, id);
    else
        printf("Did not remove: %d\n", id);
        
        
        free(new);
        
        new = NULL;
        
       
}
// This function scans for a certain threshold. it has conditionals for when the threshold is 0, 1, less than 3, or anything else. It takes a inputted threshold and the list and does not return anythiing
void hpot_scan(pList list_ptr, int thresh)
{
    int count = 1;
    int found_addr = -1;
    int sets = 0;
    int print=0;
    int next_sig=0;
    
    pIterator n1 = NULL;
    
    pIterator n2 = NULL;
    
    
    // WILL ONLY GO INTO THIS GIANT IF STATMENT IF THERE IS ANYTHING IN THE LIST
    if(list_size(list_ptr)!=0){
    
    n1=list_iter_first(list_ptr);
    n2=list_iter_next(n1);
    

    // IF STATEMENT IF THERE IS ONLY ONE PACKET IN THE LIST AND THE THRESHOLD IS 1
    if((list_size(list_ptr) == 1) && (thresh == 1)){
	    found_addr=list_access(list_ptr,n1)->dest_ip_addr;
	    printf("A set with address %d has %d packets\n", found_addr, count);
	    sets++;

    }
    // CONDITIONAL IF THE THRESHOLD IS 1 AND THERE IS MORE THAN ONE PACKET IN THE LIST
    else if(thresh==1){
	    while(n1 != list_iter_tail(list_ptr)){
		    if(list_access(list_ptr,n1)->dest_ip_addr == list_access(list_ptr,n2)->dest_ip_addr){
			    count++;
			    next_sig=1;
		    }
		    else{
			    found_addr=list_access(list_ptr, n1)->dest_ip_addr;
			    n1 = n2;
			    n2 = list_iter_next(n1);
			    next_sig=0;
			    printf("A set with address %d has %d packets\n", found_addr, count);
			    sets++;
			    count=1;

		    }
		    if(next_sig==1){
			    n2 = list_iter_next(n2);
		    }
		    if(n2 == list_iter_tail(list_ptr)){


			    found_addr=list_access(list_ptr, n1)->dest_ip_addr;
			    printf("A set with address %d has %d packets\n", found_addr, count);
			    sets++;
			    break;

		    }

	    }
    }

    // IF STATMENT AND WHILE LOOP FOR THEN THRESHOLD IS BELOW 3. 
    else if(thresh < 3){
	    while(n2 != list_iter_tail(list_ptr)){

		    if(list_access(list_ptr,n1)->dest_ip_addr == list_access(list_ptr,n2)->dest_ip_addr){

			    count++;

			    if(count == thresh  || (thresh == 1 )){
				    found_addr=list_access(list_ptr,n1)->dest_ip_addr;
			    }
			    next_sig=1;
		    }
		    else{
			    n1 = n2;
			    n2 = list_iter_next(n1);
			    if(found_addr != -1){
				    print = 1;
			    }
			    next_sig=0;

		    }
		    if((found_addr != -1) && (print == 1)){
			    printf("A set with address %d has %d packets\n", found_addr, count);
			    found_addr = -1;

			    print = 0;
			    count = 1;
			    sets++;
		    }
		    if(next_sig ==1){
			    n2 = list_iter_next(n2);
		    }

		    if(n2 == list_iter_tail(list_ptr)){
			    if(found_addr != -1){
				    printf("A set with address %d has %d packets\n", found_addr, count);
				    sets++;
				    break;
			    }
		    }
	    }
    }
    // IF STATEMENT AND WHILE LOOP FOR THEN THE THRESHOLD IS GREATER THAN OR EQUAL TO 3. EXACT SAME THING EXCEPT COUNT STARTS AT 0
    else if(thresh>=3){
	    count = 1;
	    int count2 = 0;
	    while(n2 != list_iter_tail(list_ptr)){

		    if(list_access(list_ptr,n1)->dest_ip_addr == list_access(list_ptr,n2)->dest_ip_addr){

			    count++;

			    if(count == thresh  || (thresh ==1 )){
				    found_addr=list_access(list_ptr,n1)->dest_ip_addr;
			    }
			    next_sig=1;
		    }
		    else{
			    n1 = n2;
			    n2 = list_iter_next(n1);
			    count2 = count;
			    count = 1;
			    if(found_addr != -1){
				    print = 1;
			    }
			    next_sig=0;
			    if(n2 != list_iter_tail(list_ptr)){
			    if(list_access(list_ptr,n1)->dest_ip_addr != list_access(list_ptr,n2)->dest_ip_addr){
				    count=1;
			    }

                            }
		    }
		    if((found_addr != -1) && (print == 1)){
			    printf("A set with address %d has %d packets\n", found_addr, count2);
			    found_addr = -1;

			    print = 0;
			    count = 1;
			    sets++;
		    }
		    if(next_sig ==1){
			    n2 = list_iter_next(n2);
		    }

		    if(n2 == list_iter_tail(list_ptr)){
			    if(found_addr != -1){

				    printf("A set with address %d has %d packets\n", found_addr, count);
				    sets++;
				    break;
			    }
		    }
	    }
    }

    }

    // after all sets have been discovered print one of the following
    if (sets > 0) 
	    printf("Scan found %d sets\n", sets);
    else
	    printf("Scan found no records with >= %d matches\n", thresh);

    
    n1=NULL;
    n2=NULL;

}


void hpot_scan_MP3(pList list_ptr, int thresh){
       pIterator n1 = NULL;
       pIterator n2 = NULL;
       int match = 0;
       int print = 0;
      // int print_matches = 0; //commented out for effeciecny for mp3
       int sets = 0;
       //int found_addr; //commented out for effeciecny for mp3
       
       
       n1 = list_iter_first(list_ptr);
       n2 = list_iter_first(list_ptr);
       
       while(n2 !=list_iter_tail(list_ptr))
       {
            //found_addr=list_access(list_ptr,n1)->dest_ip_addr; //commented out for effeciecny for mp3
            if(hpot_compare(n1->data_ptr, n2->data_ptr) == 0){
                match++;
                n2 = n2->next;
                if(match >= thresh){
                    print = 1;
                    //print_matches = match; //commented out for effeciecny for mp3
                }
            }
            else{
                n1 = n2;
                match =0;
            }
             
             if(print == 1 && match == 0){
                //     printf("A set with address %d has %d packets\n", found_addr, print_matches); //commented out for effeciecny for mp3
                     print = 0;
                     sets++;
             } 
        
        
        
       }
       if (sets > 0) {
	  //  printf("Scan found %d sets\n", sets); //commented out for effeciecny for mp3
	   }
        else{
	  //  printf("Scan found no records with >= %d matches\n", thresh); //commented out for effeciecny for mp3
       }
        n1=NULL;
        n2=NULL;
       

}





/* the function takes a pointer to each list and prints the
 * number of items in each list
 */
void hpot_stats(pList sorted, pList unsorted, pList priority)
{
	// get the number in list and size of the list
	int num_in_sorted_list = list_size(sorted);
	int num_in_unsorted_list = list_size(unsorted);
	int num_in_priority_list = list_size(priority);
	printf("Number records in list: %d, queue list: %d, priority list: %d\n", 
			num_in_sorted_list, num_in_unsorted_list, num_in_priority_list);
}


// function just to call list.c function from the lab3.c
void hpot_sort(pList A, int B){
    list_sort(A, B);
}




/* this function frees the memory for either a sorted or unsorted list.
 */
 
 


void hpot_cleanup(pList list_ptr)
{
	list_destruct(list_ptr);
}

/* commands specified to vim. ts: tabstop, sts: soft tabstop sw: shiftwidth */
/* vi:set ts=8 sts=4 sw=4 et: */
