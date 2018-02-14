/* datatypes.h 
 * Huzefa Dossaji
 * hdossaj
 * ECE 223 Fall 2015 
 * MP3
 *
 * Propose: The data type that is stored in the list ADT is defined here.  We
 *          define a single mapping that allows the list ADT to be defined in
 *          terms of a generic data_t.Key definitions of the honeypot packet structure and a packet comparison
 *           procedure needed by the list ADT
 *
 * Assumptions: 
 *
 *     data_t: The type of data that we want to store in the list
 *
 * Bugs: THERE ARE NO BUGS DETECTED EVEN WITH ALL MY EXTENSIVE TESTING
 * 
 */
typedef struct packet_tag {
    int dest_ip_addr;       /* IP address of destination */
    int src_ip_addr;        /* IP address of source */
    int dest_port_num;      /* port number at destination */
    int src_port_num;       /* port number at source host*/
    int hop_count;          /* number of routers in route */
    int protocol;           /* TCP=1, UDP=2, SSL=3, RTP=4 */
    float threat_score;     /* rating of source host */
    int time_received;      /* time in seconds packet received */
} packet_t;

/* the list ADT works on packet data of this type */
typedef packet_t data_t;

/* commands for vim. ts: tabstop, sts: soft tabstop sw: shiftwidth */
/* vi:set ts=8 sts=4 sw=4 et: */
