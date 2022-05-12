/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * (c) Amy Babay, 2022
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <regex.h>
#define BUFSIZE 1024

int match(char *,char *);

int 
main(int argc, char ** argv) 
{

    char * server_name = NULL;
    int    server_port = -1;
    char * server_path = NULL;
    char * req_str     = NULL;

    int ret = 0;

    /*parse args */
    if (argc != 4) {
        fprintf(stderr, "usage: http_client <hostname> <port> <path>\n");
        exit(-1);
    }

    server_name = argv[1];
    server_port = atoi(argv[2]);
    server_path = argv[3];
    
    /* Create HTTP request */
    ret = asprintf(&req_str, "GET %s HTTP/1.0\r\n\r\n", server_path);
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate request string\n");
        exit(-1);
    }

    /*
     * NULL accesses to avoid compiler warnings about unused variables
     * You should delete the following lines 
     */
    //(void)server_name;
    //(void)server_port;

    int s;
    struct hostent *hp;
    struct sockaddr_in saddr;

    /* make socket */
    if((s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
	    perror("tcp_client: fail to create socket");
	    exit(-1);
    }

    /* get host IP address  */
    if((hp=gethostbyname(server_name))==NULL){
        herror("tcp_client: gethostbyname error");
        exit(-1);
    }

    /* Hint: use gethostbyname() */

    /* set address */
    memset(&saddr,0,sizeof(saddr));
    saddr.sin_family = AF_INET;
    memcpy(&saddr.sin_addr.s_addr,hp->h_addr,hp->h_length);
    saddr.sin_port = htons(server_port);
    /* connect to the server */
    if(connect(s,(struct sockaddr *)&saddr,sizeof(saddr))<0){
    	perror("tcp_client: could not connect to server");
	    exit(-1);
    }

    int res;
    char buf[1024];

    /* send request message */
    if((res = send(s,req_str,strlen(req_str),0))<=0){
        perror("tcp_client: send error");
        exit(-1);
    }


    /* wait for response (i.e. wait until socket can be read) */
    /* Hint: use select(), and ignore timeout for now. */
    fd_set             read_mask, write_mask, error_mask;
    fd_set             tmp_rmask;
    int num;
    int valid,check_header = 0;

    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);
    FD_ZERO(&error_mask);
    FD_SET(s, &read_mask);

    /* first read loop -- read headers */
    while(1){
        tmp_rmask = read_mask;
        num = select(FD_SETSIZE, &tmp_rmask, &write_mask, &error_mask, NULL);
        if(num>0){
            if (FD_ISSET(s, &tmp_rmask)) {
                if ((res = recv(s, buf, sizeof(buf) - 1, 0)) <= 0) {
                    exit(-1);
                }
                buf[res] = '\0';
                if(check_header == 0){
                    check_header = 1;
                    char* header_match = "HTTP/[1-9].[0-9] 200 OK";
                    //cnm using reg in c is so hard
                    valid = match(buf,header_match);
                    
                    char * p_header;
                    p_header = strstr(buf,"\r\n\r\n");
                    
                    if (valid <= 0)
                    {
                        // TESTCASE
                        // ./http_client www.washington.edu 80 junk.html
                        *p_header = '\0';
                        fprintf(stderr,"%s",buf);
                        exit(-1);
                    }
                    //TESTCASE: 
                    // ./http_client gaia.cs.umass.edu 80 /wireshark-labs/HTTP-wireshark-file3.html
                    printf("%s",p_header+4);
                }else{
                    printf("%s", buf);
                }
            }
        }
    }

    /* examine return code */   
    // Skip protocol version (e.g. "HTTP/1.0")
    // Normal reply has return code 200

    /* print first part of response: header, error code, etc. */

    /* second read loop -- print out the rest of the response: real web content */

    /* close socket */
    close(s);
    return(0);

}

int match(char *string,char *pattern)
{
    regex_t re;
    if (regcomp(&re, pattern, REG_ICASE) != 0) return 0;
    int status = regexec(&re, string, 0, NULL, 0);
    regfree(&re);
    if (status != 0) return 0;
    return 1;
}