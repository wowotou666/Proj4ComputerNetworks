/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * (c) Amy Babay, 2022
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */

/*
    reference website: https://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
*/
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFSIZE 1024
#define FILENAMESIZE 100


static int 
handle_connection(int sock) 
{
 
    int res = -1;
    int len = 0;
    char buf[BUFSIZE]; 
    char * file_buffer;
    char * resp_str;
    long length;
    char filename[FILENAMESIZE];
    char * filehead;
    char * filetail;

    char * ok_response_f  = "HTTP/1.0 200 OK\r\n"        \
        					"Content-type: text/plain\r\n"                  \
        					"Content-length: %d \r\n\r\n%s";
 
    char * notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"   \
        					"Content-type: text/html\r\n\r\n"                       \
        					"<html><body bgColor=black text=white>\n"               \
        					"<h2>404 FILE NOT FOUND</h2>\n"
        					"</body></html>\n";
    

    /* first read loop -- get request and headers*/
    memset(buf, 0, BUFSIZE);
    if ((len = recv(sock, buf, sizeof(buf) - 1, 0)) <= 0)  {
        perror("tcp_server: recv error");
        exit(-1);
    }
    buf[len] = '\0';

    /* parse request to get file name */
    /* Assumption: this is a GET request and filename contains no spaces*/
    filehead = strchr(buf, ' ') + 1;
    filetail = strchr(filehead, ' ');
    int filelen = (int)(filetail - filehead);
    filename[filelen] = '\0';
    strncpy(filename,filehead,filelen);
    printf("recv reequest: %s", filename);
    memset(buf, 0, FILENAMESIZE);

    /* Assumption: this is a GET request and filename contains no spaces*/
    /* open and read the file */
    FILE * file = fopen(filename, "r");
  
	if(file == NULL){
        perror("tcp_server: file not exist error");
        /* send error response */
        if((res=send(sock,notok_response,strlen(notok_response),0))<=0){
            perror("tcp_server: send error");
            return(-1);
        }
        return -1; 
    } 

    // Readline from file
    fseek (file, 0, SEEK_END);
    length = ftell (file);
    fseek (file, 0, SEEK_SET);
    file_buffer = malloc (length);
    if (file_buffer)
    {
        fread (file_buffer, 1, length, file);
    }

    fclose(file);

	/* send response */
    asprintf(&resp_str,ok_response_f,strlen(file_buffer),file_buffer);
    if((res=send(sock,resp_str,strlen(resp_str),0))<=0){
        perror("tcp_server: send error");
        return(-1);
    }

    /* close socket and free pointers */
    close(sock);
	return 0;
}



int
main(int argc, char ** argv)
{
    int server_port = -1;
    int ret         =  0;
    int sock        = -1;
    struct sockaddr_in saddr;

    /* parse command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: http_server1 port\n");
        exit(-1);
    }

    server_port = atoi(argv[1]);

    if (server_port < 1500) {
        fprintf(stderr, "Requested port(%d) must be above 1500\n", server_port);
        exit(-1);
    }
    
    /* initialize and make socket */
    if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
        perror("tcp_server: socket error");
        exit(-1);
    }

    /* set server address */
    memset(&saddr,0,sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(server_port);

    /* bind listening socket */
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("tcp_server: bind error");
        exit(-1);
    }

    /* start listening */
    if (listen(sock, 32) < 0) {
        perror("tcp_server: listen error");
        exit(-1);
    }

    int read_list[30];
    int num;
    int max_fd;
    int curr_fd;
    int income_sock;
    fd_set read_mask, write_mask, error_mask;

    for(int i=0;i<30;i++){
        read_list[i] = 0;
    }

    /* connection handling loop: wait to accept connection */    
    while (1) { 
        FD_ZERO(&read_mask);
        FD_ZERO(&write_mask);
        FD_ZERO(&error_mask);
        FD_SET(sock,&read_mask);
        max_fd = sock;
        /* create read list */
        for(int i=0;i<30;i++){
            curr_fd = read_list[i];

            if(curr_fd > 0){
                FD_SET(curr_fd,&read_mask);
            }

            if(curr_fd > max_fd){
                max_fd = curr_fd;
            }
        }
        /* do a select() */
        num = select(max_fd+1,&read_mask,&write_mask,&error_mask,NULL);
        
        /* process sockets that are ready:
         *     for the accept socket, add accepted connection to connections
         *     for a connection socket, handle the connection
         */
        if(num>0){
            if(FD_ISSET(sock,&read_mask)){
                income_sock = accept(sock,NULL,NULL);
                if(income_sock >= 0){
                    for(int i=0;i<30;i++){
                        if(read_list[i] == 0){
                            read_list[i] = income_sock;
                            break;
                        }
                    }
                }
            }
        }
        for(int i=0;i<30;i++){
                curr_fd = read_list[i];
                if(FD_ISSET(curr_fd,&read_mask)){
                    ret = handle_connection(curr_fd);
                    read_list[i] = 0;
                    (void)ret;  // DELETE ME
                }
        }
        
    }
    return(0);
}
