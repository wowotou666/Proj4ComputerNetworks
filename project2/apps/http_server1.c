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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <petnet.h>
#include <petnet_socket_api.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>



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
    if ((len = petnet_recv(sock, buf, sizeof(buf) - 1)) <= 0)  {
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
    int c           = -1;

    /* parse command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: http_server1 port\n");
        exit(-1);
    }

    server_port = atoi(argv[1]);

    if (server_port < 1500) {
        fprintf(stderr, "INVALID PORT NUMBER: %d; can't be < 1500\n", server_port);
        exit(-1);
    }

    /* initialize and make socket */
    if((sock=petnet_socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
        perror("tcp_server: socket error");
        exit(-1);
    }

    /* set server address */
    memset(&saddr,0,sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(server_port);

    /* bind listening socket */
    if (petnet_bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("tcp_server: bind error");
        exit(-1);
    }

    /* start listening */
    if (petnet_listen(sock, 32) < 0) {
        perror("tcp_server: listen error");
        exit(-1);
    }

    /* connection handling loop: wait to accept connection */
    while (1) {
        /* handle connections */
        c = petnet_accept(sock,NULL,NULL);
        if(c >= 0){
            ret = handle_connection(c);
        }
        (void)ret; // DELETE ME
    }
    petnet_close(sock);
    return(0);
}
