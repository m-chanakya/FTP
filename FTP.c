//
//  main.c
//  file sharing protocol
//
//  Created by Chanakya Malireddy & Sriram Narayanan on 02/03/15.
//  Copyright (c) 2015 Chanakya Malireddy. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <netinet/in.h>
#include <openssl/md5.h>
//#include <CommonCrypto/CommonDigest.h>
#include <openssl/hmac.h>
#include <arpa/inet.h>

#define PACKET_DELIM "%@%"
#define SHARED_DIR "./"
#define FILE_NAME_SIZE 200
#define MAX_FILES 1000
#define PACKET_SIZE 1024
#define HISTORY 1000

/*
 Error codes:
 0 : success
 1 : invalid arguements
 2 : invalid protocol
 3 : no memory to fork
 4 : error while creating socket
 */

//GLOBALS
int udp_client_flag;
char history [HISTORY][50+FILE_NAME_SIZE];
int hist_count = 0;
int files_index;
int hash_index;
struct sockaddr_in udp_sockaddr;
int sock_addr_size;

//DATA STRUCTURES
struct file_data
{
    char name[FILE_NAME_SIZE];
    char type;
    off_t size;
    time_t mtime;
}files[MAX_FILES];

struct file_hash
{
    char *name;
    unsigned char hash[MD5_DIGEST_LENGTH];
    time_t mtime;
}hashes[MAX_FILES];

int parse_request(char *request)
{
    char request_copy[PACKET_SIZE];
    strcpy(request_copy, request);
    char *command = strtok(request_copy," ");
    if(command != NULL)
    {
        if(strcmp(command,"IndexGet") == 0)
            return 1;
        else if(strcmp(command,"FileHash") == 0)
            return 2;
        else if(strcmp(command,"FileDownload") == 0)
            return 3;
        else if(strcmp(command,"FileUpload") == 0)
            return 4;
        else if(strcmp(command, "q") == 0 || strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0)
            return 5;
        else if(strcmp(command, "history") == 0)
            return 6;
        else
            return -1;
    }
    return -1;
}

int listFiles(int mode, char * regex, time_t start_time, time_t end_time)
{
    files_index = 0;
    regex_t compare_string;
    DIR *dp;
    struct dirent *ep;
    dp = opendir(SHARED_DIR);
    struct stat file_stat;
    if(!dp) return -2;
    
    if (mode==2) //COMPILE REGEX
    {
        int status = regcomp(&compare_string, regex, REG_EXTENDED|REG_NOSUB);
        if (status) return -3;
    }
    while( (ep = readdir(dp)) )
    {
    	if(stat(ep->d_name, &file_stat) < 0) return -2;
        if ( mode==0 ||
            (mode==1 && difftime(file_stat.st_mtime, start_time) > 0 && difftime(end_time, file_stat.st_mtime) > 0) ||
            (mode==2 && !regexec(&compare_string, ep->d_name, (size_t)0, NULL, 0))
            )
        {
            strcpy(files[files_index].name, ep->d_name);
            files[files_index].size = file_stat.st_size;
            files[files_index].mtime = file_stat.st_mtime;
            files[files_index].type = (S_ISDIR(file_stat.st_mode)) ? 'd' : '-';
            files_index++;
        }
    }
    closedir(dp);
    return 0;
}

int IndexGet(char * request)
{
    /*
     return -3 if regex is wrong
     return -2 if shared folder cannot be opened
     return -1 for any error in format
     return 0 for success
     */
    char *flag;
    struct tm time_stamp;
    time_t start_time , end_time;
    
    flag = strtok(request, " ");
    flag = strtok(NULL, " ");
    if (!flag) return -1;
    if (strcmp(flag, "--LongList\n") == 0)
        return listFiles(0, NULL, 0, 0);
    else if (strcmp(flag, "--ShortList") == 0)
    {
        flag = strtok(NULL, " ");
        if (!flag) return -1;
        if (strptime(flag, "%d-%b-%Y-%H:%M:%S", &time_stamp) == NULL) return -1;
        start_time = mktime(&time_stamp);
            
        flag = strtok(NULL, " ");
        flag[strlen(flag)-1] = 0;
        if (!flag) return -1;
        if (strptime(flag, "%d-%b-%Y-%H:%M:%S", &time_stamp) == NULL) return -1;
        end_time = mktime(&time_stamp);
            
        return listFiles(1, NULL, start_time, end_time);
    }
    else if (strcmp(flag, "--RegEx") == 0)
    {
        flag = strtok(NULL, "\n");
        if (!flag) return -1;
        return listFiles(2, flag, 0, 0);
    }
    else
        return -1;
}

int hashFiles(int mode, char *filename)
{
    hash_index = 0;
    unsigned char c[MD5_DIGEST_LENGTH];
    DIR *dp;
    struct dirent *ep;
    dp = opendir (SHARED_DIR);
    struct stat file_stat;
    if (!dp) return -2;
    int i;
    while( (ep = readdir (dp)) )
    {
        if(stat(ep->d_name,&file_stat) < 0) return -2;
        
        if (mode==1 && strcmp(filename,ep->d_name) != 0)
            continue;
        
        hashes[hash_index].name = ep->d_name;
        hashes[hash_index].mtime = file_stat.st_mtime;
        FILE *inFile = fopen (ep->d_name, "r");
        MD5_CTX mdContext;
        int bytes;
        unsigned char data[1024];
        
        if (inFile == NULL) return -3;
        MD5_Init (&mdContext);
        while ((bytes = (int)fread (data, 1, 1024, inFile)) != 0)
            MD5_Update (&mdContext, data, bytes);
        MD5_Final (c, &mdContext);
        for(i = 0; i < MD5_DIGEST_LENGTH; i++)
            hashes[hash_index].hash[i] = c[i];
        fclose (inFile);
        hash_index++;

    }
    return 0;
}

int FileHash (char * request)
{
    /*
     return -3 if file cannot be opened
     return -2 if shared folder cannot be opened
     return -1 for any error in format
     return 0 for success
     */
    char *flag = strtok(request, " ");
    flag = strtok(NULL, " ");
    if (!flag) return -1;
    if (strcmp(flag, "--checkall\n") == 0)
    {
        flag = strtok(NULL, " ");
        if(flag) return -1;
        return hashFiles(0, NULL);
    }
    else if(strcmp(flag, "--verify") == 0)
    {
        flag = strtok(NULL, "\n");
        if (!flag) return -1;
        return hashFiles(1, flag);
    }
    else
        return -1;
}

int get_filename(char * request, char filename[FILE_NAME_SIZE])
{
    char *file = strtok(request, " ");
    file = strtok(NULL, "\n");
    if(!file) return -1;
    strcpy(filename, file);
    return 0;
}

int upload(char file[FILE_NAME_SIZE], int socket)
{
    /*
     0 : success
     -2: cannot open file
    */
    char write_buffer[PACKET_SIZE];
    char cresponse[PACKET_SIZE];
    bzero(write_buffer, PACKET_SIZE);
    int b,c;
    hashFiles(1, file);
    for (b = 0 ; b < 1 ; b++)
    {
        for (c = 0 ; c < MD5_DIGEST_LENGTH ; c++)
        {
            sprintf(cresponse, "%02x",hashes[b].hash[c]);
            strcat(write_buffer,cresponse);
        }
        sprintf(cresponse, ", %s",ctime(&hashes[b].mtime));
        strcat(write_buffer,cresponse);
    }
    strcat(write_buffer, PACKET_DELIM);
    if(!udp_client_flag)
    	write(socket , write_buffer , strlen(write_buffer));
    else
        sendto(socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&udp_sockaddr,sock_addr_size);

    bzero(write_buffer, PACKET_SIZE);
    FILE* fp;
    fp = fopen(file, "rb");
    if(!fp) return -2;
    size_t bytes;
    while(!feof(fp))
    {
        bytes = fread(write_buffer, 1, 1024, fp);
        if(!udp_client_flag)
        	write(socket , write_buffer , bytes);
        else
        	sendto(socket , write_buffer , bytes,0,(struct sockaddr*)&udp_sockaddr,sock_addr_size);
        bzero(write_buffer, PACKET_SIZE);
    }
    strcat(write_buffer,PACKET_DELIM);
    if(!udp_client_flag)
    	write(socket , write_buffer , strlen(write_buffer));
    else
        sendto(socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&udp_sockaddr,sock_addr_size);
    fclose(fp);
    return 0;
}

int download(char file[FILE_NAME_SIZE], int connection_socket, int flag)
{
    /*
     0 : success
     -2: cannot open file
     -3: hash did not match
    */
    char read_buffer[PACKET_SIZE], copy[PACKET_SIZE], cresponse[PACKET_SIZE];
    char *input_hash = malloc(512);
    int n;
    
    if(flag)
    {
	    bzero(read_buffer, PACKET_SIZE);
	    if(!udp_client_flag)
	    	n = (int)read(connection_socket, read_buffer, sizeof(read_buffer)-1);
	    else
    		n = (int)recvfrom(connection_socket,read_buffer, sizeof(read_buffer)-1,0,(struct sockaddr*)&udp_sockaddr, &sock_addr_size);
	    read_buffer[n-3] = 0;
	    strcpy(copy, read_buffer);
	    input_hash = strtok(copy, ", ");
	}
    FILE *fp;
    if(flag)
    {
        fp = fopen(file, "wb");
        if(!fp) return -2;
    }
    bzero(read_buffer, PACKET_SIZE);
    if(!udp_client_flag)
    	n = (int)read(connection_socket, read_buffer, sizeof(read_buffer)-1);
    else
    	n = (int)recvfrom(connection_socket,read_buffer, sizeof(read_buffer)-1,0,(struct sockaddr*)&udp_sockaddr, &sock_addr_size);
    while(n>0)
    {
        read_buffer[n] = 0;
        if(read_buffer[n-1] == '%' && read_buffer[n-2] == '@' && read_buffer[n-3] == '%')
        {
            read_buffer[n-3] = 0;
            if(flag == 1)
            {
                fwrite(read_buffer,1,n-3,fp);
                fclose(fp);
            }
            else
                printf("%s\n",read_buffer);
        	bzero(read_buffer,PACKET_SIZE);
            break;
        }
        else
        {
            if(flag == 1)
                fwrite(read_buffer,1,n,fp);
            else
                printf("%s\n",read_buffer);
        }
        bzero(read_buffer,PACKET_SIZE);
        if(!udp_client_flag)
    		n = (int)read(connection_socket, read_buffer, sizeof(read_buffer)-1);
    	else
    		n = (int)recvfrom(connection_socket,read_buffer, sizeof(read_buffer)-1,0,(struct sockaddr*)&udp_sockaddr, &sock_addr_size);
    }
    if(flag == 1)
	{
        char temp[PACKET_SIZE];
        bzero(cresponse, PACKET_SIZE);
	    hashFiles(1, file);
	    int b, c;
	    for (b = 0 ; b < 1 ; b++)
	    {
	        for (c = 0 ; c < MD5_DIGEST_LENGTH ; c++)
            {
	            sprintf(temp, "%02x",hashes[b].hash[c]);
                strcat(cresponse, temp);
            }
	    }
	    if (strcmp(cresponse, input_hash) != 0)
	    {
	        //remove(file);
	        return -3;
	    }
        return 0;
	}
    return 0;
}

void tcp_server(int listen_port)
{
    printf("TCP SERVER started\n");
    int listen_socket = 0, connection_socket = 0;
    struct sockaddr_in serv_addr;
    
    char read_buffer[PACKET_SIZE];
    char write_buffer[PACKET_SIZE];
    
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_socket < 0)
    {
        printf("\n[SERVER] Error while creating socket\n");
        exit(4);
    }
    printf("\n[SERVER] Socket Established\n");
    
    bzero((char *) &serv_addr,sizeof(serv_addr));
    bzero(read_buffer,PACKET_SIZE);
    bzero(write_buffer,PACKET_SIZE);
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(listen_port);
    
    if(bind(listen_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("[SERVER] ERROR WHILE BINDING THE SOCKET\n");
        exit(0);
    }
    printf("[SERVER] SOCKET BOUND SUCCESSFULLY\n");
    
    listen(listen_socket, 10); //maximum of 10 connections
    connection_socket = accept(listen_socket, (struct sockaddr*)NULL, NULL);
    
    char response[PACKET_SIZE];
    
    //LOOP VARIABLES
    int i, j;
    int n = (int)read(connection_socket, read_buffer, sizeof(read_buffer));
    
    while(n > 0)
    {
        char *request = malloc(strlen(read_buffer) + 1);
        strcpy(request,read_buffer);
        strcpy(history[hist_count],request);
        hist_count++;
        
        bzero(read_buffer,PACKET_SIZE);
        bzero(write_buffer,PACKET_SIZE);
        
        int command = parse_request(request);
        if (command == 5)           //quit
            _exit(0);
        else if(command == 1)      //Indexget
        {
            int status = IndexGet(request);
            if(!status)
            {
                for (i=0; i<files_index; i++)
                {
                    sprintf(response, "%-35s| %-10lld| %-3c| %-20s" , files[i].name , files[i].size , files[i].type , ctime(&files[i].mtime));
                    if(i==files_index-1)
                    	strcat(response,PACKET_DELIM);
                    strcat(write_buffer, response);
                    write(connection_socket , write_buffer , strlen(write_buffer));
                    bzero(write_buffer,PACKET_SIZE);
                }
            }
            else //ERROR HANDLING
            {
                if (status == -1)
                    sprintf(response,"\nERROR: Invalid Format.\
                            \nCorrect Formats :\
                            \nIndexGet --LongList\
                            \nIndexGet --ShortList <StartTimeStamp> <EndTimeStamp>\
                            \nIndexGet --RegEx <regex expression>\n");
                else if (status == -2)
                    sprintf(response,"\nERROR: shared folder cannot be opened\n");
                else if (status == -3)
                    sprintf(response,"\nERROR: invalid regex\n");
                strcat(write_buffer, response);
    			strcat(write_buffer,PACKET_DELIM);
                write(connection_socket , write_buffer , strlen(write_buffer));
            }
        }
        else if(command == 2)      //FileHash
        {
            int status = FileHash(request);
            if(!status)
            {
                for (i = 0 ; i < hash_index ; i++)
                {
                    bzero(write_buffer,PACKET_SIZE);
                    sprintf(response, "%-35s | ", hashes[i].name);
                    strcat(write_buffer, response);
                    for (j = 0 ; j < MD5_DIGEST_LENGTH ; j++)
                    {
                        sprintf(response, "%x",hashes[i].hash[j]);
                        strcat(write_buffer, response);
                    }
                    sprintf(response, "\t %20s",ctime(&hashes[i].mtime));
                    if(i==hash_index-1)
                        strcat(response,PACKET_DELIM);
                    strcat(write_buffer, response);
                    write(connection_socket , write_buffer , strlen(write_buffer));
                }
            }
            else //ERROR HANDLING
            {
                if (status == -1)
                    sprintf(response,"\nERROR: Invalid Format.\
                            \nCorrect Formats :\
                            \nFileHash --checkall\
                            \nIndexGet --verify <filename>\n");
                else if (status == -2)
                    sprintf(response,"\nERROR: shared folder cannot be opened\n");
                else if (status == -3)
                    sprintf(response,"\nERROR: cannot open file\n");
                strcat(write_buffer, response);
                strcat(write_buffer,PACKET_DELIM);
                write(connection_socket , write_buffer , strlen(write_buffer));
            }
        }
        else if(command == 3)      //FileDownload
        {
            int status;
            char file[FILE_NAME_SIZE];
            status = get_filename(request, file);
            if(!status)
                status = upload(file, connection_socket);
            if(status)
            {
                bzero(write_buffer,PACKET_SIZE);
                if (status == -1)
                    sprintf(response, "\nERROR: Invalid Format.\
                            \n Correct Formats :\
                            \nFileDownload <filename>");
                else if (status == -2)
                    sprintf(response,"\nERROR: cannot open file\n");
                strcat(write_buffer, response);
                strcat(write_buffer,PACKET_DELIM);
                write(connection_socket , write_buffer , strlen(write_buffer));
            }
        }
        else if(command == 4)      //FileUpload
        {
            int status;
            char file[FILE_NAME_SIZE];
            status = get_filename(request, file);
            if(!status)
            {
                FILE* fp;
  				fp = fopen("permissions", "rb");
                fscanf(fp, "%s", response);
                if (strcmp(response, "FileUploadAllow") == 0)
                {
                    strcat(write_buffer, response);
                	//strcat(write_buffer,PACKET_DELIM);
                    write(connection_socket , write_buffer , strlen(write_buffer));
                    status = download(file, connection_socket, 1);
                }
                else
                {
                    strcat(write_buffer, response);
                	//strcat(write_buffer,PACKET_DELIM);
                    write(connection_socket , write_buffer , strlen(write_buffer));
                }
                fclose(fp);
            }
            if (status == -1)
                sprintf(response, "\nERROR: Invalid Format.\
                        \n Correct Formats :\
                        \nFileDownload <filename>");
            else if(status == -2)
                sprintf(response,"\nERROR: cannot open file\n");
            else if (status == -3)
                sprintf(response,"\nERROR: md5 did not match (send again)\n");
            strcat(write_buffer, response);
           	strcat(write_buffer,PACKET_DELIM);
            write(connection_socket , write_buffer , strlen(write_buffer));
        }
        else if (command == 6)
        {
            for (i=0; i<hist_count; i++)
            {
                sprintf(response, "%s" , history[i]);
                if(i==hist_count-1)
                    strcat(response,PACKET_DELIM);
                strcat(write_buffer, response);
                write(connection_socket , write_buffer , strlen(write_buffer));
                bzero(write_buffer,PACKET_SIZE);
            }
        }
        else if (command == -1)     //error
        {
            sprintf(response, "\nInvalid Request\n");
            strcat(write_buffer, response);
           	strcat(write_buffer,PACKET_DELIM);
            write(connection_socket , write_buffer , strlen(write_buffer));
        }
        while((n = (int)read(connection_socket, read_buffer, sizeof(read_buffer)))<=0);
    }
    return;
}

void tcp_client(char *ip, int connection_port)
{
    printf("TCP CLIENT started\n");
    int connection_socket = 0;
    
    char read_buffer[PACKET_SIZE];
    char write_buffer[PACKET_SIZE];
    
    struct sockaddr_in serv_addr;
    char file[PACKET_SIZE];
    
    bzero((char *) &serv_addr,sizeof(serv_addr));
    
    if((connection_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n[CLIENT] Error while creating socket\n");
        exit(4);
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(connection_port);
    
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        exit(4);
    }
    
    while( connect(connection_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0);
    
    int download_flag, upload_flag;
    
    while(1)
    {
        bzero(read_buffer,PACKET_SIZE);
        bzero(write_buffer,PACKET_SIZE);
        download_flag = 0;
        upload_flag = 0;
        char cresponse[PACKET_SIZE];
        
        printf("[Enter Command Here : ]");
        fgets(write_buffer, sizeof(write_buffer), stdin);
        
        char *filename = malloc(PACKET_SIZE);
        char copy[PACKET_SIZE];
        strcpy(copy, write_buffer);
        filename = strtok(copy, " \n");
        
        if(strcmp(filename, "quit") == 0)
            _exit(1);
        
        if(strcmp(filename,"FileDownload") == 0)
        {
            download_flag = 1;
            filename = strtok(NULL," \n");
            strcpy(file, filename);
        }
        else if(strcmp(filename,"FileUpload") == 0)
        {
            upload_flag = 1;
            filename = strtok(NULL," \n");
            strcpy(file, filename);
        }
        write(connection_socket, write_buffer , strlen(write_buffer));
        bzero(write_buffer,PACKET_SIZE);
        
        if (download_flag || !upload_flag)
        {
            int status = download(file, connection_socket, download_flag);
            if(status)
            {
                if(status == -2)
                    sprintf(cresponse,"\nERROR: cannot open file\n");
                else if (status == -3)
                    sprintf(cresponse,"\nERROR: md5 did not match (send again)\n");
                strcat(write_buffer, cresponse);
                write(connection_socket , write_buffer , strlen(write_buffer));
                bzero(write_buffer,PACKET_SIZE);
            }
        }
        else
        {
            read(connection_socket, read_buffer, sizeof(read_buffer)-1);
            if(strcmp(read_buffer, "FileUploadAllow") == 0)
                upload(file, connection_socket);
        }
    }
}

void udp_server(int listen_port)
{
    printf("UDP SERVER started\n");
    int listen_socket = 0;
    struct sockaddr_in serv_addr;

    char read_buffer[PACKET_SIZE];
    char write_buffer[PACKET_SIZE];
    
    listen_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(listen_socket < 0)
    {
        printf("\n[SERVER] Error while creating socket\n");
        exit(4);
    }
    printf("\n[SERVER] Socket Established\n");
    
    bzero((char *) &serv_addr,sizeof(serv_addr));
    bzero(read_buffer,PACKET_SIZE);
    bzero(write_buffer,PACKET_SIZE);
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(listen_port);
    
    if(bind(listen_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("[SERVER] ERROR WHILE BINDING THE SOCKET\n");
        exit(0);
    }
    printf("[SERVER] SOCKET BOUND SUCCESSFULLY\n");
    
    char response[PACKET_SIZE];
    
    udp_sockaddr = serv_addr;
    
    //LOOOP VARIABLES
    int i, j;
    int n = (int)recvfrom(listen_socket,read_buffer,sizeof(read_buffer),0,(struct sockaddr*)&serv_addr,&sock_addr_size);
    
    while(n > 0)
    {
        char *request = malloc(strlen(read_buffer) + 1);
        strcpy(request,read_buffer);
        strcpy(history[hist_count],request);
        hist_count++;
        
        bzero(read_buffer,PACKET_SIZE);
        bzero(write_buffer,PACKET_SIZE);
        
        int command = parse_request(request);
        if (command == 5)           //quit
            _exit(0);
        else if(command == 1)      //Indexget
        {
            int status = IndexGet(request);
            if(!status)
            {
                for (i=0; i<files_index; i++)
                {
                    sprintf(response, "%-35s| %-10lld| %-3c| %-20s" , files[i].name , files[i].size , files[i].type , ctime(&files[i].mtime));
                    if(i==files_index-1)
                    	strcat(response,PACKET_DELIM);
                    strcat(write_buffer, response);
                    sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
                    bzero(write_buffer,PACKET_SIZE);
                }
            }
            else //ERROR HANDLING
            {
                if (status == -1)
                    sprintf(response,"\nERROR: Invalid Format.\
                            \nCorrect Formats :\
                            \nIndexGet --LongList\
                            \nIndexGet --ShortList <StartTimeStamp> <EndTimeStamp>\
                            \nIndexGet --RegEx <regex expression>\n");
                else if (status == -2)
                    sprintf(response,"\nERROR: shared folder cannot be opened\n");
                else if (status == -3)
                    sprintf(response,"\nERROR: invalid regex\n");
                strcat(write_buffer, response);
    			strcat(write_buffer,PACKET_DELIM);
                sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
            }
        }
        else if(command == 2)      //FileHash
        {
            int status = FileHash(request);
            if(!status)
            {
                for (i = 0 ; i < hash_index ; i++)
                {
                    bzero(write_buffer,PACKET_SIZE);
                    sprintf(response, "%-35s | ", hashes[i].name);
                    strcat(write_buffer, response);
                    for (j = 0 ; j < MD5_DIGEST_LENGTH ; j++)
                    {
                        sprintf(response, "%x",hashes[i].hash[j]);
                        strcat(write_buffer, response);
                    }
                    sprintf(response, "\t %20s",ctime(&hashes[i].mtime));
                    if(i==hash_index-1)
                        strcat(response,PACKET_DELIM);
                    strcat(write_buffer, response);
                    sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
                }
            }
            else //ERROR HANDLING
            {
                if (status == -1)
                    sprintf(response,"\nERROR: Invalid Format.\
                            \nCorrect Formats :\
                            \nFileHash --checkall\
                            \nIndexGet --verify <filename>\n");
                else if (status == -2)
                    sprintf(response,"\nERROR: shared folder cannot be opened\n");
                else if (status == -3)
                    sprintf(response,"\nERROR: cannot open file\n");
                strcat(write_buffer, response);
                strcat(write_buffer,PACKET_DELIM);
                sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
            }
        }
        else if(command == 3)      //FileDownload
        {
            int status;
            char file[FILE_NAME_SIZE];
            status = get_filename(request, file);
            if(!status)
                status = upload(file, listen_socket);
            if(status)
            {
                bzero(write_buffer,PACKET_SIZE);
                if (status == -1)
                    sprintf(response, "\nERROR: Invalid Format.\
                            \n Correct Formats :\
                            \nFileDownload <filename>");
                else if (status == -2)
                    sprintf(response,"\nERROR: cannot open file\n");
                strcat(write_buffer, response);
                strcat(write_buffer,PACKET_DELIM);
                sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
            }
        }
        else if(command == 4)      //FileUpload
        {
            int status;
            char file[FILE_NAME_SIZE];
            status = get_filename(request, file);
            if(!status)
            {
                FILE* fp;
  				fp = fopen("permissions", "rb");
                fscanf(fp, "%s", response);
                if (strcmp(response, "FileUploadAllow") == 0)
                {
                    strcat(write_buffer, response);
                	//strcat(write_buffer,PACKET_DELIM);
	                sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
                    status = download(file, listen_socket, 1);
                }
                else
                {
                    strcat(write_buffer, response);
                	//strcat(write_buffer,PACKET_DELIM);
	                sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
                }
                fclose(fp);
            }
            if (status == -1)
                sprintf(response, "\nERROR: Invalid Format.\
                        \n Correct Formats :\
                        \nFileDownload <filename>");
            else if(status == -2)
                sprintf(response,"\nERROR: cannot open file\n");
            else if (status == -3)
                sprintf(response,"\nERROR: md5 did not match (send again)\n");
            strcat(write_buffer, response);
           	strcat(write_buffer,PACKET_DELIM);
            sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
        }
        else if (command == 6)
        {
            for (i=0; i<hist_count; i++)
            {
                sprintf(response, "%s" , history[i]);
                if(i==hist_count-1)
                    strcat(response,PACKET_DELIM);
                strcat(write_buffer, response);
            	sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
                bzero(write_buffer,PACKET_SIZE);
            }
        }
        else if (command == -1)     //error
        {
            sprintf(response, "\nInvalid Request\n");
            strcat(write_buffer, response);
           	strcat(write_buffer,PACKET_DELIM);
            sendto(listen_socket , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
        }
    	while((n = (int)recvfrom(listen_socket,read_buffer,sizeof(read_buffer),0,(struct sockaddr*)&serv_addr,&sock_addr_size))<=0);
    }
    return;
}

void udp_client(char *ip, int connection_port)
{
    printf("UDP CLIENT started\n");
    int sockfd = 0;
    
    char read_buffer[PACKET_SIZE];
    char write_buffer[PACKET_SIZE];
    
    struct sockaddr_in serv_addr;
    char file[PACKET_SIZE];
    
    bzero((char *) &serv_addr,sizeof(serv_addr));
    
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("\n[CLIENT] Error while creating socket\n");
        exit(4);
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(connection_port);
    
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        exit(4);
    }
    
    int download_flag, upload_flag;
    
    while(1)
    {
        bzero(read_buffer,PACKET_SIZE);
        bzero(write_buffer,PACKET_SIZE);
        download_flag = 0;
        upload_flag = 0;
        char cresponse[PACKET_SIZE];
        
        printf("[Enter Command Here : ]");
        fgets(write_buffer,sizeof(write_buffer),stdin);
        
        char *filename = malloc(PACKET_SIZE);
        char copy[PACKET_SIZE];
        strcpy(copy, write_buffer);
        filename = strtok(copy, " \n");
        
        if(strcmp(filename, "quit") == 0)
            _exit(1);
        
        if(strcmp(filename,"FileDownload") == 0)
        {
            download_flag = 1;
            filename = strtok(NULL," \n");
            strcpy(file, filename);
        }
        if(strcmp(filename,"FileUpload") == 0)
        {
            upload_flag = 1;
            filename = strtok(NULL," \n");
            strcpy(file, filename);
        }
        sendto(sockfd , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
        
        if (download_flag || !upload_flag)
        {
            int status = download(file, sockfd, download_flag);
            if(status == -2)
                sprintf(cresponse,"\nERROR: cannot open file\n");
            else if (status == -3)
                sprintf(cresponse,"\nERROR: md5 did not match (send again)\n");
            strcat(write_buffer, cresponse);
       		strcat(write_buffer,PACKET_DELIM);
        	sendto(sockfd , write_buffer , strlen(write_buffer),0,(struct sockaddr*)&serv_addr,sock_addr_size);
        }
        else
        {
    		recvfrom(sockfd, read_buffer,sizeof(read_buffer),0,(struct sockaddr*)&serv_addr,&sock_addr_size);
            if(strcmp(read_buffer, "FileUploadAllow\n") == 0)
                upload(file, sockfd);
        }
    }
}

int main(int argc, char *argv[])
{
    if(argc != 5)
    {
        printf("\nUsage: %s <ip of server> <listenportno> <connectportno> <protocol>\n",argv[0]);
        exit(1);
    }
    
    char *ip = argv[1];
    char *listen_port = argv[2];
    char *connect_port = argv[3];

    sock_addr_size = sizeof(struct sockaddr);
    
    if(strcmp(argv[4], "udp")==0)
        udp_client_flag = 1;
    else if(strcmp(argv[4], "tcp")==0)
        udp_client_flag = 0;
    else
    {
        printf("\nInvalid protocol\n");
        exit(2);
    }
    
    pid_t pid;
    pid = fork();
    if(pid > 0)
    {
        if(udp_client_flag==1)
            udp_server(atoi(listen_port));
        else
            tcp_server(atoi(listen_port));
        wait(NULL);
    }
    else if(pid == 0)
    {
        if(udp_client_flag==1)
            udp_client(ip, atoi(connect_port));
        else
            tcp_client(ip, atoi(connect_port));
    }
    else
    {
        printf("\nNo memory, cannot fork\n");
        exit(3);
    }
    return 0;
}
