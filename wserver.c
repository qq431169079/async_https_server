 /* A simple HTTPS server */
#include <stdio.h>
#include <string.h>   //strlen
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>   //close
#include <arpa/inet.h>    //close
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "common.h"
#include "server.h"


#define SOCKET int
#define bool int
#define true 1
#define false 0

#define MAX_SSL_READ_BUFFER 65535

typedef enum {
  ACCEPT =0,
  CONNECT,
  READ,
  WRITE,
  SHUTDOWN
};


void terminateConnection(int socket) {
}

void GetSSLErrors() {
  int errorCode;
  char pTempBuffer[40960]={0};
  ERR_error_string_n(errorCode, pTempBuffer, 40960);
  printf("%s\n", pTempBuffer);
}

bool setFdNonBlock(SOCKET fd) {
  int32_t arg;
  if ((arg = fcntl(fd, F_GETFL, NULL)) < 0) {
    int32_t err = errno;
    printf("Unable to get fd flags: %d,%s", err, strerror(err));
    return false;
  }
  arg |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, arg) < 0) {
    int32_t err = errno;
    printf("Unable to set fd flags: %d,%s", err, strerror(err));
    return false;
  }

  return true;
}

bool setFdNoSIGPIPE(SOCKET fd) {
  //This is not needed because we use MSG_NOSIGNAL when using send/write functions
  return true;
}

bool setFdKeepAlive(SOCKET fd, bool isUdp) {
  if (isUdp)
    return true;

  int32_t one = 1;
  int32_t keepidle = 10;
  int32_t keepintvl = 5;
  int32_t keepcnt = 3;

  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
      (const char*) & one, sizeof (one)) != 0) {
    printf("Unable to set SO_NOSIGPIPE");
    return false;
  }

  if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
      (const char*) &keepidle, sizeof (keepidle)) != 0) {
    printf("Unable to set TCP_KEEPIDLE");
  }
  if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
      (const char*) &keepintvl, sizeof (keepintvl)) != 0) {
    printf("Unable to set TCP_KEEPINTVL");
  }
  if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
      (const char*) &keepcnt, sizeof (keepcnt)) != 0) {
    printf("Unable to set TCP_KEEPCNT");
  }


  return true;
}

bool setFdNoNagle(SOCKET fd, bool isUdp) {
  if (isUdp)
    return true;
  int32_t one = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) & one, sizeof (one)) != 0) {
    return false;
  }
  return true;
}

bool setFdReuseAddress(SOCKET fd) {
  int32_t one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) & one, sizeof (one)) != 0) {
    printf("Unable to reuse address");
    return false;
  }
#ifdef SO_REUSEPORT
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) & one, sizeof (one)) != 0) {
    printf("Unable to reuse port");
    return false;
  }
#endif /* SO_REUSEPORT */
  return true;
}

bool setFdOptions(SOCKET fd) {
  if (!setFdNonBlock(fd)) {
    printf("Unable to set non block");
    return false;
  }

  if (!setFdNoSIGPIPE(fd)) {
    printf("Unable to set no SIGPIPE");
    return false;
  }

  if (!setFdKeepAlive(fd, false)) {
    printf("Unable to set keep alive");
    return false;
  }

  if (!setFdNoNagle(fd, false)) {
    printf("Unable to disable Nagle algorithm");
  }

  if (!setFdReuseAddress(fd)) {
    printf("Unable to enable reuse address");
    return false;
  }
  return true;
}

int main(int argc, char **argv) {
    int master_socket , addrlen , new_socket , client_socket[30] ,  max_clients = 30 , activity, i , valread , sd;
    int client_state[30]={0};
    int client_https_state[30]={0};
    SSL *client_ssl[30]={0};
    int max_sd;
    struct sockaddr_in address;
    SSL_CTX *ctx;
    fd_set readfds, writefds;
    fd_set readFdsCopy, writeFdsCopy;
    char buffer[4096];
    struct timeval tv={3,0};

   FD_ZERO(&readfds);
   FD_ZERO(&writefds);
   FD_ZERO(&readFdsCopy);
   FD_ZERO(&writeFdsCopy);

    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < max_clients; i++) {
        client_socket[i] = 0;
    }

    /* Build our SSL context*/
    ctx=initialize_ctx();
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    master_socket=tcp_listen();
    setFdOptions(master_socket);

    addrlen = sizeof(address);
    FD_SET(master_socket, &readfds);
    max_sd = master_socket;

    while (1) {
      FD_ZERO(&readFdsCopy);
      FD_ZERO(&writeFdsCopy);
      readFdsCopy=readfds;
      writeFdsCopy=writefds;
      tv.tv_sec=1;
      tv.tv_usec=0;

      activity = select(max_sd+1, &readFdsCopy , &writeFdsCopy , NULL , &tv);
      if ((activity < 0) && (errno!=EINTR)) {
        printf("select error");
      }

      //accept connection here
      if (FD_ISSET(master_socket, &readFdsCopy)) {
          int available=0;
          int new_socket=0;
          int index=0;
          int flags=0;

          if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
              perror("accept");
              exit(EXIT_FAILURE);
          }

          //inform user of socket number - used in send and receive commands
          printf("New connection , socket fd is %d , ip is : %s , port : %d\n", new_socket, inet_ntoa(address.sin_addr), ntohs (address.sin_port));
          setFdOptions(new_socket);

          //add new socket to array of sockets
          for (i = 0; i < max_clients; i++) {
              //if position is empty
              if( client_socket[i] == 0 ) {
                  client_socket[i] = new_socket;
                  client_ssl[i] = SSL_new(ctx);
                  SSL_set_bio(client_ssl[i], BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
                  printf("Adding to list of sockets as %d, %p\n" , i, client_ssl[i]);
                  available=1;
                  index=i;
                  FD_SET(new_socket, &readfds);
                  if (new_socket > max_sd) {
                    max_sd=new_socket;
                  }
                  break;
              }
          }

          if (!client_ssl[index]) {
            printf("Unable to SSL_new\n");
            if (new_socket>0) {
              close(new_socket);
            }
          }
          else if (available==0) {
            printf("No available client\n");
            if (new_socket>0) {
              close(new_socket);
            }
          }
          else {
            int errCode=SSL_accept(client_ssl[index]);
            int error=SSL_get_error(client_ssl[index], errCode);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
              printf("unable to do SSL_accept");
              exit(1);
            }
          }
      } //end of accept connection

      //some IO operation on other socket
      for (i = 0; i < max_clients; i++) {
        sd = client_socket[i];
        if (sd==0) {
          continue;
        }

        if (FD_ISSET(sd, &readFdsCopy)) {
            if ((valread = recv(sd, buffer, 4096, MSG_NOSIGNAL)) == 0) {
              //Somebody disconnected , get his details and print
              getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);
              printf("Host disconnected , ip %s , port %d \n" , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
              //Close the socket and mark as 0 in list for reuse
              close(sd);
              SSL_free(client_ssl[i]);
              client_socket[i] = 0;
              client_ssl[i]=0;
              client_state[i]=0;
              FD_CLR(sd, &readfds); //remove from select list
              FD_CLR(sd, &writefds); //remove from select list
            }
            else {
              int j;
              printf("sd:%d, client_ssl[%d]:%p, size:%d\n", sd, sd, client_ssl[i], valread);
              BIO *pInBio = SSL_get_rbio(client_ssl[i]);
              BIO_write(pInBio, buffer, valread);

              if (client_state[i]==0) { //handshake not completed
                printf("read handshake not completed\n");
                //DoHandShake
                int errorCode=SSL_ERROR_NONE;
                errorCode=SSL_accept(client_ssl[i]);
                if (errorCode < 0) {
                  int error = SSL_get_error(client_ssl[i], errorCode);
                  if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                    printf("unable to accept SSL connection: %d", error);
                    exit(1);
                  }
                }

                //Perform IO
                BIO *pOutBio= SSL_get_wbio(client_ssl[i]);
                int bioAvailable=BIO_pending(pOutBio);
                if (bioAvailable<0) {
                  printf("bioAvailable failed");
                }
                else if (bioAvailable>0){
                  char outBuffer[bioAvailable];
                  int written=BIO_read(pOutBio, outBuffer, bioAvailable);
                  send(client_socket[i], outBuffer, bioAvailable, MSG_NOSIGNAL);
                }
                client_state[i]=SSL_is_init_finished(client_ssl[i]);
              }
              else { //handshake completed
                printf("read handshake completed\n");
                int32_t read = 0;
                char readBuffer[MAX_SSL_READ_BUFFER];
                while ((read = SSL_read(client_ssl[i], readBuffer, MAX_SSL_READ_BUFFER)) > 0) {
                  printf("%s\n", readBuffer);
                }

                char data[256]={0};
                sprintf(data, "%s", "HTTP/1.1 200 OK\r\nContent-Length: 30\r\nServer: EKRServer\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body>test</body></html>");
                SSL_write(client_ssl[i], data, 256);

                //performIO
                BIO *pOutBio= SSL_get_wbio(client_ssl[i]);
                int bioAvailable=BIO_pending(pOutBio);
                if (bioAvailable<0) {
                  printf("complete bioAvailable failed");
                }
                else if (bioAvailable>0){
                  char outBuffer[bioAvailable];
                  int written=BIO_read(pOutBio, outBuffer, bioAvailable);
                  int result=send(client_socket[i], outBuffer, bioAvailable, MSG_NOSIGNAL);
                  client_https_state[i]=1;
                  //listen write event to disconnect connection
                  FD_SET(client_socket[i], &writefds);
                }
              }
            }
          }

          if (FD_ISSET(sd, &writeFdsCopy)) { //apache bench tool
            printf("write\n");
            if (client_https_state[i]) {
              int sd=client_socket[i];
              close(sd);
              SSL_free(client_ssl[i]);
              client_socket[i] = 0;
              client_ssl[i]=0;
              client_state[i]=0;
              FD_CLR(sd, &readfds); //remove from select list
              FD_CLR(sd, &writefds); //remove from select list
            }
          }
        }
    } //end of while loop

    destroy_ctx(ctx);
    exit(0);
}
