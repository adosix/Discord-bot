
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <stdio.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define REQUIRED_ARGUMENT 1
#define NO_ARGUMENT 0

SSL *ssl;
int sock;


void exit_program(int ret_val, std::string msg)
{
    std::cerr << msg;
    exit(ret_val);
}


/**
 * Class which processes arguments
 */
class Arguments
{
    public:
        bool verbose;
         std::string token;
        static Arguments* parse_arguments(int argc, char **argv);

    Arguments()
    {
        //init setting
        this->verbose = false;
        this->token = "";
    }

    /**
     * Help
     */
    void print_help()
    {
        printf("Discord Bot\n\n");
        printf("Arguments: [-h] [-v] -t token \n");
        printf("-t: token of server\n");
        printf("-v/--verbose: Prints messages bot reacts to on stdout in format <channel> - <username>: <message>\n");
        printf("-h/--help: Prints help\n");
        exit(0);
    }
};


Arguments* Arguments::parse_arguments(int argc, char **argv)
{
    Arguments *arguments = new Arguments();

    bool wasServer = false;
    char option;

    const struct option longopts[] =
    {
        {"help", NO_ARGUMENT, 0, 'h'},
        {"verbose", NO_ARGUMENT, 0, 'v'},
        {"", REQUIRED_ARGUMENT, 0, 't'}
    };

    int index;
    while((option = getopt_long(argc, argv, "hvt:", longopts,&index)) != -1)
    {
        
        switch(option)
        {
            case 'h':
                arguments->print_help();
                break;
            case 'v':
                arguments->verbose = true;
                break;
            case 't':
                arguments->token = optarg;
                break;
            default:
                arguments->print_help();;
        }
    }

    if (arguments->token == "")
    {
        exit_program(1, "attribute token can't be empty\n");
    }
    
    return arguments;
}

int RecvPacket()
{
    int len=100;
    char buf[1000];
    do {
        len=SSL_read(ssl, buf, 100);
        buf[len]=0;
        printf("%s\n",buf);
    } while (len > 0);
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
    if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
    }
    return 0;
}

int SendPacket(const char *buf)
{
    int len = SSL_write(ssl, buf, strlen(buf));
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }
    return 0;
}
    
void log_ssl()
{
    int err;
    while (err = ERR_get_error()) {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;
        printf("%s",str);
        printf("\n");
        fflush(stdout);
    }
}

int main(int argc, char *argv[])
{
    char *ip=(char*)malloc(sizeof(char) *100);
    struct in_addr **addr_list;
    Arguments *arguments = Arguments::parse_arguments(argc, argv);
    //printf("%s",arguments->token.c_str());

    int s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("Error creating socket.\n");
        return -1;
    }
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    struct hostent *hos;
    hos=gethostbyname("www.discord.com");
    if(!hos){   
        printf("chyba pri gethostbyname\n");
        close(s);
        exit(10);
        
    }
    addr_list = (struct in_addr **) hos->h_addr_list;

    for(int i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        break;
    }

    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip); // address of google.ru
    sa.sin_port        = htons (443); 
    socklen_t socklen = sizeof(sa);
    if (connect(s, (struct sockaddr *)&sa, socklen)) {
        printf("Error connecting to server.\n");
        return -1;
    }
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *meth = TLSv1_2_client_method();
    SSL_CTX *ctx = SSL_CTX_new (meth);
    ssl = SSL_new (ctx);
    if (!ssl) {
        printf("Error creating SSL.\n");
        log_ssl();
        return -1;
    }
    char content[1024];
    sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, s);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        printf("Error creating SSL connection.  err=%x\n", err);
        log_ssl();
        fflush(stdout);
        return -1;
    }
    sprintf(content,
        "GET /api/channels/768841171505774613/messages HTTP/1.1\r\n"
        "Host: discord.com\r\n"
        "Authorization: Bot %s\r\n\r\n"
        ,
      arguments->token.c_str());

    printf("%s",content);
    if(SendPacket(content) != 0){
        return -1;
    };
    if(RecvPacket() != 0){
        return -1;
    }
    return 0;
}