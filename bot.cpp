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
#include <regex>
#include <list> 
#include <iterator> 


#define REQUIRED_ARGUMENT 1
#define NO_ARGUMENT 0
const int NUM_SECONDS = 2;


std::regex r_id("\"id\": \"(.*?)\""); 
std::regex r_name("\"name\": \"(.*?)\"");
std::regex r_last_msg("\"last_message_id\": \"(.*?)\""); 
std::regex r_content("\"content\": \"(.*?)\""); 
std::regex r_username("\"username\": \"(.*?)\""); 

SSL *ssl;
int sock;
std::string resp("");

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
/**
     * Function recieve packet and stores it in global variable resp
     */
int RecvPacket()
{
    int len=100;
    char buf[1000000];
   while (len>0){
        len=SSL_read(ssl, buf, 100);
        buf[len]=0;
        resp.append(buf);
        if (buf[0]=='0' && buf[1]=='\r' && buf[2]=='\n')
        {
            break;
        }
        
    } 
    //printf("%s \n", resp.c_str());


    if (len <= 0) {
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

void get_guilds(std::string token){
    char content[1024];
    sprintf(content,
        "GET /api/users/@me/guilds HTTP/1.1\r\n"
        "Host: discord.com\r\n"
        "Connection: keep-alive\r\n"
        "Authorization: Bot %s\r\n\r\n"
        ,
    token.c_str());
    //printf("%s",content);
    SendPacket(content);
    RecvPacket();
}

void get_newer_msgs(std::string token, std::string last_msg,std::string channel){
    char content[1024];
    resp= "";
    std::cout << channel.c_str() << std::endl;
    sprintf(content,
    "GET /api/channels/%s/messages?after=%s HTTP/1.1\r\n"
    "Host: discord.com\r\n"
    "Authorization: Bot %s\r\n\r\n"
    ,
    channel.c_str(),
    last_msg.c_str(),
    token.c_str()); 
    SendPacket(content);
    RecvPacket();
}

void check_new_messages(std::string token,std::string last_msgs[], int cnt, std::list <std::string> chosen_channels){
    
    for(const auto& channel : chosen_channels)
        {
            std::smatch match;
            char content[1024];
            resp= "";
            std::cout << "\nchannel: "<< channel.c_str() << std::endl;
            sprintf(content,
            "GET /api/channels/%s HTTP/1.1\r\n"
            "Host: discord.com\r\n"
            "Authorization: Bot %s\r\n\r\n"
            ,
            channel.c_str(),
            token.c_str());

            SendPacket(content);
            RecvPacket();

            
            
            std::regex_search(resp, match, r_last_msg);
            printf(" match last message :%s", match.str(1).c_str());
            printf("\n stored last message:%s\n\n", last_msgs[cnt].c_str());
            
            if((last_msgs[cnt].compare(match.str(1))) != 0 ){             
                std::string tempo = match.str(1);
                get_newer_msgs(token, last_msgs[cnt], channel);
                printf("%s\n", resp.c_str());

                last_msgs[cnt]= tempo;
                
                std::string temp_resp = resp;
                while(std::regex_search(temp_resp, match, r_content)) {
                    std::string msg = match.str(1);
                    std::regex_search(temp_resp, match, r_username);
                    
                    if ((match.str(1).compare("isa-bot")) != 0){
                    msg = "{\"content\": \""+match.str(1)+": "+ msg +"\"}";
                    sprintf(content,
                    "POST /api/channels/%s/messages HTTP/1.1\r\n"
                    "Host: discord.com\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: %ld\r\n"
                    "Authorization: Bot %s\r\n\r\n"
                    "%s"
                    ,
                    channel.c_str(),
                    strlen(msg.c_str()),
                    token.c_str(),
                    msg.c_str()
                    );
                    SendPacket(content);  
                    RecvPacket();    
                    printf("\nodpoved na post:%s\n", resp.c_str());
                    resp = "";
                    }
                    temp_resp = match.suffix().str();  
                }
              resp= "";    
            }
            resp= "";
            cnt++;
        }
}
int main(int argc, char *argv[])
{


    char *ip=(char*)malloc(sizeof(char) *100);
    struct in_addr **addr_list;
    Arguments *arguments = Arguments::parse_arguments(argc, argv);

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
    sa.sin_addr.s_addr = inet_addr(ip);
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

    //get guilds of the bot
    get_guilds(arguments->token);

    int n_channels = 0;
    std::smatch match;
    std::string temp = resp;
    while(std::regex_search(temp, match, r_id)) {
        std::string id_value = match.str(1); 
        temp = match.suffix().str(); 
        n_channels++;
    }
    std::string guild_ids[n_channels];
    while(std::regex_search(resp, match, r_id)) {
        n_channels--;
        guild_ids[n_channels] = match.str(1); 
        resp = match.suffix().str(); 
    }

   
    std::list <std::string> chosen_channels;
    for(int i=0; i < sizeof(guild_ids)/sizeof(guild_ids[0]); i++){
        sprintf(content,
        "GET /api/guilds/%s/channels HTTP/1.1\r\n"
        "Host: discord.com\r\n"
        "Connection: keep-alive\r\n"
        "Authorization: Bot %s\r\n\r\n"
        ,
        guild_ids[i].c_str(),
        arguments->token.c_str());

        SendPacket(content);
        RecvPacket();
        std::string temp = resp;
        while(std::regex_search(temp, match, r_id)) {
        std::string id_value = match.str(1); 
        temp = match.suffix().str(); 
        std::regex_search(temp, match, r_name) ;
        if(match.str(1)=="isa-bot"){
            chosen_channels.push_back(id_value);

        }
    }   
    }

    std::string last_msgs[chosen_channels.size()];
    int cnt =0;
    for(const auto& channel : chosen_channels)
        {
            resp= "";
            std::cout << channel.c_str() << std::endl;
            sprintf(content,
            "GET /api/channels/%s HTTP/1.1\r\n"
            "Host: discord.com\r\n"
            "Authorization: Bot %s\r\n\r\n"
            ,
            channel.c_str(),
            arguments->token.c_str());

            SendPacket(content);
            RecvPacket();
            std::regex_search(resp, match, r_last_msg) ;
            last_msgs[cnt] = match.str(1);
            resp= "";
            cnt++;
        }
    int i;
    //infinite loop with cooldown 2 secs
    for(;;)
    {
        // delay for "NUM_SECONDS" seconds
        for(i = 0 ; i < NUM_SECONDS ; i++) { usleep(1000 * 1000); }
        int cnt =0;
        check_new_messages(arguments->token, last_msgs, cnt, chosen_channels);
    }
    return 0;
}