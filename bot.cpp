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
       /* if (std::regex_search(resp, match, r_retry))
        {
             
            printf("\n\n!!!!match was found here: %s \n\n", match.str(1).c_str());
            sleep_sec(std::stoi(match.str(1))/1000000);
        }*/

#define REQUIRED_ARGUMENT 1
#define NO_ARGUMENT 0
const int NUM_SECONDS = 2;

std::regex r_retry("retry-after: (.*?)\r\n");


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

void sleep_sec(int i){
     for(i = 0 ; i < NUM_SECONDS ; i++) { usleep(1000 * 1000); }
}

/**
     * Function recieve packet and stores it in global variable resp
     */
int RecvPacket()
{
    int len=10000;
    std::regex end_of_body{"0\r\n"};
    std::regex chunk{"Transfer-Encoding: chunked"};
    bool chunked = false;
    char buf[1000000];
    while(len>0) {
        len=SSL_read(ssl, buf, 10000);
        buf[len] = 0;
        resp.append(buf);
        
        if(!chunked) {
            if(std::regex_search(resp, chunk)){
                chunked = true;
            } 
            else { //is not chunked
            if(SSL_pending(ssl) == 0) break;
            }  
        }
        else { //we know it's chunked and end wont be in first chunk
            if(std::regex_search(buf, end_of_body)) break; //has end
        }
    }
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
        printf("%s------",str);
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
    if(RecvPacket() == -1){
        resp="";
        SendPacket(content);
        RecvPacket();
    }
    }

void get_newer_msgs(std::string token, std::string last_msg,std::string channel){
    char content[1024];
    resp= "";
    sprintf(content,
    "GET /api/channels/%s/messages?after=%s HTTP/1.1\r\n"
    "Host: discord.com\r\n"
    "Authorization: Bot %s\r\n\r\n"
    ,
    channel.c_str(),
    last_msg.c_str(),
    token.c_str()); 
    printf("\nmoj get na msg after: \n%s\n", content);
    SendPacket(content);
    if(RecvPacket() == -1){
        resp="";
        SendPacket(content);
        RecvPacket();
    }
    printf("\nodpoved na GET msgs after:\n%s\n", resp.c_str());
}


void respond_to_new_msgs(std::string token,std::string last_msgs[], int cnt, std::list <std::string> chosen_channels){
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
            if(RecvPacket() == -1){
                resp="";
                SendPacket(content);
                RecvPacket();
            }

            printf("\nodpoved na GET channels:\n%s\n", resp.c_str());
            
            std::regex_search(resp, match, r_last_msg);
            printf("match last message :%s\n", match.str(1).c_str());
            printf("stored last message:%s\n\n", last_msgs[cnt].c_str());
            std::string temp_last = match.str(1);
            if((last_msgs[cnt].compare(match.str(1))) != 0 ){             
                printf("new msg pred funkciou: %s", temp_last.c_str());
                get_newer_msgs(token,last_msgs[cnt], channel);
                std::list <std::string> authors_messages; //stores [msg,author,msg,author..]
                last_msgs[cnt] = temp_last;
                
                std::string temp_resp = resp;
                while(std::regex_search(temp_resp, match, r_content)) {
                    authors_messages.push_back(match.str(1)); //content
                    std::regex_search(temp_resp, match, r_username);
                    temp_resp = match.suffix().str();    
                    authors_messages.push_back(match.str(1)); //author
                }
                while(true){
                    if(authors_messages.empty()){
                        break;
                    }
                    std::string author = authors_messages.back();
                    authors_messages.pop_back();
                    std::string msg =  authors_messages.back();
                    authors_messages.pop_back();
                    if ((author.compare("isa-bot")) != 0){

                        std::string author_msg = "{\"content\": \""+ author+": "+ msg+"\"}";
                        sprintf(content,
                        "POST /api/channels/%s/messages HTTP/1.1\r\n"
                        "Host: discord.com\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %ld\r\n"
                        "Authorization: Bot %s\r\n\r\n"
                        "%s"
                        ,
                        channel.c_str(),
                        strlen(author_msg.c_str()),
                        token.c_str(),
                        author_msg.c_str()
                        );

                        SendPacket(content);  
                        if(RecvPacket() == -1){
                            resp="";
                            SendPacket(content);
                            RecvPacket();
                        }  

                        printf("\nMOJ POST KTORY SA ODOSLAL: \n%s\n", content);                    
                        printf("\nodpoved na POST:\n%s\n", resp.c_str());
                        resp = "";
                    }
                
                }
                resp= ""; 
            }
            resp= "";
            cnt++;
        }
}
int main(int argc, char *argv[]){   
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
    memset(&sa, 0, sizeof(sa));
    struct hostent *hos;
    hos = gethostbyname("www.discord.com");
    if(!hos){   
        printf("Error while gethostbyname\n");
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
        if(RecvPacket() == -1){
            resp="";
            SendPacket(content);
            RecvPacket();
        }
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
            if(RecvPacket() == -1){
                resp="";
                SendPacket(content);
                RecvPacket();
            }
            std::regex_search(resp, match, r_last_msg) ;
            last_msgs[cnt] = match.str(1);
            resp= "";
            cnt++;
        }
        printf("NO POOOOD");
    int i;
    //infinite loop with cooldown 2 secs
    for(;;)
    {
        
        // delay for "NUM_SECONDS" seconds
       sleep_sec(2);
        int cnt =0;
        respond_to_new_msgs(arguments->token, last_msgs, cnt, chosen_channels);
    }
    return 0;
}