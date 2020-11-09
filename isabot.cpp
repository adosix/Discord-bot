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

class Arguments;

#define REQUIRED_ARGUMENT 1
#define NO_ARGUMENT 0

static const std::regex r_unicode4("\\\\u(\\a|b|c|d|e|f){4}");
static const std::regex r_unicode8("\\\\U(\\a|b|c|d|e|f){8}");
static const std::regex r_retry("retry-after: (.*?)\r\n");
static const std::regex r_bot("(.*?)bot(.*?)");
static const std::regex r_id("\"id\": \"(.*?)\""); 
static const std::regex r_name("\"name\": \"(.*?)\"");
static const std::regex r_last_msg("\"last_message_id\": \"(.*?)\""); 
static const std::regex r_content("\"content\": \"(((.*?)|(?=\\\\\"))*?)\", "); 
static const std::regex r_username("\"username\": \"(.*?)\""); 
static const std::regex r_end_of_body{"0\r\n"};
static const std::regex r_chunk{"Transfer-Encoding: chunked"};
static const std::regex r_unauthorized("(.*?)401 Unauthorized\r\n");

Arguments *arguments;
SSL *ssl;
int sock;
std::string resp("");

void exit_program(int ret_val, std::string msg)
{
    std::cerr << msg << "\n";
    exit(ret_val);
}

/**
 * Class which processes arguments
 */
class Arguments
{
    public:
        bool debug;     //if true then debug prints will be printed
        bool verbose;   //printing messages from server on the stadard output
        int period;     //number of seconds before recheckinng channels for new messages
        std::string token;
        static Arguments* parse_arguments(int argc, char **argv);

    Arguments()
    {
        //init setting
        this->period = 2;
        this->debug = false;
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
        printf("-t <bot_access_token>: token of server\n");
        printf("-v/--verbose: Prints messages bot reacts to on stdout in format \"echo <channel> - <username>: <message>\"\n");
        printf("-p/--period <n_of_seconds>: argument specifies seconds between requests\n");
        printf("-d/--debug: Prints debug messages for program\n");
        printf("-h/--help: Prints help\n");
        exit(0);
    }
};


Arguments* Arguments::parse_arguments(int argc, char **argv){
    Arguments *arguments = new Arguments();

    bool wasServer = false;
    char option;

    const struct option longopts[] =
    {
        {"help", NO_ARGUMENT, 0, 'h'},
        {"debug", NO_ARGUMENT, 0, 'd'},
        {"verbose", NO_ARGUMENT, 0, 'v'},
        {"token", REQUIRED_ARGUMENT, 0, 't'},
        {"period", REQUIRED_ARGUMENT, 0, 'p'}
    };

    int index;
    while((option = getopt_long(argc, argv, "hdvt:p:", longopts,&index)) != -1){
        
        switch(option){
            case 'h':
                arguments->print_help();
                break;
            case 'd':
                arguments->debug = true;
                break;
            case 'v':
                arguments->verbose = true;
                break;
            case 't':
                arguments->token = optarg;
                break;
            case 'p':
                try {
                    arguments->period = std::stoi(optarg);
                    if(arguments->period <= 0){
                        exit_program(-1,"Invalid argument");
                    }
                }
                catch (std::invalid_argument& e) {
                    exit_program(-1,"Invalid argument");
                }
                break;
            default:
                arguments->print_help();;
        }
    }

    if (arguments->token == ""){
        exit_program(1, "attribute token can't be empty\n");
    }
    
    return arguments;
}

void sleep_sec(int i){
     for(i = 0 ; i < arguments->period ; i++) { usleep(1000 * 1000); }
}

/**
 * Function recieve packet and stores it in global variable resp
*/
int recv_packet(){
    std::smatch match;
    int len=1000000;
    bool chunked = false;
    char buf[1000000];
    while(len>0) {
        len=SSL_read(ssl, buf, 1000000);
        buf[len] = 0;
        resp.append(buf);
        
        if (std::regex_search(resp, match, r_retry)){     
            sleep_sec(std::stoi(match.str(1))/100000);
            resp="";
            return -1;
        }
        if(!chunked) {
            if(std::regex_search(resp, r_chunk)){
                chunked = true;
            } 
            //response is not chunked
            else { 
                if(SSL_pending(ssl) == 0) break;
            }  
        }
        //we know response is chunked and end wont be in first chunk
        else { 
            if(std::regex_search(buf, r_end_of_body)) break; //has end
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

/*
 * Send packet throught ssl connection
 * 
 * @param buf   buffer with message:
*/
int send_packet(const char *buf){
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
            exit_program( -1, "SSL write error");
        }
    }
    return 0;
}

/*
 * Function prints error logs of ssl connection
*/
void log_ssl(){
    int err;
    while (err = ERR_get_error()) {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;
        std::cerr << "ssl-error: " << str;
    }
}

/*
 * Get servers/guilds of our bot
 *
 * @param token:        verification token of bot
*/
void get_guilds(std::string token){
    char content[1000000];
    sprintf(content,
        "GET /api/users/@me/guilds HTTP/1.1\r\n"
        "Host: discord.com\r\n"
        "Connection: keep-alive\r\n"
        "Authorization: Bot %s\r\n\r\n"
        ,
    token.c_str());
    //printf("%s",content);
    send_packet(content);
    while(recv_packet() == -1){
        resp="";
        send_packet(content);
    }
    if (arguments->debug == true){   
        std::smatch match;
        printf("\nGET GUILDS\n%s", resp.c_str());
        if(std::regex_search(resp, match, r_unauthorized)){
            exit_program(1, "Unathorized token");
        }
    }
    
}
/*
 * function gets messages after "last_msg" and calls send packet for each
 *
 * @param token:        verification token of bot
 * @param last_msg:     id of last stored message
 * @param channel:      id of channel
*/
void get_msgs_after(std::string token, std::string last_msg,std::string channel){
    char content[1000000];
    resp= "";
    sprintf(content,
        "GET /api/channels/%s/messages?after=%s HTTP/1.1\r\n"
        "Host: discord.com\r\n"
        "Authorization: Bot %s\r\n\r\n"
    ,
    channel.c_str(),
    last_msg.c_str(),
    token.c_str()); 
    if (arguments->debug == true)
    {
        printf("\nmoj get na msg after: \n%s\n", content);
    }
    send_packet(content);
    while(recv_packet() == -1){
        resp="";
        send_packet(content);
    }
    if (arguments->debug == true)
    {
        printf("\nodpoved na GET msgs after:\n%s\n", resp.c_str());
    }
}

/*
 * function which creates request to get information about given channel
 *
 * @param channel:      id of channel
 * @param token:        verification token of bot  
*/
void get_channel(std::string channel,std::string token){
    char content[1000000];
    sprintf(content,
        "GET /api/channels/%s HTTP/1.1\r\n"
        "Host: discord.com\r\n"
        "Authorization: Bot %s\r\n\r\n"
        ,
        channel.c_str(),
        token.c_str());

    send_packet(content);
}
/*
 * send msg to DC channel (json and message length mus be verified)
 *
 * @param channel:      id of channel
 * @param token:        verification token of bot
 * @param msg_body      json which will be sent to DC channel   
*/
void post_msg(std::string channel,std::string token, std::string msg_body){
        char content[1000000];
        sprintf(content,
            "POST /api/channels/%s/messages HTTP/1.1\r\n"
            "Host: discord.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %ld\r\n"
            "Authorization: Bot %s\r\n\r\n"
            "%s"
            ,
            channel.c_str(),
            strlen(msg_body.c_str()),
            token.c_str(),
            msg_body.c_str()
        );
        send_packet(content);
        if (arguments->debug == true)
        {
            printf("\nMOJ POST KTORY SA ODOSLAL: \n%s\n", content);
        }
}
/*
 * function creates body of message and decide if the message is under 2000 characters
 *
 * @param channel:      id of channel
 * @param token:        verification token of bot
 * @param author:       author of message
 * @param msg:          content of message    
*/  
void post_msgs(std::string channel,std::string token,std::string author,std::string msg){
    std::string msg_body = "{\"content\": \"echo: " + author+" - "+ msg+"\"}";
    std::string temp = std::regex_replace(msg, r_unicode4, "x");
    temp = std::regex_replace(temp, r_unicode8, "x");

    if (("echo: " + author + " - " + temp).length()>2000){
        if (arguments->debug == true){
            printf("splitting message");
        }
        
        msg_body="{\"content\": \"echo: "+ author+" - \"}";
        post_msg(channel,token,msg_body);

        while(recv_packet() == -1){
                resp="";
                post_msg(channel,token,msg_body);
            }
        if (arguments->debug==true)
        {
            printf("\nodpoved na POST:\n%s\n", resp.c_str());
        }         
            
        msg_body="{\"content\": \""+ msg+"\"}";
        post_msg(channel,token,msg_body);
    }
    else{
        post_msg(channel,token,msg_body);
        
    }
    while(recv_packet() == -1){
        resp="";
        post_msg(channel,token,msg_body);
    }
    if (arguments->debug==true)
    {
        printf("\nodpoved na POST:\n%s\n", resp.c_str());
    } 
    resp="";
}


/*
 * function checks if there is new messages in channels and if there is, then send responses to them
 *
 * @param token:        contains access token of bot (passed to the program by user)
 * @param last_msgs[]:  contains last msg of every channel in chosen channels
 * @param chosen_channels:  channels to which our bot has access
 * @param verbose:      argument of program, if true then the program prints messages of users to stdout
*/  
void respond_to_new_msgs(std::string token,std::string last_msgs[], std::list <std::string> chosen_channels, bool verbose){
    int cnt =0;
    for(const auto& channel : chosen_channels){
            std::smatch match;
            char content[1024];
            if(arguments->debug == true){
                printf("channel: %s\n", channel.c_str());
            }
            resp= "";
            get_channel(channel,token);
            while(recv_packet() == -1){
                if(arguments->debug == -1){
                    printf("\n\n\n\n CAKAM \n\n\n\n");
                }
                resp="";
                get_channel(channel,token);
            }
            std::regex_search(resp, match, r_last_msg);
            if (arguments->debug == true){
                printf("\nodpoved na GET channels:\n%s\n", resp.c_str());
                printf("match last message :%s\n", match.str(1).c_str());
                printf("stored last message:%s\n\n", last_msgs[cnt].c_str());
            }
            
            if((last_msgs[cnt].compare(match.str(1))) != 0 ){             

                get_msgs_after(token,last_msgs[cnt], channel);
                std::list <std::string> authors_messages; //stores [msg,author,msg,author..]   
                std::string temp_resp = resp;
                while(std::regex_search(temp_resp, match, r_content)) {
                    authors_messages.push_back(match.str(1)); //content
                    
                    //saving msg id of last msg found
                    std::regex_search(resp, match, r_id);
                    last_msgs[cnt] = match.str(1);

                    std::regex_search(temp_resp, match, r_username);   
                    authors_messages.push_back(match.str(1)); //author
                    temp_resp = match.suffix().str(); 
                }
                while(true){
                    if(authors_messages.empty()){
                        break;
                    }
                    std::string author = authors_messages.back();
                    authors_messages.pop_back();
                    std::string msg =  authors_messages.back();
                    authors_messages.pop_back();
                    if (!(std::regex_search(author, match, r_bot))){
                        if (verbose == true){
                            printf("%s - %s: %s\n", channel.c_str(), author.c_str(), msg.c_str());
                        }
                        
                        post_msgs(channel,token, author, msg);
                        
                        resp = "";
                    }
                }
            }
            resp= "";
            cnt++;
        }
}


int main(int argc, char *argv[]){   
    char *ip=(char*)malloc(sizeof(char) *100);
    struct in_addr **addr_list;
    arguments = Arguments::parse_arguments(argc, argv);
    int s;
    s = socket(AF_INET, SOCK_STREAM, 0);

    if (s < 0) {
        exit_program(-1,"Error creating socket.\n");
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    struct hostent *hos;
    hos = gethostbyname("www.discord.com");
    if(!hos){   
        close(s);
        exit_program(10,"Error while gethostbyname\n");
    }
    
    addr_list = (struct in_addr **) hos->h_addr_list;

    for(int i = 0; addr_list[i] != NULL; i++) {
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
        log_ssl();
        exit_program(-1,"Error creating SSL connection.\n"+ err);
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
        send_packet(content);
        while(recv_packet() == -1){
            resp="";
            send_packet(content);
        }
        if (arguments->debug == true)
        {
          printf("GET CHANNELS TO SELECT \"isa-bot\"\n%s\n", resp.c_str());
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
        resp="";  
    }

    std::string last_msgs[chosen_channels.size()];
    int cnt =0;
    for(const auto& channel : chosen_channels){
            resp= "";
            if (arguments->debug == true){
                printf("channel: %s\n",channel.c_str());
            }
            get_channel(channel,arguments->token);
            while(recv_packet() == -1){
                resp="";
                get_channel(channel,arguments->token);
            }
            if (arguments->debug == true){
                printf("GET CHANNEL FOR LAST MSG\n%s\n",resp.c_str());
            }
            std::regex_search(resp, match, r_last_msg) ;
            last_msgs[cnt] = match.str(1);
            resp= "";
            cnt++;
        }
    int i;
    //infinite loop with cooldown 2 secs
    for(;;){
        // delay for "NUM_SECONDS" seconds
        sleep_sec(2);
        respond_to_new_msgs(arguments->token, last_msgs, chosen_channels,arguments->verbose);
    }
    return 0;
}