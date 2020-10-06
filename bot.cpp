
#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>

#define REQUIRED_ARGUMENT 1

#define NO_ARGUMENT 0


void error(std::string error)
{
    std::cerr << error;
    exit(1);
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

    return arguments;
}

int main(int argc, char *argv[])
{
    Arguments *arguments = Arguments::parse_arguments(argc, argv);

}