#pragma once

#include "inc.hpp"

struct Client{

    // client_Fd
    // is password set
    // nick name
    // username 
    // buffer for incomplet message 
    int client_fd;
    bool is_pass_set;
    std::string nick;
    std::string user;
    std::string buffer;
    std::string prefix;
    std::string command;
    std::vector<std::string> params;

    std::vector<std::string> channels;
};
