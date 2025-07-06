#pragma once

#include "inc.hpp"

struct Client
{
    int client_fd;
    bool is_pass_set;
    bool authenticated;
    std::string nick;
    std::string user;
    std::string buffer;
    std::string prefix;
    std::string command;
    std::vector<std::string> channels;
    std::vector<std::string> params;

    std::string host;
};

















































