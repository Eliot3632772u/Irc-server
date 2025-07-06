#pragma once

#include "inc.hpp"

bool areEqualScandi(const std::string& one, const std::string& two);

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

    bool hasChannel(std::string& name);
};

inline bool Client::hasChannel(std::string& name)
{
    for (size_t i = 0; i < this->channels.size(); i++)
    {
        if (areEqualScandi(name, this->channels[i]))
            return true;
    }
    return false;
}
