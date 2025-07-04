#pragma once 

#include "inc.hpp"

struct Channel
{
    bool invite_only;
    bool userlimited;
    size_t max_users;
    std::string name;
    std::string topic;
    std::string password;
    std::vector<std::string> members;
    std::vector<std::string> operators;
    std::vector<std::string> invited_users;
};