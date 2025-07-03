#pragma once 

#include "inc.hpp"

struct Channel{

    // channel name
    // password
    // topic
    // members
    // operators
    // userlimit
    // invite only channel
    // invited users
    std::string name;
    std::string password;
    std::string topic;
    std::vector<std::string> members;
    std::vector<std::string> operators;
    std::vector<std::string> invited_users;
    int userlimit;
    bool is_invite_only;

};