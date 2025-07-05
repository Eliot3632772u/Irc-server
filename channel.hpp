#pragma once 

#include "inc.hpp"
#include "client.hpp"

struct Channel
{
    bool invite_only;
    bool userlimited;
    size_t max_users;
    std::string name;
    std::string topic;
    bool topic_restricted;
    std::string password;
    std::vector<std::string> members;
    std::vector<std::string> operators;
    std::vector<std::string> invited_users;

    Channel();

    bool isAnyMember(const std::string& nick) const; // check is memebrs and operators
    // is operator to make code cleaner
    // is invited 
    // send message to all memebers
    void broadcastToAll(std::map<int, std::pair<int, Client> >& clients, int except, std::string message) const;
};