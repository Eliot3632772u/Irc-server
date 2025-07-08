#pragma once 

#include "inc.hpp"
#include "client.hpp"

struct Channel
{
    Channel();
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
    void removeMember(std::string nick);
    bool isAnyMember(const std::string& nick) const;
    void broadcastToAll(std::map<int, std::pair<int, Client> >& recipients, Client& sender, std::string message, bool include_sender) const;
};
