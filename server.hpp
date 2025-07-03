#pragma once

#include <vector>
#include <iostream>
#include <algorithm>
#include "client.hpp"
#include "channel.hpp"

enum status{

    ERR_INPUTTOOLONG = 417,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 462,
};

struct Server {

    int socketFd;
    int epollFd;
    std::string serverPort;
    std::string serverPass;
    std::map<int, std::pair<int, Client> > clients;
    std::map<std::string, Channel> channels;

    Server(std::string serverPass, std::string serverPort);
    void initSocket();
    void creatEpoll();
    void acceptConnections();
    void readReq(int client_fd);
    void parseCmd(int client_fd);
    void serverResponse(int cliet_fd, enum status);
    void clearClientData(int client_fd);
};