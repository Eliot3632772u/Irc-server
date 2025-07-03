#pragma once

#include <vector>
#include <iostream>
#include <algorithm>
#include "client.hpp"
#include "channel.hpp"

enum status{

    ERR_NOSUCHNICK = 401,
    ERR_INPUTTOOLONG = 417, // DOES NOT EXITS
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 461,
    ERR_ALREADYREGISTRED = 462,
    ERR_PASSWDMISMATCH = 464,

    ERR_NONICKNAMEGIVEN = 431,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,
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
    void handleMessage(int client_fd);

    void passCMD(int client_fd);
    void nickCMD(int client_fd);
    void userCMD(int client_fd);
    void joinCMD(int client_fd);
    void privmsgCMD(int client_fd);
    void kickCMD(int client_fd);
    void inviteCMD(int client_fd);
    void topicCMD(int client_fd);
    void modeCMD(int client_fd);
};