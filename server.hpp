#pragma once

#include <vector>
#include <iostream>
#include <algorithm>
#include "client.hpp"
#include "channel.hpp"

enum status
{
    ERR_NOSUCHNICK = 401,
    ERR_INPUTTOOLONG = 417, // DOES NOT EXITS
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 461,
    ERR_ALREADYREGISTRED = 462,
    ERR_PASSWDMISMATCH = 464,

    ERR_NONICKNAMEGIVEN = 431,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,

    ERR_NOTREGISTERED = 451,
    ERR_NOSUCHCHANNEL = 403,
    ERR_CHANNELISFULL = 471,
    ERR_INVITEONLYCHAN = 473,

    ERR_BADCHANNELKEY = 475,
    ERR_CHANOPRIVSNEEDED = 482,
    ERR_UNKNOWNMODE = 472,
    ERR_USERNOTINCHANNEL = 441,

    ERR_USERONCHANNEL = 443,
    ERR_NOTONCHANNEL = 442,

    ERR_NOTEXTTOSEND = 412,
    ERR_NORECIPIENT = 411,
};

struct Server
{

    int socketFd;
    int epollFd;
    std::string serverPass;
    std::string serverPort;
    std::map<int, std::pair<int, Client> > clients;
    std::map<std::string, Channel> channels;

    Server(std::string serverPass, std::string serverPort);

    void initSocket();
    void creatEpoll();
    void acceptConnections();
    void readReq(int client_fd);
    void parseCmd(int client_fd);
    void serverResponse(int cliet_fd, enum status code);
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
    void botCMD(int client_fd);
};
