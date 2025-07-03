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





// void Server::parseCmd(int client_fd){

//     size_t last = this->clients[client_fd].second.buffer.size() - 3;
//     std::stringstream bufferStream(this->clients[client_fd].second.buffer.substr(0, last));
//     bool isPrefix = false;

//     if (this->clients[client_fd].second.buffer[0] == ':'){

//         // extract prefix

//         std::string prefix;

//         // bufferStream >> prefix;
//         std::getline(bufferStream, prefix, ' ');

//         int pos;
//         for (int i = 0; i < prefix.size(); i++){

//             if (prefix[i] == '!' || prefix[i] == '@'){

//                 pos = i;
//                 break;
//             }
//         }

//         this->clients[client_fd].second.prefix = prefix.substr(1, pos - 1);
//         isPrefix = true;
//     }

//     if (!isPrefix){
        
//     }
//     std::string command;

//     // bufferStream >> command;
//     std::getline(bufferStream, command, ' ');

//     size_t pos = command.find_first_not_of(' ');
//     if (pos == std::string::npos){

//         // no command found
//         clearClientData(client_fd);
//         serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
//     }

//     command = command.substr(pos);

//     for (int i = 0; i < command.size(); i++){

//         if (!isalpha(command[i])){

//             // throw not valid command 
//             clearClientData(client_fd);
//             serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
//             return;
//         }
//     }

//     this->clients[client_fd].second.command = command;

//     while(!bufferStream.eof()){

//         std::string param;

//         bufferStream >> param;

//         size_t pos = param.find_first_not_of(' ');
//         if (pos == std::string::npos){

//             this->clients[client_fd].second.buffer.clear();
//             return ;
//         }

//         param = param.substr(pos);

//         if (param[0] == ':'){

//             this->clients[client_fd].second.params.push_back(param.substr(1));
//             this->clients[client_fd].second.buffer.clear();
//             return ;
//         }

//         if (param.find(':') != std::string::npos){

//             // throw bad param
//             // delelte message
//             clearClientData(client_fd);
//             serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
//             return ;
//         }

//         this->clients[client_fd].second.params.push_back(param);
//     }

//     if (this->clients[client_fd].second.params.size() > 15){

//         serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
//         return ;
//     }
// }