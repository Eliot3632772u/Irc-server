#pragma once

#include <vector>
#include <iostream>
#include <algorithm>

struct Server {

    int socketFd;
    std::string serverPort;
    std::string serverPass;
    std::vector<std::pair<int, std::pair<std::string, std::string> > > client_fds;
    int epollFd;

    Server(std::string serverPass, std::string serverPort);
    void initSocket();
    void creatEpoll();
    void acceptConnections();
};