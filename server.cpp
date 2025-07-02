#include "inc.hpp"
#include "server.hpp"

Server::Server(std::string serverPass, std::string serverPort) : serverPass(serverPass), serverPort(serverPort){}

struct addrinfo * initSocketData(const char * host, const char * port){

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status = getaddrinfo(host, port, &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << "\n";
        return NULL;
    }

    return res;
}

void initSocketsError(const char * err, int socketFd, struct addrinfo * addrinfo){

    if (addrinfo)
        freeaddrinfo(addrinfo);

    if (err)
        perror(err);

    if (socketFd)
        close(socketFd);

    exit(1);
}

void Server::initSocket(){

    struct addrinfo *res;
    
    res = initSocketData(NULL, this->serverPort.c_str());
    if(res == NULL)
        initSocketsError(NULL, -1, res);
        
    this->socketFd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (this->socketFd == -1)
        initSocketsError("socket: ", -1, res);


    if (fcntl(this->socketFd, F_SETFL, O_NONBLOCK) < 0)
        initSocketsError("fcntl: ", this->socketFd, res);

    int yes = 1;
    if (setsockopt(this->socketFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        initSocketsError("stesocketopt: ", this->socketFd, res);
    

    if (bind(this->socketFd, res->ai_addr, res->ai_addrlen) < 0)
        initSocketsError("bind: ", this->socketFd, res);


    if (listen(this->socketFd, SOMAXCONN) < 0)
        initSocketsError("listen: ", this->socketFd, res);

    freeaddrinfo(res);
}

void Server::creatEpoll(){

    this->epollFd = epoll_create1(0);
    if (this->epollFd < 0)
        initSocketsError("epoll_create: ", this->socketFd, NULL);

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.fd = this->socketFd;

    if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, this->socketFd, &event) == -1) {
           
        close(this->epollFd);
        initSocketsError("epoll_ctl", this->socketFd, NULL);
    }
}

void Server::acceptConnections(){

    struct epoll_event events[100];

    while (true){
        
        int ready_fds = epoll_wait(this->epollFd, events, 100, -1);
        std::cout << "waiting :" << std::endl;
        if (ready_fds < 0){
            
            close(this->epollFd);
            initSocketsError("epoll_event: ", this->socketFd, NULL);
        }

        for(int i = 0; i < ready_fds; i++){

            int fd = events[i].data.fd;

            if (fd == this->socketFd){

                // struct sockaddr_storage client_addr;
                // socklen_t addr_len = sizeof(client_addr);

                int client_fd = accept(fd, NULL, NULL);
                if (client_fd < 0){

                    close(this->epollFd);
                    initSocketsError("accept: ", this->socketFd, NULL);
                }

                fcntl(client_fd, F_SETFL, O_NONBLOCK);

                struct epoll_event event;
                event.events = EPOLLIN | EPOLLOUT | EPOLLET;
                event.data.fd = client_fd;

                if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, client_fd, &event) == -1) {
                    
                    close(this->epollFd);
                    close(client_fd);
                    for(int i = 0; i < this->client_fds.size(); i++)
                        initSocketsError(NULL, this->client_fds[i].first, NULL);
                    
                    initSocketsError("epoll_ctl", this->socketFd, NULL);
                }

                // char ipstr[INET6_ADDRSTRLEN];
                // char portstr[NI_MAXSERV];

                // int rc = getnameinfo(
                //             (struct sockaddr*)&client_addr,
                //             addr_len,
                //             ipstr,
                //             sizeof(ipstr),
                //             portstr,
                //             sizeof(portstr),
                //             NI_NUMERICHOST | NI_NUMERICSERV
                //         );

                // if (rc != 0){

                //     std::cerr << "getnameinfo: " << gai_strerror(rc) << std::endl;
                //     this->client_fds.push_back(std::make_pair(client_fd, std::make_pair("unknown", "unknown")));
                // }

                // std::cout << "client fd;" << client_fd << " " << ipstr << ':' << portstr << std::endl;
                
                // this->client_fds.push_back(std::make_pair(client_fd, std::make_pair(ipstr, portstr)));
                continue;
            }
            else {
                
                // parse cmd
            }

        }
    }
}
